import crypto from 'node:crypto';
import type { RequestHandler } from 'express';
import type { SupabaseClient } from '@supabase/supabase-js';
import { normalizeNewsletterEmail } from './newsletter.js';

export function validWebhookSecret(actual: unknown, expected: string | undefined) {
    if (!expected || typeof actual !== 'string') return false;
    const a = Buffer.from(actual);
    const b = Buffer.from(expected);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function createNewsletterWebhook(db: SupabaseClient): RequestHandler {
    return async (req, res) => {
        if (!process.env.BREVO_WEBHOOK_SECRET) {
            res.sendStatus(503);
            return;
        }
        if (!validWebhookSecret(req.get('x-weekplore-webhook-secret'), process.env.BREVO_WEBHOOK_SECRET)) {
            res.sendStatus(401);
            return;
        }
        const events = Array.isArray(req.body) ? req.body : [req.body];
        if (!events.length || events.length > 1000) {
            res.sendStatus(400);
            return;
        }
        try {
            for (const event of events) {
                if (!event || typeof event !== 'object') { res.sendStatus(400); return; }
                if (event.event !== 'unsubscribe' && event.event !== 'unsubscribed') continue;
                const email = normalizeNewsletterEmail(event.email);
                const seconds = event.ts_event ?? event.ts;
                if (!email || typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds <= 0 || seconds * 1000 > Date.now() + 300000) {
                    res.sendStatus(400);
                    return;
                }
                const date = new Date(seconds * 1000);
                if (!Number.isFinite(date.getTime())) { res.sendStatus(400); return; }
                const listId = Number(process.env.BREVO_NEWSLETTER_LIST_ID);
                if (!Number.isSafeInteger(listId) || listId <= 0) { res.sendStatus(503); return; }
                // Empty/missing list metadata represents an account-wide unsubscribe.
                if (Array.isArray(event.list_id) && event.list_id.length && !event.list_id.some((id: unknown) => Number(id) === listId)) continue;
                const timestamp = date.toISOString();
                const { error } = await db.from('newsletter_subscribers').update({
                    unsubscribed_at: timestamp,
                    sync_status: 'synced',
                    last_synced_at: new Date().toISOString(),
                }).eq('email', email).is('unsubscribed_at', null)
                    .or(`consented_at.is.null,consented_at.lte.${timestamp}`);
                // Ignore duplicate notifications and events older than a fresh signup.
                if (error) throw error;
            }
            res.sendStatus(204);
        } catch {
            console.warn('Brevo unsubscribe notification could not be saved');
            res.sendStatus(503);
        }
    };
}
