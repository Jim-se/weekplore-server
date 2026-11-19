import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeNewsletterEmail, subscribeNewsletter } from './newsletter';

test('normalizes email and rejects invalid inputs', () => {
    assert.equal(normalizeNewsletterEmail(' Person@Example.com '), 'person@example.com');
    for (const value of [null, '', 'missing-at.com', 'a@b', 'a b@example.com', 'a'.repeat(255) + '@example.com']) {
        assert.equal(normalizeNewsletterEmail(value), null);
    }
});

test('saves before Brevo, avoids duplicates, and records one failed attempt without retrying', async () => {
    process.env.BREVO_API_KEY = 'test-key';
    process.env.BREVO_NEWSLETTER_LIST_ID = '3';
    const originalFetch = globalThis.fetch;
    let existing: any = null;
    let failSave = false;
    let failBrevo = false;
    const calls: string[] = [];
    const db: any = { from: () => ({
        select: () => ({ eq: () => ({ maybeSingle: async () => ({ data: existing }) }) }),
        upsert: async (row: any) => {
            assert.equal(row.sync_status, 'pending');
            calls.push('save');
            return { error: failSave ? new Error('save failed') : null };
        },
        update: (row: any) => ({ eq: async () => {
            calls.push(row.sync_status);
            return { error: null };
        } }),
    }) };
    globalThis.fetch = (async (_url: any, options: any) => {
        calls.push('brevo');
        assert.deepEqual(JSON.parse(options.body).listIds, [3]);
        return new Response(JSON.stringify({ id: 42 }), { status: failBrevo ? 503 : 201 });
    }) as typeof fetch;
    try {
        await subscribeNewsletter(db, 'person@example.com', 'website');
        assert.deepEqual(calls, ['save', 'brevo', 'synced']);
        calls.length = 0;
        existing = { sync_status: 'synced', unsubscribed_at: null };
        assert.equal(await subscribeNewsletter(db, 'person@example.com', 'website'), 'already_subscribed');
        assert.deepEqual(calls, []);
        existing = null;
        failSave = true;
        await assert.rejects(subscribeNewsletter(db, 'person@example.com', 'website'));
        assert.deepEqual(calls, ['save']);
        calls.length = 0;
        failSave = false;
        failBrevo = true;
        await assert.rejects(subscribeNewsletter(db, 'person@example.com', 'booking'));
        assert.deepEqual(calls, ['save', 'brevo', 'failed']);
    } finally {
        globalThis.fetch = originalFetch;
    }
});
