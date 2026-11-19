import type { SupabaseClient } from '@supabase/supabase-js';

export const normalizeNewsletterEmail = (value: unknown) => {
    if (typeof value !== 'string') return null;
    const email = value.trim().toLowerCase();
    return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : null;
};

// One database save followed by one Brevo request. No background retries.
export async function subscribeNewsletter(db: SupabaseClient, email: string, source: 'website' | 'booking') {
    const key = process.env.BREVO_API_KEY;
    const listId = Number(process.env.BREVO_NEWSLETTER_LIST_ID);
    if (!key || !Number.isSafeInteger(listId) || listId <= 0) throw new Error('Newsletter configuration missing');

    const { data: existing, error: lookupError } = await db.from('newsletter_subscribers')
        .select('id,unsubscribed_at,sync_status').eq('email', email).maybeSingle();
    if (lookupError) throw new Error('Newsletter lookup failed');
    if (existing && !existing.unsubscribed_at && existing.sync_status === 'synced') return 'already_subscribed';

    const record = { email, source, consented_at: new Date().toISOString(), unsubscribed_at: null, sync_status: 'pending' };
    const { error: saveError } = await db.from('newsletter_subscribers').upsert(record, { onConflict: 'email' });
    if (saveError) throw new Error('Newsletter save failed');

    try {
        const response = await fetch('https://api.brevo.com/v3/contacts', {
            method: 'POST',
            headers: { 'api-key': key, 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify({ email, listIds: [listId], updateEnabled: true,
                // Only an explicit signup after a recorded unsubscribe reactivates email delivery.
                ...(existing?.unsubscribed_at ? { emailBlacklisted: false } : {}),
            }),
            signal: AbortSignal.timeout(10000),
        });
        if (!response.ok) throw new Error('Brevo contact request failed');
        const contact = response.status === 204 ? null : await response.json();
        const { error } = await db.from('newsletter_subscribers').update({
            sync_status: 'synced', last_synced_at: new Date().toISOString(),
            ...(contact?.id != null ? { brevo_contact_id: String(contact.id) } : {}),
        }).eq('email', email);
        if (error) throw new Error('Newsletter status save failed');
        return 'subscribed';
    } catch {
        await db.from('newsletter_subscribers').update({ sync_status: 'failed' }).eq('email', email);
        throw new Error('Newsletter subscription could not be completed');
    }
}
