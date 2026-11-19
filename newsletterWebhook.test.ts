import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createNewsletterWebhook, validWebhookSecret } from './newsletterWebhook.js';

test('requires an exact nonempty webhook secret', () => {
    assert.equal(validWebhookSecret('secret', 'secret'), true);
    for (const value of [undefined, '', 'other', ['secret']]) assert.equal(validWebhookSecret(value, 'secret'), false);
    assert.equal(validWebhookSecret('', undefined), false);
});

test('unsubscribe handler authenticates, validates, filters lists and uses guarded updates', async () => {
    process.env.BREVO_WEBHOOK_SECRET = 'test-secret';
    process.env.BREVO_NEWSLETTER_LIST_ID = '3';
    const calls: any[] = [];
    let fail = false;
    const db: any = { from: (table: string) => ({ update: (values: any) => {
        const entry: any = { table, values }; calls.push(entry);
        return { eq: (field: string, value: string) => {
            entry.email = [field, value];
            return { is: (field: string, value: null) => {
                entry.guard = [field, value];
                return { or: async (filter: string) => { entry.filter = filter; return { error: fail ? new Error() : null }; } };
            } };
        } };
    } }) };
    const handler = createNewsletterWebhook(db);
    const event = { event: 'unsubscribe', email: ' Person@Example.com ', list_id: [3], ts_event: Math.floor(Date.now() / 1000) - 60 };
    const run = async (body: any, secret = 'test-secret') => {
        let status = 0;
        await handler({ body, get: () => secret } as any, { sendStatus: (code: number) => { status = code; } } as any, () => {});
        return status;
    };
    assert.equal(await run(event, 'wrong'), 401);
    assert.equal(calls.length, 0);
    assert.equal(await run({ ...event, email: 'bad' }), 400);
    assert.equal(await run({ ...event, list_id: [9] }), 204);
    assert.equal(await run({ ...event, event: 'opened' }), 204);
    assert.equal(calls.length, 0);
    assert.equal(await run([event]), 204);
    assert.deepEqual(calls[0].email, ['email', 'person@example.com']);
    assert.deepEqual(calls[0].guard, ['unsubscribed_at', null]);
    assert.match(calls[0].filter, /^consented_at.is.null,consented_at.lte\./);
    assert.equal(calls[0].values.unsubscribed_at, new Date(event.ts_event * 1000).toISOString());
    fail = true;
    assert.equal(await run(event), 503);
});
