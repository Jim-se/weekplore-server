import dotenv from 'dotenv';
dotenv.config();

// Run from server after deploying and copying BREVO_WEBHOOK_SECRET to Railway.
const base = process.env.BREVO_WEBHOOK_BASE_URL;
const secret = process.env.BREVO_WEBHOOK_SECRET;
const apiKey = process.env.BREVO_API_KEY;
if (!base || !secret || !apiKey || !base.startsWith('https://')) {
    throw new Error('Set BREVO_WEBHOOK_BASE_URL to your HTTPS backend URL and configure both Brevo secrets.');
}
const url = `${base.replace(/\/+$/, '')}/api/newsletter/brevo-webhook`;
const probe = await fetch(url, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'x-weekplore-webhook-secret': secret },
    body: JSON.stringify({ event: 'weekplore_configuration_probe' }),
});
if (probe.status !== 204) throw new Error(`Deployed endpoint is not ready (${probe.status}); no Brevo settings changed.`);
const headers = { 'api-key': apiKey, 'Content-Type': 'application/json' };
const listing = await fetch('https://api.brevo.com/v3/webhooks?type=marketing', { headers });
if (!listing.ok) throw new Error(`Unable to check existing webhooks (${listing.status}).`);
const existing = (await listing.json()).webhooks?.find(item => item.url === url);
const result = await fetch(`https://api.brevo.com/v3/webhooks${existing ? '/' + existing.id : ''}`, {
    method: existing ? 'PUT' : 'POST', headers,
    body: JSON.stringify({ url, type: 'marketing', events: ['unsubscribed'], batched: false,
        description: 'Weekplore newsletter unsubscribe sync',
        headers: [{ key: 'x-weekplore-webhook-secret', value: secret }],
    }),
});
if (!result.ok) throw new Error(`Brevo webhook configuration failed (${result.status}).`);
console.log('Brevo unsubscribe webhook configured successfully.');
