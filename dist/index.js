import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { Resend } from 'resend';
import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
dotenv.config();
// Use Service Role Key for the backend to bypass RLS (Safer/Admin access)
const supabaseUrl = process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL || '';
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.VITE_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY || '';
const supabase = createClient(supabaseUrl, supabaseKey);
const resend = new Resend(process.env.RESEND_API_KEY);
const app = express();
const PORT = process.env.PORT || 3001;
app.set('trust proxy', 1);
const adminEmailAllowlist = (process.env.ADMIN_EMAILS || '')
    .split(',')
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean);
const allowedCorsOrigins = (process.env.CORS_ALLOWED_ORIGINS || 'http://localhost:3000,http://127.0.0.1:3000,http://weekplore.gr,https://weekplore.gr,http://www.weekplore.gr,https://www.weekplore.gr')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CONTROL_CHAR_REGEX = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;
const CANCEL_BOOKING_ROUTE = '/api/cancel-booking';
const BOOKING_RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000;
const BOOKING_RATE_LIMIT_MAX_REQUESTS = 5;
const BOOKING_RATE_LIMIT_CLEANUP_EVERY = 100;
const DUPLICATE_BOOKING_ERROR_MESSAGE = 'This email already has a booking for this time slot. If you need to make a change, please contact us.';
const DUPLICATE_BOOKING_CONSTRAINT = 'bookings_unique_shift_email_idx';
const ARCHIVED_STATUSES = new Set(['archived', 'canceled', 'cancelled']);
const EMAIL_TEMPLATE_FIELDS = ['subject_eng', 'body_eng', 'subject_el', 'body_el'];
const bookingRateLimitStore = new Map();
const activeBookingKeys = new Set();
let bookingRateLimitChecks = 0;
const pickDefined = (source, allowedKeys) => {
    const result = {};
    for (const key of allowedKeys) {
        if (source[key] !== undefined) {
            result[key] = source[key];
        }
    }
    return result;
};
const isNonEmptyString = (value) => typeof value === 'string' && value.trim().length > 0;
const normalizeLifecycleStatus = (value) => typeof value === 'string' ? value.trim().toLowerCase() : '';
const isArchivedStatus = (value) => typeof value === 'string' && ARCHIVED_STATUSES.has(normalizeLifecycleStatus(value));
const toArchiveStatus = (value, fallback = 'archived') => {
    const normalized = normalizeLifecycleStatus(value);
    if (normalized === 'cancelled') {
        return 'canceled';
    }
    if (normalized === 'archived' || normalized === 'canceled') {
        return normalized;
    }
    return fallback;
};
const isPlainObject = (value) => typeof value === 'object' && value !== null && Object.getPrototypeOf(value) === Object.prototype;
const sanitizeStringInput = (value, options = {}) => {
    const { lowercase = false, maxLength = 5000, preserveNewlines = true } = options;
    const normalizedLineBreaks = value.replace(/\r\n/g, '\n');
    const withoutControlChars = normalizedLineBreaks.replace(CONTROL_CHAR_REGEX, '');
    const collapsed = preserveNewlines
        ? withoutControlChars
        : withoutControlChars.replace(/\s+/g, ' ');
    const trimmed = collapsed.trim().slice(0, maxLength);
    return lowercase ? trimmed.toLowerCase() : trimmed;
};
const sanitizeRequestPayload = (value) => {
    if (typeof value === 'string') {
        return sanitizeStringInput(value);
    }
    if (Array.isArray(value)) {
        return value.map((entry) => sanitizeRequestPayload(entry));
    }
    if (isPlainObject(value)) {
        return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, sanitizeRequestPayload(entry)]));
    }
    return value;
};
const normalizeEmail = (value) => typeof value === 'string'
    ? sanitizeStringInput(value, { lowercase: true, maxLength: 254, preserveNewlines: false })
    : '';
const normalizePhone = (value) => typeof value === 'string'
    ? sanitizeStringInput(value, { maxLength: 40, preserveNewlines: false })
    : '';
const normalizeSingleLineText = (value, maxLength = 255) => typeof value === 'string'
    ? sanitizeStringInput(value, { maxLength, preserveNewlines: false })
    : '';
const normalizeMultilineText = (value, maxLength = 4000) => typeof value === 'string'
    ? sanitizeStringInput(value, { maxLength, preserveNewlines: true })
    : '';
const escapeHtml = (value) => value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
const normalizeEmailLanguage = (value) => {
    if (typeof value !== 'string') {
        return 'en';
    }
    const normalized = value.trim().toLowerCase();
    return normalized.startsWith('el') || normalized.startsWith('gr') ? 'el' : 'en';
};
const getLocalizedTemplateContent = (template, language) => {
    const subject = language === 'el'
        ? normalizeSingleLineText(template?.subject_el, 1000) || normalizeSingleLineText(template?.subject_eng, 1000) || normalizeSingleLineText(template?.subject, 1000)
        : normalizeSingleLineText(template?.subject_eng, 1000) || normalizeSingleLineText(template?.subject_el, 1000) || normalizeSingleLineText(template?.subject, 1000);
    const body = language === 'el'
        ? normalizeMultilineText(template?.body_el, 20000) || normalizeMultilineText(template?.body_eng, 20000) || normalizeMultilineText(template?.body, 20000)
        : normalizeMultilineText(template?.body_eng, 20000) || normalizeMultilineText(template?.body_el, 20000) || normalizeMultilineText(template?.body, 20000);
    return { subject, body };
};
const getMappedTemplates = async (purposes) => {
    const { data, error } = await supabase
        .from('email_purposes')
        .select('purpose, template_id, email_templates(*)')
        .in('purpose', purposes);
    if (error) {
        throw error;
    }
    return new Map((data || []).map((row) => [row.purpose, row.email_templates]));
};
const sortProductsByPrice = (products = []) => [...products].sort((left, right) => {
    const priceDiff = (Number(left?.price) || 0) - (Number(right?.price) || 0);
    if (priceDiff !== 0) {
        return priceDiff;
    }
    return String(left?.title || '').localeCompare(String(right?.title || ''));
});
const sortProductCategories = (productCategories = []) => [...productCategories]
    .map((productCategory) => ({
    ...productCategory,
    products: sortProductsByPrice(Array.isArray(productCategory?.products) ? productCategory.products : []),
}))
    .sort((left, right) => {
    const leftCreatedAt = left?.created_at ? new Date(left.created_at).getTime() : 0;
    const rightCreatedAt = right?.created_at ? new Date(right.created_at).getTime() : 0;
    if (leftCreatedAt && rightCreatedAt && leftCreatedAt !== rightCreatedAt) {
        return leftCreatedAt - rightCreatedAt;
    }
    return String(left?.name || '').localeCompare(String(right?.name || ''));
});
const flattenProductCategories = (productCategories = []) => sortProductCategories(productCategories).flatMap((productCategory) => Array.isArray(productCategory?.products) ? productCategory.products : []);
const attachProductCategoryData = (event) => {
    const productCategories = sortProductCategories(Array.isArray(event?.product_categories) ? event.product_categories : []);
    return {
        ...event,
        product_categories: productCategories,
        products: flattenProductCategories(productCategories),
    };
};
const isDuplicateShiftEmailBookingError = (error) => {
    const candidate = error;
    if (!candidate || candidate.code !== '23505') {
        return false;
    }
    const searchableText = [candidate.message, candidate.details, candidate.hint]
        .filter((value) => typeof value === 'string')
        .join(' ')
        .toLowerCase();
    return searchableText.includes(DUPLICATE_BOOKING_CONSTRAINT) ||
        searchableText.includes('(shift_id, lower(email))') ||
        searchableText.includes('lower(email)');
};
const getClientIp = (req) => req.ip || req.socket.remoteAddress || 'unknown';
const pruneRateLimitStore = (now) => {
    for (const [ip, timestamps] of bookingRateLimitStore.entries()) {
        const recentHits = timestamps.filter((timestamp) => now - timestamp < BOOKING_RATE_LIMIT_WINDOW_MS);
        if (recentHits.length === 0) {
            bookingRateLimitStore.delete(ip);
            continue;
        }
        bookingRateLimitStore.set(ip, recentHits);
    }
};
const bookingRateLimit = (req, res, next) => {
    const ip = getClientIp(req);
    const now = Date.now();
    const recentHits = (bookingRateLimitStore.get(ip) || []).filter((timestamp) => now - timestamp < BOOKING_RATE_LIMIT_WINDOW_MS);
    if (recentHits.length >= BOOKING_RATE_LIMIT_MAX_REQUESTS) {
        res.set('Retry-After', Math.ceil(BOOKING_RATE_LIMIT_WINDOW_MS / 1000).toString());
        return res.status(429).json({
            error: 'Too many booking attempts from this IP. Please wait 10 minutes and try again.'
        });
    }
    recentHits.push(now);
    bookingRateLimitStore.set(ip, recentHits);
    bookingRateLimitChecks += 1;
    if (bookingRateLimitChecks % BOOKING_RATE_LIMIT_CLEANUP_EVERY === 0) {
        pruneRateLimitStore(now);
    }
    next();
};
app.use(cors({
    origin(origin, callback) {
        // If no origin (like mobile apps or curl requests) or origin is in the allowlist
        if (!origin || allowedCorsOrigins.includes(origin)) {
            return callback(null, true);
        }
        console.error(`CORS blocked for origin: ${origin}`);
        return callback(new Error('Origin not allowed by CORS'));
    }
}));
app.use(express.json());
app.use((req, _res, next) => {
    if (req.body && typeof req.body === 'object') {
        req.body = sanitizeRequestPayload(req.body);
    }
    next();
});
app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok' });
});
// --- ADMIN AUTHORIZATION MIDDLEWARE ---
const requireAdmin = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Missing or malformed Authorization header' });
        }
        const token = authHeader.split(' ')[1];
        if (!token) {
            return res.status(401).json({ error: 'Token missing' });
        }
        // Verify JWT with Supabase Auth
        const { data: { user }, error } = await supabase.auth.getUser(token);
        if (error || !user || !user.email) {
            return res.status(401).json({ error: 'Invalid or expired token', details: error?.message });
        }
        // Check if email is in the ADMIN_EMAILS allowlist
        if (adminEmailAllowlist.length === 0) {
            return res.status(500).json({ error: 'ADMIN_EMAILS is not configured on the server.' });
        }
        if (!adminEmailAllowlist.includes(user.email.toLowerCase())) {
            return res.status(403).json({ error: 'Forbidden: You do not have admin access.' });
        }
        // Request is authenticated and user is an admin
        next();
    }
    catch (err) {
        return res.status(500).json({ error: 'Internal server error during authorization', details: err.message });
    }
};
// Validation Helper
const isValidISODatetime = (iso) => {
    if (!iso.includes('T'))
        return false;
    const [date, time] = iso.split('T');
    if (!date || !time)
        return false;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date))
        return false;
    if (!/^\d{2}:\d{2}$/.test(time.slice(0, 5)))
        return false;
    const [h, m] = time.slice(0, 5).split(':').map(Number);
    if (h < 0 || h > 23 || m < 0 || m > 59)
        return false;
    return true;
};
// --- CANCEL TOKEN HELPER ---
const CANCEL_SECRET = process.env.CANCEL_SECRET || 'weekplore-cancel-secret-change-me';
const SERVER_URL = (process.env.SERVER_URL || `http://localhost:${process.env.PORT || 3001}`).replace(/\/+$/, '');
const generateCancelToken = (bookingId) => {
    return crypto.createHmac('sha256', CANCEL_SECRET).update(String(bookingId)).digest('hex');
};
const buildCancelBookingPath = (bookingId, token) => `${CANCEL_BOOKING_ROUTE}/${encodeURIComponent(String(bookingId))}?token=${encodeURIComponent(token)}`;
const buildCancelBookingUrl = (bookingId, token) => `${SERVER_URL}${buildCancelBookingPath(bookingId, token)}`;
const verifyCancelToken = (bookingId, token) => {
    const expected = generateCancelToken(bookingId);
    try {
        return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(token, 'hex'));
    }
    catch {
        return false;
    }
};
// Cancel page HTML helpers
const cancelPageHtml = (bookingName, eventTitle, bookingId, token) => `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Cancel Booking – Weekplore</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: Georgia, 'Times New Roman', serif; background: #f9f6f1; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; color: #1a1a1a; }
    .card { background: white; border-radius: 32px; padding: 56px 48px; max-width: 480px; width: 100%; text-align: center; box-shadow: 0 20px 60px rgba(0,0,0,0.08); border: 1px solid #e8e0d6; }
    .icon { width: 72px; height: 72px; background: #fff4f0; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 24px; font-size: 32px; }
    .label { font-size: 10px; letter-spacing: 4px; text-transform: uppercase; color: #c9a96e; font-family: sans-serif; font-weight: 700; margin-bottom: 12px; }
    h1 { font-size: 28px; margin-bottom: 8px; }
    .name { color: #1a1a1a; font-weight: bold; }
    p { color: #666; font-family: sans-serif; font-size: 14px; line-height: 1.6; margin-bottom: 8px; }
    .event { font-weight: bold; color: #1a1a1a; }
    .warning { background: #fff4f0; border-radius: 12px; padding: 16px; margin: 24px 0; font-size: 13px; color: #c0392b; font-family: sans-serif; }
    form { margin-top: 32px; }
    .btn-cancel { display: block; width: 100%; padding: 18px; background: #c0392b; color: white; border: none; border-radius: 16px; font-size: 12px; font-weight: 700; letter-spacing: 3px; text-transform: uppercase; cursor: pointer; font-family: sans-serif; margin-bottom: 12px; transition: background 0.2s; }
    .btn-cancel:hover { background: #a93226; }
    .btn-keep { display: block; width: 100%; padding: 18px; background: #f9f6f1; color: #666; border: 1px solid #e8e0d6; border-radius: 16px; font-size: 12px; font-weight: 700; letter-spacing: 3px; text-transform: uppercase; cursor: pointer; font-family: sans-serif; text-decoration: none; }
    .footer { margin-top: 32px; font-size: 11px; color: #aaa; font-family: sans-serif; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">⚠️</div>
    <div class="label">Booking Cancellation</div>
    <h1>Are you sure, <span class="name">${escapeHtml(bookingName.split(' ')[0] || 'there')}?</span></h1>
    <p style="margin-top: 16px;">You are about to cancel your booking for</p>
    <p class="event">${escapeHtml(eventTitle)}</p>
    <div class="warning">This action is permanent and cannot be undone.</div>
    <form method="POST" action="${buildCancelBookingPath(bookingId, token)}">
      <button type="submit" class="btn-cancel">Yes, Cancel My Booking</button>
    </form>
    <a href="/" class="btn-keep">No, Keep My Booking</a>
    <p class="footer">Weekplore · If you did not request this, simply ignore this page.</p>
  </div>
</body>
</html>
`;
const cancelSuccessHtml = (bookingName, eventTitle) => `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Booking Cancelled – Weekplore</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: Georgia, 'Times New Roman', serif; background: #f9f6f1; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; color: #1a1a1a; }
    .card { background: white; border-radius: 32px; padding: 56px 48px; max-width: 480px; width: 100%; text-align: center; box-shadow: 0 20px 60px rgba(0,0,0,0.08); border: 1px solid #e8e0d6; }
    .icon { width: 72px; height: 72px; background: #f0faf4; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 24px; font-size: 32px; }
    .label { font-size: 10px; letter-spacing: 4px; text-transform: uppercase; color: #27ae60; font-family: sans-serif; font-weight: 700; margin-bottom: 12px; }
    h1 { font-size: 28px; margin-bottom: 16px; }
    p { color: #666; font-family: sans-serif; font-size: 14px; line-height: 1.6; margin-bottom: 8px; }
    .event { font-weight: bold; color: #1a1a1a; }
    .btn-home { display: inline-block; margin-top: 32px; padding: 16px 40px; background: #1a1a1a; color: white; border-radius: 99px; font-size: 11px; font-weight: 700; letter-spacing: 3px; text-transform: uppercase; font-family: sans-serif; text-decoration: none; }
    .footer { margin-top: 24px; font-size: 11px; color: #aaa; font-family: sans-serif; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">✓</div>
    <div class="label">Cancellation Confirmed</div>
    <h1>Done, ${escapeHtml(bookingName.split(' ')[0] || 'there')}.</h1>
    <p>Your booking for <span class="event">${escapeHtml(eventTitle)}</span> has been successfully cancelled.</p>
    <p>We hope to see you at a future Weekplore experience.</p>
    <a href="/" class="btn-home">Back to Weekplore</a>
    <p class="footer">Weekplore · Thank you for letting us know.</p>
  </div>
</body>
</html>
`;
const cancelErrorHtml = (message) => `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Error – Weekplore</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: Georgia, serif; background: #f9f6f1; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; }
    .card { background: white; border-radius: 32px; padding: 56px 48px; max-width: 480px; width: 100%; text-align: center; box-shadow: 0 20px 60px rgba(0,0,0,0.08); }
    .icon { font-size: 40px; margin-bottom: 20px; }
    h1 { font-size: 24px; margin-bottom: 12px; }
    p { color: #666; font-family: sans-serif; font-size: 14px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">❌</div>
    <h1>Something went wrong</h1>
    <p>${escapeHtml(message)}</p>
  </div>
</body>
</html>
`;
const getShiftCancelledTemplate = async () => {
    const { data: purposeData } = await supabase
        .from('email_purposes')
        .select('purpose, template_id, email_templates(*)')
        .eq('purpose', 'shift_cancelled')
        .single();
    return purposeData?.email_templates;
};
const sendShiftCancelledEmails = async ({ event, shift, bookings, template, }) => {
    if (!process.env.RESEND_API_KEY || !bookings.length) {
        return;
    }
    const resolvedTemplate = template || await getShiftCancelledTemplate();
    if (!resolvedTemplate) {
        return;
    }
    const dateStr = new Date(shift.start_time).toLocaleString('en-GB', {
        dateStyle: 'full',
        timeStyle: 'short'
    });
    for (const booking of bookings) {
        const emailLanguage = normalizeEmailLanguage(booking.email_language);
        const { subject: localizedSubject, body: localizedBody } = getLocalizedTemplateContent(resolvedTemplate, emailLanguage);
        if (!localizedSubject || !localizedBody) {
            continue;
        }
        const formatEmail = (text, isHtml = false) => {
            const safeName = isHtml ? escapeHtml(booking.full_name) : booking.full_name;
            const safeEventTitle = isHtml ? escapeHtml(event.title) : event.title;
            const safeDateStr = isHtml ? escapeHtml(dateStr) : dateStr;
            const safeLocation = isHtml
                ? escapeHtml(event.location_name || 'TBD')
                : event.location_name || 'TBD';
            return text
                .replace(/{name}/g, safeName)
                .replace(/{event}/g, safeEventTitle)
                .replace(/{date}/g, safeDateStr)
                .replace(/{location}/g, safeLocation)
                .replace(/{people}/g, (booking.number_of_people || 0).toString());
        };
        const subject = formatEmail(localizedSubject);
        const textBody = formatEmail(localizedBody);
        const htmlBody = formatEmail(localizedBody, true).replace(/\n/g, '<br>');
        try {
            await resend.emails.send({
                from: process.env.EMAIL_FROM || 'info@weekplore.gr',
                to: booking.email,
                subject,
                text: textBody,
                html: htmlBody,
            });
            await supabase.from('email_logs').insert([{
                    booking_id: booking.id,
                    shift_id: shift.id,
                    event_id: event.id,
                    recipient_email: booking.email,
                    email_purpose: 'shift_cancelled',
                    status: 'sent',
                    template_id: resolvedTemplate.id
                }]);
        }
        catch (err) {
            console.error(`Failed to send cancellation email to ${booking.email}:`, err.message);
        }
    }
};
const archiveShiftAndNotify = async (shiftId, status = 'archived', extraUpdates = {}) => {
    const { data: shift, error: shiftErr } = await supabase
        .from('shifts')
        .select('*, events(id, title, location_name)')
        .eq('id', shiftId)
        .single();
    if (shiftErr || !shift) {
        throw shiftErr || new Error('Shift not found');
    }
    const archiveStatus = toArchiveStatus(status);
    const shouldNotify = !isArchivedStatus(shift.status);
    let bookings = [];
    if (shouldNotify) {
        const { data: bookingRows, error: bookingsError } = await supabase
            .from('bookings')
            .select('*')
            .eq('shift_id', shiftId);
        if (bookingsError) {
            throw bookingsError;
        }
        bookings = bookingRows || [];
    }
    const { data: updatedShift, error: updateError } = await supabase
        .from('shifts')
        .update({
        ...extraUpdates,
        status: archiveStatus,
        is_active: false,
    })
        .eq('id', shiftId)
        .select()
        .single();
    if (updateError) {
        throw updateError;
    }
    if (shouldNotify && bookings.length > 0) {
        await sendShiftCancelledEmails({
            event: shift.events,
            shift,
            bookings,
        });
    }
    return updatedShift;
};
const archiveEventAndNotify = async (eventId, status = 'archived', extraUpdates = {}) => {
    const { data: event, error: eventErr } = await supabase
        .from('events')
        .select('*')
        .eq('id', eventId)
        .single();
    if (eventErr || !event) {
        throw eventErr || new Error('Event not found');
    }
    const archiveStatus = toArchiveStatus(status);
    const { data: shifts, error: shiftsError } = await supabase
        .from('shifts')
        .select('*')
        .eq('event_id', eventId);
    if (shiftsError) {
        throw shiftsError;
    }
    const shiftsToNotify = (shifts || []).filter((shift) => !isArchivedStatus(shift.status));
    const shiftIdsToNotify = shiftsToNotify.map((shift) => shift.id);
    const bookingsByShift = new Map();
    if (shiftIdsToNotify.length > 0) {
        const { data: bookings, error: bookingsError } = await supabase
            .from('bookings')
            .select('*')
            .in('shift_id', shiftIdsToNotify);
        if (bookingsError) {
            throw bookingsError;
        }
        for (const booking of bookings || []) {
            const existing = bookingsByShift.get(booking.shift_id) || [];
            existing.push(booking);
            bookingsByShift.set(booking.shift_id, existing);
        }
    }
    const { data: updatedEvent, error: updateEventError } = await supabase
        .from('events')
        .update({
        ...extraUpdates,
        status: archiveStatus,
    })
        .eq('id', eventId)
        .select()
        .single();
    if (updateEventError) {
        throw updateEventError;
    }
    if ((shifts || []).length > 0) {
        const { error: updateShiftsError } = await supabase
            .from('shifts')
            .update({
            status: archiveStatus,
            is_active: false,
        })
            .eq('event_id', eventId);
        if (updateShiftsError) {
            throw updateShiftsError;
        }
    }
    if (shiftsToNotify.length > 0) {
        const template = await getShiftCancelledTemplate();
        for (const shift of shiftsToNotify) {
            const bookings = bookingsByShift.get(shift.id) || [];
            if (bookings.length === 0) {
                continue;
            }
            await sendShiftCancelledEmails({
                event: updatedEvent,
                shift,
                bookings,
                template,
            });
        }
    }
    return updatedEvent;
};
// --- PUBLIC SELF-SERVICE CANCEL ENDPOINTS ---
// GET: Show the confirmation page
app.get('/api/cancel-booking/:id', async (req, res) => {
    const { id } = req.params;
    const { token } = req.query;
    if (!token || !verifyCancelToken(id, token)) {
        return res.status(400).send(cancelErrorHtml('This cancellation link is invalid or has expired.'));
    }
    try {
        const { data: booking } = await supabase
            .from('bookings')
            .select('id, full_name, event_id, events(title)')
            .eq('id', id)
            .single();
        if (!booking) {
            return res.status(404).send(cancelErrorHtml('This booking has already been cancelled or does not exist.'));
        }
        const eventTitle = booking.events?.title || 'your experience';
        return res.send(cancelPageHtml(booking.full_name, eventTitle, id, token));
    }
    catch (err) {
        return res.status(500).send(cancelErrorHtml('An unexpected error occurred. Please try again.'));
    }
});
// POST: Perform the actual cancellation
app.post('/api/cancel-booking/:id', async (req, res) => {
    const { id } = req.params;
    const { token } = req.query;
    if (!token || !verifyCancelToken(id, token)) {
        return res.status(400).send(cancelErrorHtml('This cancellation link is invalid or has expired.'));
    }
    try {
        const { data: booking } = await supabase
            .from('bookings')
            .select('id, full_name, event_id, events(title)')
            .eq('id', id)
            .single();
        if (!booking) {
            return res.status(404).send(cancelErrorHtml('This booking has already been cancelled or does not exist.'));
        }
        const eventTitle = booking.events?.title || 'your experience';
        // Delete booking products first, then the booking
        await supabase.from('booking_products').delete().eq('booking_id', id);
        const { error: deleteError } = await supabase.from('bookings').delete().eq('id', id);
        if (deleteError)
            throw deleteError;
        return res.send(cancelSuccessHtml(booking.full_name, eventTitle));
    }
    catch (err) {
        return res.status(500).send(cancelErrorHtml('Failed to cancel your booking. Please contact us directly.'));
    }
});
// --- EVENTS ---
app.get('/api/events', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('events')
            .select(`
        *,
        images:event_images(*),
        shifts(*),
        product_categories(
            *,
            products(*)
        )
      `)
            .eq('is_hidden', false)
            .order('event_date', { ascending: true });
        if (error)
            throw error;
        if (data) {
            const visibleEvents = data
                .filter((event) => !isArchivedStatus(event.status))
                .map((event) => {
                if (event.shifts) {
                    event.shifts = event.shifts.filter((shift) => !isArchivedStatus(shift.status) && shift.is_active !== false);
                }
                return attachProductCategoryData(event);
            });
            return res.json(visibleEvents);
        }
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.get('/api/events/:slug', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('events')
            .select(`
        *,
        images:event_images(*),
        shifts(*),
        product_categories(
            *,
            products(*)
        )
      `)
            .eq('slug', req.params.slug)
            .eq('is_hidden', false)
            .single();
        if (error)
            throw error;
        if (data && isArchivedStatus(data.status)) {
            return res.status(404).json({ error: 'Experience not found.' });
        }
        if (data?.shifts) {
            data.shifts = data.shifts.filter((shift) => !isArchivedStatus(shift.status) && shift.is_active !== false);
        }
        res.json(attachProductCategoryData(data));
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.get('/api/private-events', async (_req, res) => {
    try {
        const { data, error } = await supabase
            .from('private_events')
            .select('*')
            .order('created_at', { ascending: false });
        if (error)
            throw error;
        res.json((data || []).filter((privateEvent) => privateEvent?.is_visible !== false));
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/private-event-inquiries', async (req, res) => {
    const firstName = normalizeSingleLineText(req.body?.first_name, 80);
    const lastName = normalizeSingleLineText(req.body?.last_name, 80);
    const email = normalizeEmail(req.body?.email);
    const phone = normalizePhone(req.body?.phone);
    const normalizedPeople = Number(req.body?.number_of_people);
    const dateApprox = normalizeSingleLineText(req.body?.date_approx, 10);
    const setting = normalizeSingleLineText(req.body?.setting, 40);
    const area = normalizeSingleLineText(req.body?.area, 120);
    const message = normalizeMultilineText(req.body?.message, 4000);
    const normalizedDecorationBudget = Number(req.body?.decoration_budget);
    const isCustom = Boolean(req.body?.is_custom);
    const hasActivity = Boolean(req.body?.has_activity);
    const emailLanguage = normalizeEmailLanguage(req.body?.email_language);
    const privateEventTemplateId = isCustom
        ? null
        : normalizeSingleLineText(req.body?.private_event_template_id, 64) || null;
    if (!firstName || !lastName || !email || !phone || !dateApprox || !setting || !area || !message || req.body?.decoration_budget === undefined || req.body?.decoration_budget === null) {
        return res.status(400).json({ error: 'Please fill in all required fields.' });
    }
    if (!EMAIL_REGEX.test(email)) {
        return res.status(400).json({ error: 'Please provide a valid email address.' });
    }
    if (!Number.isInteger(normalizedPeople) || normalizedPeople < 1) {
        return res.status(400).json({ error: 'Please provide a valid number of guests.' });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dateApprox)) {
        return res.status(400).json({ error: 'Please provide a valid approximate date.' });
    }
    if (!Number.isFinite(normalizedDecorationBudget) || normalizedDecorationBudget < 0) {
        return res.status(400).json({ error: 'Please provide a valid decoration budget.' });
    }
    try {
        const { error, data: insertedData } = await supabase
            .from('private_event_inquiries')
            .insert([{
                first_name: firstName,
                last_name: lastName,
                email,
                phone,
                number_of_people: normalizedPeople,
                date_approx: dateApprox,
                setting: setting || null,
                has_activity: hasActivity,
                decoration_budget: normalizedDecorationBudget,
                message: message || null,
                area: area || null,
                is_custom: isCustom,
                private_event_template_id: privateEventTemplateId,
                status: 'new',
                email_language: emailLanguage
            }])
            .select()
            .single();
        if (error) {
            console.error('Insert error:', error);
            throw error;
        }
        // Send Email Notification to Admin
        if (process.env.RESEND_API_KEY) {
            const adminEmail = process.env.PRIVATE_EVENT_ADMIN_EMAIL || adminEmailAllowlist[0];
            if (adminEmail) {
                const safeMessage = message ? escapeHtml(message).replace(/\n/g, '<br/>') : 'No message provided';
                const htmlBody = `
                    <h2>New Private Event Inquiry</h2>
                    <p><strong>Name:</strong> ${escapeHtml(`${firstName} ${lastName}`)}</p>
                    <p><strong>Email:</strong> ${escapeHtml(email)}</p>
                    <p><strong>Phone:</strong> ${escapeHtml(phone)}</p>
                    <p><strong>Date (approx):</strong> ${escapeHtml(dateApprox || 'Not specified')}</p>
                    <p><strong>Number of People:</strong> ${normalizedPeople || 'Not specified'}</p>
                    <p><strong>Area:</strong> ${escapeHtml(area || 'Not specified')}</p>
                    <p><strong>Setting:</strong> ${escapeHtml(setting || 'Not specified')}</p>
                    <p><strong>Include Activity:</strong> ${hasActivity ? 'Yes' : 'No'}</p>
                    <p><strong>Decoration Budget:</strong> €${normalizedDecorationBudget}</p>
                    <p><strong>Message:</strong><br/>${safeMessage}</p>
                    <br/>
                    <p><small>Inquiry ID: ${insertedData?.id || 'N/A'}</small></p>
                `;
                try {
                    await resend.emails.send({
                        from: process.env.EMAIL_FROM || 'info@weekplore.gr',
                        to: adminEmail,
                        subject: `New Private Event Inquiry from ${firstName} ${lastName}`,
                        html: htmlBody,
                    });
                    await supabase.from('email_logs').insert([{
                            booking_id: null,
                            shift_id: null,
                            event_id: null,
                            recipient_email: adminEmail,
                            email_purpose: 'private_event_admin_notification',
                            status: 'sent',
                            template_id: null
                        }]);
                }
                catch (emailErr) {
                    console.error('Failed to send admin notification email:', emailErr.message);
                }
            }
            // --- SEND AUTO-REPLY TO USER ---
            try {
                // Fetch Template from mappings
                const { data: purposeData } = await supabase
                    .from('email_purposes')
                    .select('purpose, template_id, email_templates(*)')
                    .eq('purpose', 'private_event_inquiry_received')
                    .single();
                const autoReplyTemplate = purposeData?.email_templates;
                if (autoReplyTemplate) {
                    const { subject: localizedSubject, body: localizedBody } = getLocalizedTemplateContent(autoReplyTemplate, emailLanguage);
                    if (!localizedSubject || !localizedBody) {
                        throw new Error('Selected private event auto-reply template is missing localized content.');
                    }
                    const recipientName = `${firstName} ${lastName}`.trim();
                    const eventName = isCustom ? 'Custom Private Event' : 'Private Event';
                    const dateStr = dateApprox || 'TBD';
                    const locationStr = area || 'TBD';
                    const peopleStr = normalizedPeople ? normalizedPeople.toString() : 'TBD';
                    // Simplified formatter for inquiries
                    const formatEmail = (text, isHtml = false) => {
                        const safeRecipientName = isHtml ? escapeHtml(recipientName) : recipientName;
                        const safeEventName = isHtml ? escapeHtml(eventName) : eventName;
                        const safeDateStr = isHtml ? escapeHtml(dateStr) : dateStr;
                        const safeLocationStr = isHtml ? escapeHtml(locationStr) : locationStr;
                        const formattedText = text
                            .replace(/{name}/g, safeRecipientName)
                            .replace(/{event}/g, safeEventName)
                            .replace(/{date}/g, safeDateStr)
                            .replace(/{location}/g, safeLocationStr)
                            .replace(/{people}/g, peopleStr)
                            .replace(/{cancel_url}/g, '#');
                        return isHtml ? formattedText.replace(/\n/g, '<br>') : formattedText;
                    };
                    const textBody = formatEmail(localizedBody, false);
                    const htmlBody = formatEmail(localizedBody, true);
                    const subject = formatEmail(localizedSubject, false);
                    const { error: sendError } = await resend.emails.send({
                        from: process.env.EMAIL_FROM || 'info@weekplore.gr',
                        to: email,
                        subject: subject,
                        text: textBody,
                        html: htmlBody,
                    });
                    if (sendError)
                        throw sendError;
                    const { error: logError } = await supabase.from('email_logs').insert([{
                            booking_id: null,
                            shift_id: null,
                            event_id: null,
                            recipient_email: email,
                            email_purpose: 'private_event_inquiry_received',
                            status: 'sent',
                            template_id: autoReplyTemplate.id
                        }]);
                }
            }
            catch (err) {
                console.error(`Failed to send private event auto-reply email:`, err.message);
                // Fetch the template ID if we failed after retrieving it
                let templateId = null;
                try {
                    const { data } = await supabase
                        .from('email_purposes')
                        .select('template_id')
                        .eq('purpose', 'private_event_inquiry_received')
                        .single();
                    templateId = data?.template_id;
                }
                catch { /* ignore */ }
                await supabase.from('email_logs').insert([{
                        booking_id: null,
                        shift_id: null,
                        event_id: null,
                        recipient_email: email,
                        email_purpose: 'private_event_inquiry_received',
                        status: 'failed',
                        template_id: templateId,
                        error_message: err.message
                    }]);
            }
        }
        res.json({ success: true, message: 'Inquiry submitted successfully.' });
    }
    catch (error) {
        console.error('Private event inquiry error:', error);
        res.status(500).json({ error: 'Failed to submit inquiry. Please try again later.' });
    }
});
// --- BOOKINGS ---
app.post('/api/bookings', bookingRateLimit, async (req, res) => {
    const { eventId, formData } = req.body ?? {};
    const normalizedEventId = Number(eventId);
    const normalizedShiftId = Number(formData?.shiftId);
    const normalizedPeople = Number(formData?.numberOfPeople);
    const normalizedFullName = normalizeSingleLineText(formData?.fullName, 120);
    const normalizedEmail = normalizeEmail(formData?.email);
    const normalizedPhone = normalizePhone(formData?.phone);
    const normalizedEmailLanguage = normalizeEmailLanguage(formData?.email_language);
    const selectedProducts = Array.isArray(formData?.products) ? formData.products : [];
    // --- 1. SERVER-SIDE VALIDATION & CAPACITY CHECKS ---
    if (!Number.isInteger(normalizedEventId) ||
        normalizedEventId < 1 ||
        !formData ||
        !Number.isInteger(normalizedShiftId) ||
        normalizedShiftId < 1 ||
        !normalizedFullName ||
        !normalizedEmail ||
        !normalizedPhone) {
        return res.status(400).json({ error: 'Missing required booking information' });
    }
    if (!EMAIL_REGEX.test(normalizedEmail)) {
        return res.status(400).json({ error: 'Please provide a valid email address.' });
    }
    if (!Number.isInteger(normalizedPeople) || normalizedPeople < 1) {
        return res.status(400).json({ error: 'Invalid number of people.' });
    }
    const bookingKey = `${normalizedShiftId}:${normalizedEmail}`;
    if (activeBookingKeys.has(bookingKey)) {
        return res.status(409).json({ error: 'A booking for this email and shift is already being processed.' });
    }
    activeBookingKeys.add(bookingKey);
    try {
        let productTotal = 0;
        const { data: event, error: eventError } = await supabase
            .from('events')
            .select('id, price, is_hidden, is_sold_out, booking_deadline, status')
            .eq('id', normalizedEventId)
            .single();
        if (eventError || !event) {
            return res.status(404).json({ error: 'Experience not found.' });
        }
        if (isArchivedStatus(event.status) || event.is_hidden || event.is_sold_out) {
            return res.status(400).json({ error: 'This experience is not currently bookable.' });
        }
        if (event.booking_deadline) {
            const bookingDeadline = new Date(event.booking_deadline);
            if (!Number.isNaN(bookingDeadline.getTime()) && bookingDeadline.getTime() < Date.now()) {
                return res.status(400).json({ error: 'The booking deadline for this experience has passed.' });
            }
        }
        // Verify Event and Shift relationship + fetch shift status
        const { data: shift, error: fetchShiftError } = await supabase
            .from('shifts')
            .select('id, event_id, people_counter, capacity, is_active, is_full, start_time, is_confirmed, status')
            .eq('id', normalizedShiftId)
            .single();
        if (fetchShiftError || !shift) {
            return res.status(404).json({ error: 'Experience shift not found.' });
        }
        if (shift.event_id !== normalizedEventId) {
            return res.status(400).json({ error: 'Shift does not belong to this experience.' });
        }
        if (isArchivedStatus(shift.status) || !shift.is_active) {
            return res.status(400).json({ error: 'This shift is not active.' });
        }
        if (shift.is_full) {
            return res.status(400).json({ error: 'This shift is already full.' });
        }
        const { data: duplicateBookings, error: duplicateBookingsError } = await supabase
            .from('bookings')
            .select('id')
            .eq('shift_id', normalizedShiftId)
            .ilike('email', normalizedEmail)
            .limit(1);
        if (duplicateBookingsError)
            throw duplicateBookingsError;
        if ((duplicateBookings || []).length > 0) {
            return res.status(409).json({ error: DUPLICATE_BOOKING_ERROR_MESSAGE });
        }
        const { data: existingBookings, error: bookingsErr } = await supabase
            .from('bookings')
            .select('number_of_people')
            .eq('shift_id', shift.id);
        if (bookingsErr)
            throw bookingsErr;
        const currentTotal = (existingBookings || []).reduce((sum, booking) => sum + (booking.number_of_people || 0), 0);
        if (typeof shift.capacity === 'number' && shift.capacity > 0 && currentTotal + normalizedPeople > shift.capacity) {
            return res.status(400).json({
                error: `Sorry, only ${Math.max(shift.capacity - currentTotal, 0)} spots remaining for this experience.`
            });
        }
        const { data: eventProductCategories, error: eventProductCategoriesError } = await supabase
            .from('product_categories')
            .select(`
                id,
                products(
                    id,
                    price
                )
            `)
            .eq('event_id', normalizedEventId);
        if (eventProductCategoriesError)
            throw eventProductCategoriesError;
        const populatedProductCategories = sortProductCategories(eventProductCategories || [])
            .filter((productCategory) => (productCategory.products?.length || 0) > 0);
        const hasInvalidProductPayload = selectedProducts.some((product) => !product ||
            !isNonEmptyString(product.product_id) ||
            !Number.isInteger(product.quantity) ||
            product.quantity < 1);
        if (hasInvalidProductPayload) {
            return res.status(400).json({ error: 'Invalid product selection.' });
        }
        const requiredProductSelectionCount = normalizedPeople * populatedProductCategories.length;
        if (requiredProductSelectionCount === 0) {
            if (selectedProducts.length > 0) {
                return res.status(400).json({ error: 'This experience does not accept product selections.' });
            }
        }
        else {
            const totalProductQuantity = selectedProducts.reduce((sum, product) => sum + product.quantity, 0);
            if (totalProductQuantity !== requiredProductSelectionCount) {
                return res.status(400).json({ error: 'Each guest must pick one product from every category.' });
            }
            const productCategoryByProductId = new Map();
            const productPriceById = new Map();
            for (const productCategory of populatedProductCategories) {
                for (const product of productCategory.products || []) {
                    productCategoryByProductId.set(String(product.id), Number(productCategory.id));
                    productPriceById.set(String(product.id), Number(product.price) || 0);
                }
            }
            const selectedCategoryQuantities = new Map();
            for (const product of selectedProducts) {
                const productId = String(product.product_id);
                const productCategoryId = productCategoryByProductId.get(productId);
                if (!productCategoryId) {
                    return res.status(400).json({ error: 'Invalid product selected.' });
                }
                selectedCategoryQuantities.set(productCategoryId, (selectedCategoryQuantities.get(productCategoryId) || 0) + product.quantity);
            }
            const hasIncompleteCategorySelections = populatedProductCategories.some((productCategory) => (selectedCategoryQuantities.get(Number(productCategory.id)) || 0) !== normalizedPeople);
            if (hasIncompleteCategorySelections) {
                return res.status(400).json({ error: 'Each guest must pick one product from every category.' });
            }
            productTotal = selectedProducts.reduce((sum, product) => sum + (product.quantity * (productPriceById.get(String(product.product_id)) || 0)), 0);
        }
        const totalBill = ((Number(event.price) || 0) * normalizedPeople) + productTotal;
        // --- 2. Insert booking into Supabase ---
        const { data: booking, error: bookingError } = await supabase
            .from('bookings')
            .insert([
            {
                event_id: normalizedEventId,
                shift_id: normalizedShiftId,
                full_name: normalizedFullName,
                email: normalizedEmail,
                phone: normalizedPhone,
                number_of_people: normalizedPeople,
                payment_status: 'pending',
                bill: totalBill,
                email_language: normalizedEmailLanguage
            }
        ])
            .select()
            .single();
        if (bookingError) {
            if (isDuplicateShiftEmailBookingError(bookingError)) {
                return res.status(409).json({ error: DUPLICATE_BOOKING_ERROR_MESSAGE });
            }
            throw bookingError;
        }
        // --- 3. Insert booking products if any ---
        if (selectedProducts.length > 0) {
            const bookingProducts = selectedProducts.map((p) => ({
                booking_id: booking.id,
                product_id: p.product_id,
                quantity: p.quantity
            }));
            const { error: productsError } = await supabase
                .from('booking_products')
                .insert(bookingProducts);
            if (productsError) {
                console.error('Booking products insert failed, rolling back booking:', productsError.message);
                const { error: rollbackProductsError } = await supabase
                    .from('booking_products')
                    .delete()
                    .eq('booking_id', booking.id);
                if (rollbackProductsError) {
                    console.error('Failed to roll back booking products:', rollbackProductsError.message);
                }
                const { error: rollbackBookingError } = await supabase
                    .from('bookings')
                    .delete()
                    .eq('id', booking.id);
                if (rollbackBookingError) {
                    console.error('Failed to roll back booking after products error:', rollbackBookingError.message);
                }
                throw productsError;
            }
        }
        // --- 4. Email Logic (Run asynchronously so it doesn't block the response) ---
        if (process.env.RESEND_API_KEY) {
            (async () => {
                try {
                    const templatesByPurpose = await getMappedTemplates([
                        'interest_received',
                        'payment_invitation',
                        'confirmed_shift_booking'
                    ]);
                    const interestReceivedTemplate = templatesByPurpose.get('interest_received');
                    const paymentInvitationTemplate = templatesByPurpose.get('payment_invitation');
                    const confirmedShiftTemplate = templatesByPurpose.get('confirmed_shift_booking');
                    const { data: emailEvent, error: emailEventError } = await supabase
                        .from('events')
                        .select('id, title, location_name')
                        .eq('id', normalizedEventId)
                        .single();
                    if (emailEventError) {
                        throw emailEventError;
                    }
                    const dateStr = shift ? new Date(shift.start_time).toLocaleString('en-GB', {
                        dateStyle: 'full',
                        timeStyle: 'short'
                    }).replace(' at ', ', ') : 'TBD';
                    const formatEmail = (text, recipientName, bookingId, peopleCount, billAmount, isHtml = false) => {
                        const cancelToken = generateCancelToken(bookingId);
                        const cancelUrl = buildCancelBookingUrl(bookingId, cancelToken);
                        const safeRecipientName = isHtml ? escapeHtml(recipientName) : recipientName;
                        const safeEventTitle = isHtml ? escapeHtml(emailEvent?.title || 'Experience') : emailEvent?.title || 'Experience';
                        const safeDateStr = isHtml ? escapeHtml(dateStr) : dateStr;
                        const safeLocationName = isHtml ? escapeHtml(emailEvent?.location_name || 'TBD') : emailEvent?.location_name || 'TBD';
                        const priceText = billAmount == null ? '0' : String(billAmount);
                        const safePrice = isHtml ? escapeHtml(priceText) : priceText;
                        const normalizedPeopleCount = Number.isFinite(peopleCount) ? peopleCount : 0;
                        const cancelLink = isHtml
                            ? `<a href="${cancelUrl}" style="color: #c0392b; font-weight: bold; text-decoration: underline;">Cancel Reservation</a>`
                            : cancelUrl;
                        return text
                            .replace(/{name}/g, safeRecipientName)
                            .replace(/{event}/g, safeEventTitle)
                            .replace(/{date}/g, safeDateStr)
                            .replace(/{location}/g, safeLocationName)
                            .replace(/{price}/g, safePrice)
                            .replace(/{people}/g, normalizedPeopleCount.toString())
                            .replace(/{cancel_url}/g, cancelLink);
                    };
                    const sendTemplateEmail = async ({ recipientEmail, recipientName, bookingId, peopleCount, billAmount, template, purpose, language, }) => {
                        if (!template) {
                            return;
                        }
                        const { subject: localizedSubject, body: localizedBody } = getLocalizedTemplateContent(template, language);
                        if (!localizedSubject || !localizedBody) {
                            throw new Error(`Selected ${purpose} template is missing localized content.`);
                        }
                        const subject = formatEmail(localizedSubject, recipientName, bookingId, peopleCount, billAmount, false);
                        const textBody = formatEmail(localizedBody, recipientName, bookingId, peopleCount, billAmount, false);
                        const htmlBody = formatEmail(localizedBody, recipientName, bookingId, peopleCount, billAmount, true)
                            .replace(/\n/g, '<br>');
                        try {
                            const { error: sendError } = await resend.emails.send({
                                from: process.env.EMAIL_FROM || 'info@weekplore.gr',
                                to: recipientEmail,
                                subject: subject,
                                text: textBody,
                                html: htmlBody,
                            });
                            if (sendError) {
                                throw sendError;
                            }
                            await supabase.from('email_logs').insert([{
                                    booking_id: bookingId,
                                    shift_id: normalizedShiftId,
                                    event_id: normalizedEventId,
                                    recipient_email: recipientEmail,
                                    email_purpose: purpose,
                                    status: 'sent',
                                    template_id: template.id ?? null
                                }]);
                        }
                        catch (err) {
                            console.error(`Failed to send ${purpose} email:`, err.message);
                            await supabase.from('email_logs').insert([{
                                    booking_id: bookingId,
                                    shift_id: normalizedShiftId,
                                    event_id: normalizedEventId,
                                    recipient_email: recipientEmail,
                                    email_purpose: purpose,
                                    status: 'failed',
                                    template_id: template.id ?? null,
                                    error_message: err.message
                                }]);
                        }
                    };
                    const { data: allShiftBookings, error: allShiftBookingsError } = await supabase
                        .from('bookings')
                        .select('id, number_of_people, email, full_name, email_language, bill')
                        .eq('shift_id', normalizedShiftId);
                    if (allShiftBookingsError) {
                        throw allShiftBookingsError;
                    }
                    const emailTotalPeople = (allShiftBookings || []).reduce((sum, shiftBooking) => sum + (Number(shiftBooking.number_of_people) || 0), 0);
                    const isGoalMetNow = Boolean(shift && shift.people_counter > 0 && emailTotalPeople >= shift.people_counter);
                    let templateToUse = null;
                    let purposeToUse = '';
                    if (shift?.is_confirmed || isGoalMetNow) {
                        templateToUse = confirmedShiftTemplate;
                        purposeToUse = 'confirmed_shift_booking';
                    }
                    else {
                        templateToUse = interestReceivedTemplate;
                        purposeToUse = 'interest_received';
                    }
                    await sendTemplateEmail({
                        recipientEmail: normalizedEmail,
                        recipientName: normalizedFullName,
                        bookingId: booking.id,
                        peopleCount: normalizedPeople,
                        billAmount: booking.bill,
                        template: templateToUse,
                        purpose: purposeToUse,
                        language: normalizedEmailLanguage
                    });
                    if (isGoalMetNow && shift && !shift.is_confirmed) {
                        const { error: confirmError } = await supabase
                            .from('shifts')
                            .update({ is_confirmed: true, confirmed_at: new Date().toISOString() })
                            .eq('id', normalizedShiftId);
                        if (confirmError) {
                            throw confirmError;
                        }
                        if (paymentInvitationTemplate && allShiftBookings) {
                            const previousBookings = allShiftBookings.filter((shiftBooking) => shiftBooking.id !== booking.id);
                            for (const previousBooking of previousBookings) {
                                await sendTemplateEmail({
                                    recipientEmail: previousBooking.email,
                                    recipientName: previousBooking.full_name,
                                    bookingId: previousBooking.id,
                                    peopleCount: Number(previousBooking.number_of_people) || 0,
                                    billAmount: previousBooking.bill,
                                    template: paymentInvitationTemplate,
                                    purpose: 'payment_invitation',
                                    language: normalizeEmailLanguage(previousBooking.email_language)
                                });
                            }
                        }
                    }
                }
                catch (emailErr) {
                    console.error('Email automation failed:', emailErr.message);
                }
            })();
        }
        res.json(booking);
    }
    catch (error) {
        console.error('Booking error:', error);
        if (isDuplicateShiftEmailBookingError(error)) {
            return res.status(409).json({ error: DUPLICATE_BOOKING_ERROR_MESSAGE });
        }
        res.status(500).json({ error: 'Failed to create booking. Please try again later.' });
    }
    finally {
        activeBookingKeys.delete(bookingKey);
    }
});
app.patch('/api/admin/bookings/status', requireAdmin, async (req, res) => {
    const { bookingIds, status } = req.body;
    const allowedStatuses = new Set(['pending', 'paid']);
    if (!Array.isArray(bookingIds) || bookingIds.length === 0 || !allowedStatuses.has(status)) {
        return res.status(400).json({ error: 'Invalid booking status update payload.' });
    }
    try {
        const { error } = await supabase
            .from('bookings')
            .update({ payment_status: status })
            .in('id', bookingIds);
        if (error)
            throw error;
        res.json({ success: true });
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// --- ADMIN API ---
app.get('/api/admin/events', requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('events')
            .select(`
        *,
        shifts(
          *,
          bookings(*)
        ),
        product_categories(
          *,
          products(*)
        )
      `)
            .order('created_at', { ascending: false });
        if (error)
            throw error;
        if (data) {
            res.json(data.map((event) => attachProductCategoryData(event)));
            return;
        }
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.get('/api/admin/private-events', requireAdmin, async (_req, res) => {
    try {
        const { data, error } = await supabase
            .from('private_events')
            .select('*')
            .order('created_at', { ascending: false });
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.get('/api/admin/private-event-inquiries', requireAdmin, async (_req, res) => {
    try {
        const { data, error } = await supabase
            .from('private_event_inquiries')
            .select(`
                *,
                private_event_templates:private_event_template_id(name)
            `)
            .order('created_at', { ascending: false });
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/admin/validate-event', requireAdmin, (req, res) => {
    const data = req.body;
    const errors = [];
    if (!data.title)
        errors.push('Title is required');
    if (!data.event_date || !isValidISODatetime(data.event_date))
        errors.push('Valid event date and time are required');
    if (!data.booking_deadline || !isValidISODatetime(data.booking_deadline))
        errors.push('Valid booking deadline is required');
    if (errors.length > 0) {
        return res.status(400).json({ errors });
    }
    res.json({ success: true });
});
app.post('/api/admin/events', requireAdmin, async (req, res) => {
    const { eventData, imageUrls, shifts, productCategories, products } = req.body;
    try {
        const safeImageUrls = Array.isArray(imageUrls) ? imageUrls.filter(isNonEmptyString) : [];
        const safeShifts = Array.isArray(shifts) ? shifts : [];
        const safeProductCategories = Array.isArray(productCategories) ? productCategories : [];
        const safeLegacyProducts = Array.isArray(products) ? products : [];
        if (safeShifts.length === 0) {
            return res.status(400).json({ error: 'At least one shift is required to create an event.' });
        }
        const safeEventData = {
            ...pickDefined(eventData || {}, [
                'title',
                'slug',
                'short_description',
                'full_description',
                'price',
                'event_date',
                'booking_deadline',
                'location_name',
                'location_address',
                'location_url',
                'is_hidden',
                'is_sold_out',
                'base_price',
                'tag',
            ]),
            cover_image_url: safeImageUrls[0] || '',
            is_sold_out: Boolean(eventData?.is_sold_out),
            is_hidden: Boolean(eventData?.is_hidden),
            status: isNonEmptyString(eventData?.status) ? eventData.status : 'active',
        };
        const { data: event, error: eventError } = await supabase
            .from('events')
            .insert([safeEventData])
            .select()
            .single();
        if (eventError)
            throw eventError;
        if (safeImageUrls.length > 0) {
            const imageRecords = safeImageUrls.map((url, index) => ({
                event_id: event.id,
                image_url: url,
                is_cover: index === 0
            }));
            await supabase.from('event_images').insert(imageRecords);
        }
        if (safeShifts.length > 0) {
            const shiftRecords = safeShifts.map((s) => ({
                event_id: event.id,
                start_time: s.start_time,
                end_time: s.end_time,
                capacity: s.capacity ?? 999,
                people_counter: s.people_counter || 0,
                booked_spots: 0,
                is_active: s.is_active ?? true,
                is_full: s.is_full ?? false,
                status: isNonEmptyString(s.status) ? s.status : 'active',
            }));
            await supabase.from('shifts').insert(shiftRecords);
        }
        const normalizedProductCategories = (safeProductCategories.length > 0
            ? safeProductCategories
            : (safeLegacyProducts.length > 0 ? [{ name: 'Add-ons', products: safeLegacyProducts }] : []))
            .map((productCategory) => ({
            name: normalizeSingleLineText(productCategory?.name, 120),
            products: Array.isArray(productCategory?.products) ? productCategory.products : [],
        }))
            .filter((productCategory) => productCategory.name);
        for (const productCategory of normalizedProductCategories) {
            const { data: insertedProductCategory, error: productCategoryError } = await supabase
                .from('product_categories')
                .insert([{
                    event_id: event.id,
                    name: productCategory.name,
                }])
                .select()
                .single();
            if (productCategoryError)
                throw productCategoryError;
            const categoryProducts = productCategory.products
                .map((product) => {
                const title = normalizeSingleLineText(product?.title, 160);
                if (!title) {
                    return null;
                }
                return {
                    category_id: insertedProductCategory.id,
                    title,
                    description: normalizeMultilineText(product?.description, 1000) || null,
                    price: Number.isFinite(Number(product?.price)) ? Number(product.price) : 0,
                    image_url: normalizeSingleLineText(product?.image_url, 2000) || null,
                };
            })
                .filter(Boolean);
            if (categoryProducts.length > 0) {
                const { error: productError } = await supabase.from('products').insert(categoryProducts);
                if (productError)
                    throw productError;
            }
        }
        res.json(event);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.put('/api/admin/events/:id', requireAdmin, async (req, res) => {
    try {
        const safeEventData = pickDefined(req.body || {}, [
            'title',
            'slug',
            'short_description',
            'full_description',
            'price',
            'event_date',
            'booking_deadline',
            'location_name',
            'location_address',
            'location_url',
            'is_hidden',
            'is_sold_out',
            'status',
            'base_price',
            'tag',
            'cover_image_url',
        ]);
        if (Object.keys(safeEventData).length === 0) {
            return res.status(400).json({ error: 'No valid event fields provided.' });
        }
        if (safeEventData.status !== undefined) {
            safeEventData.status = toArchiveStatus(safeEventData.status, normalizeLifecycleStatus(safeEventData.status) || 'active');
        }
        if (isArchivedStatus(safeEventData.status)) {
            const { status, ...otherUpdates } = safeEventData;
            const data = await archiveEventAndNotify(req.params.id, status, otherUpdates);
            return res.json(data);
        }
        const { data, error } = await supabase
            .from('events')
            .update(safeEventData)
            .eq('id', req.params.id)
            .select()
            .single();
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.delete('/api/admin/events/:id', requireAdmin, async (req, res) => {
    try {
        const data = await archiveEventAndNotify(req.params.id, 'archived');
        res.json({ success: true, message: 'Event archived and notifications triggered.', event: data });
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// PRIVATE EVENTS
app.post('/api/admin/private-events', requireAdmin, async (req, res) => {
    try {
        const safePrivateEvent = pickDefined(req.body || {}, [
            'name',
            'description',
            'image_url',
            'is_visible',
        ]);
        if (safePrivateEvent.is_visible === undefined) {
            safePrivateEvent.is_visible = true;
        }
        if (!isNonEmptyString(safePrivateEvent.name)) {
            return res.status(400).json({ error: 'Private event name is required.' });
        }
        if (typeof safePrivateEvent.is_visible !== 'boolean') {
            return res.status(400).json({ error: 'Private event visibility must be a boolean.' });
        }
        const { data, error } = await supabase
            .from('private_events')
            .insert([safePrivateEvent])
            .select()
            .single();
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.put('/api/admin/private-events/:id', requireAdmin, async (req, res) => {
    try {
        const safePrivateEvent = pickDefined(req.body || {}, [
            'name',
            'description',
            'image_url',
            'is_visible',
        ]);
        if (Object.keys(safePrivateEvent).length === 0) {
            return res.status(400).json({ error: 'No valid private event fields provided.' });
        }
        if (safePrivateEvent.is_visible !== undefined && typeof safePrivateEvent.is_visible !== 'boolean') {
            return res.status(400).json({ error: 'Private event visibility must be a boolean.' });
        }
        const { data, error } = await supabase
            .from('private_events')
            .update(safePrivateEvent)
            .eq('id', req.params.id)
            .select()
            .single();
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.delete('/api/admin/private-events/:id', requireAdmin, async (req, res) => {
    try {
        const privateEventId = normalizeSingleLineText(req.params.id, 64);
        if (!privateEventId) {
            return res.status(400).json({ error: 'Invalid private event id.' });
        }
        const { count: linkedInquiryCount, error: linkedInquiryCountError } = await supabase
            .from('private_event_inquiries')
            .select('id', { count: 'exact', head: true })
            .eq('private_event_template_id', privateEventId);
        if (linkedInquiryCountError)
            throw linkedInquiryCountError;
        if ((linkedInquiryCount || 0) > 0) {
            const { error: detachInquiryError } = await supabase
                .from('private_event_inquiries')
                .update({ private_event_template_id: null })
                .eq('private_event_template_id', privateEventId);
            if (detachInquiryError)
                throw detachInquiryError;
        }
        const { data, error } = await supabase
            .from('private_events')
            .delete()
            .eq('id', privateEventId)
            .select('id')
            .maybeSingle();
        if (error)
            throw error;
        if (!data) {
            return res.status(404).json({ error: 'Private event not found.' });
        }
        res.json({
            success: true,
            detachedInquiryCount: linkedInquiryCount || 0
        });
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// SHIFTS
app.post('/api/admin/shifts', requireAdmin, async (req, res) => {
    try {
        const safeShiftData = {
            ...pickDefined(req.body || {}, [
                'event_id',
                'start_time',
                'end_time',
                'capacity',
                'people_counter',
                'is_confirmed',
                'is_full',
                'is_active',
                'status',
            ]),
            end_time: req.body?.end_time || null,
            capacity: req.body?.capacity ?? 999,
            people_counter: req.body?.people_counter || 0,
            is_confirmed: Boolean(req.body?.is_confirmed),
            is_full: Boolean(req.body?.is_full),
            is_active: req.body?.is_active ?? true,
            status: isNonEmptyString(req.body?.status) ? req.body.status : 'active',
        };
        const { data, error } = await supabase.from('shifts').insert([safeShiftData]).select().single();
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.put('/api/admin/shifts/:id', requireAdmin, async (req, res) => {
    try {
        const shiftId = req.params.id;
        const updates = pickDefined(req.body || {}, [
            'start_time',
            'end_time',
            'capacity',
            'people_counter',
            'is_confirmed',
            'is_full',
            'is_active',
            'status',
        ]);
        if (Object.keys(updates).length === 0) {
            return res.status(400).json({ error: 'No valid shift fields provided.' });
        }
        if (updates.status !== undefined) {
            updates.status = toArchiveStatus(updates.status, normalizeLifecycleStatus(updates.status) || 'active');
        }
        if (isArchivedStatus(updates.status)) {
            const { status, ...otherUpdates } = updates;
            const data = await archiveShiftAndNotify(shiftId, status, otherUpdates);
            return res.json(data);
        }
        // Handle confirmed_at logic
        if (updates.is_confirmed === true) {
            const { data: currentShift } = await supabase
                .from('shifts')
                .select('is_confirmed')
                .eq('id', shiftId)
                .single();
            if (currentShift && !currentShift.is_confirmed) {
                updates.confirmed_at = new Date().toISOString();
            }
        }
        const { data, error } = await supabase.from('shifts').update(updates).eq('id', shiftId).select().single();
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.delete('/api/admin/shifts/:id', requireAdmin, async (req, res) => {
    try {
        const data = await archiveShiftAndNotify(req.params.id, 'archived');
        res.json({ success: true, message: 'Shift archived and notifications triggered.', shift: data });
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// PRODUCT CATEGORIES
app.post('/api/admin/product-categories', requireAdmin, async (req, res) => {
    try {
        const safeProductCategoryInfo = pickDefined(req.body || {}, [
            'event_id',
            'name',
        ]);
        safeProductCategoryInfo.name = normalizeSingleLineText(safeProductCategoryInfo.name, 120);
        if (!safeProductCategoryInfo.event_id || !isNonEmptyString(safeProductCategoryInfo.name)) {
            return res.status(400).json({ error: 'Missing required product category information.' });
        }
        const { data, error } = await supabase.from('product_categories').insert([safeProductCategoryInfo]).select().single();
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.put('/api/admin/product-categories/:id', requireAdmin, async (req, res) => {
    try {
        const safeProductCategoryInfo = pickDefined(req.body || {}, [
            'name',
        ]);
        if (safeProductCategoryInfo.name !== undefined) {
            safeProductCategoryInfo.name = normalizeSingleLineText(safeProductCategoryInfo.name, 120);
        }
        if (Object.keys(safeProductCategoryInfo).length === 0 || !isNonEmptyString(safeProductCategoryInfo.name)) {
            return res.status(400).json({ error: 'No valid product category fields provided.' });
        }
        const { data, error } = await supabase
            .from('product_categories')
            .update(safeProductCategoryInfo)
            .eq('id', req.params.id)
            .select()
            .single();
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.delete('/api/admin/product-categories/:id', requireAdmin, async (req, res) => {
    try {
        const { data: categoryProducts, error: categoryProductsError } = await supabase
            .from('products')
            .select('id')
            .eq('category_id', req.params.id);
        if (categoryProductsError)
            throw categoryProductsError;
        const productIds = (categoryProducts || []).map((product) => product.id);
        if (productIds.length > 0) {
            const { error: bookingProductsError } = await supabase
                .from('booking_products')
                .delete()
                .in('product_id', productIds);
            if (bookingProductsError)
                throw bookingProductsError;
        }
        const { error: productDeleteError } = await supabase.from('products').delete().eq('category_id', req.params.id);
        if (productDeleteError)
            throw productDeleteError;
        const { error } = await supabase.from('product_categories').delete().eq('id', req.params.id);
        if (error)
            throw error;
        res.json({ success: true });
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// PRODUCTS
app.post('/api/admin/products', requireAdmin, async (req, res) => {
    try {
        const safeProductInfo = pickDefined(req.body || {}, [
            'category_id',
            'title',
            'description',
            'price',
            'image_url',
            'amount',
        ]);
        safeProductInfo.title = normalizeSingleLineText(safeProductInfo.title, 160);
        if (safeProductInfo.description !== undefined) {
            safeProductInfo.description = normalizeMultilineText(safeProductInfo.description, 1000) || null;
        }
        if (safeProductInfo.image_url !== undefined) {
            safeProductInfo.image_url = normalizeSingleLineText(safeProductInfo.image_url, 2000) || null;
        }
        if (safeProductInfo.price !== undefined) {
            safeProductInfo.price = Number.isFinite(Number(safeProductInfo.price)) ? Number(safeProductInfo.price) : 0;
        }
        if (!safeProductInfo.category_id || !isNonEmptyString(safeProductInfo.title)) {
            return res.status(400).json({ error: 'Missing required product information.' });
        }
        const { data, error } = await supabase.from('products').insert([safeProductInfo]).select().single();
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.put('/api/admin/products/:id', requireAdmin, async (req, res) => {
    try {
        const safeProductInfo = pickDefined(req.body || {}, [
            'category_id',
            'title',
            'description',
            'price',
            'image_url',
            'amount',
        ]);
        if (safeProductInfo.title !== undefined) {
            safeProductInfo.title = normalizeSingleLineText(safeProductInfo.title, 160);
        }
        if (safeProductInfo.description !== undefined) {
            safeProductInfo.description = normalizeMultilineText(safeProductInfo.description, 1000) || null;
        }
        if (safeProductInfo.image_url !== undefined) {
            safeProductInfo.image_url = normalizeSingleLineText(safeProductInfo.image_url, 2000) || null;
        }
        if (safeProductInfo.price !== undefined) {
            safeProductInfo.price = Number.isFinite(Number(safeProductInfo.price)) ? Number(safeProductInfo.price) : 0;
        }
        if (Object.keys(safeProductInfo).length === 0) {
            return res.status(400).json({ error: 'No valid product fields provided.' });
        }
        if (safeProductInfo.title !== undefined && !isNonEmptyString(safeProductInfo.title)) {
            return res.status(400).json({ error: 'Product title is required.' });
        }
        const { data, error } = await supabase.from('products').update(safeProductInfo).eq('id', req.params.id).select().single();
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.delete('/api/admin/products/:id', requireAdmin, async (req, res) => {
    try {
        await supabase.from('booking_products').delete().eq('product_id', req.params.id);
        const { error } = await supabase.from('products').delete().eq('id', req.params.id);
        if (error)
            throw error;
        res.json({ success: true });
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// REVIEWS
app.get('/api/admin/reviews', requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase.from('reviews').select('*').order('created_at', { ascending: false });
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.get('/api/reviews/visible', async (req, res) => {
    try {
        const { data, error } = await supabase.from('reviews').select('*').eq('status', 'visible').order('created_at', { ascending: false });
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/reviews', async (req, res) => {
    const safeReview = {
        name: normalizeSingleLineText(req.body?.name, 120),
        email: normalizeEmail(req.body?.email),
        start: Number(req.body?.start),
        review: normalizeMultilineText(req.body?.review, 2000),
        status: 'pending',
    };
    if (!isNonEmptyString(safeReview.name) || !EMAIL_REGEX.test(safeReview.email) || !Number.isInteger(safeReview.start) || safeReview.start < 1 || safeReview.start > 5 || !isNonEmptyString(safeReview.review)) {
        return res.status(400).json({ error: 'Invalid review payload.' });
    }
    try {
        const { data, error } = await supabase.from('reviews').insert([safeReview]).select().single();
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        console.error('Review submission error:', error);
        res.status(500).json({ error: 'Failed to submit review. Please try again later.' });
    }
});
app.patch('/api/admin/reviews/:id/status', requireAdmin, async (req, res) => {
    const allowedStatuses = new Set(['pending', 'invisible', 'visible']);
    if (!allowedStatuses.has(req.body?.status)) {
        return res.status(400).json({ error: 'Invalid review status.' });
    }
    try {
        const { error } = await supabase.from('reviews').update({ status: req.body.status }).eq('id', req.params.id);
        if (error)
            throw error;
        res.json({ success: true });
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// PEOPLE
app.get('/api/people', async (req, res) => {
    try {
        const { data, error } = await supabase.from('people').select('*').order('created_at', { ascending: true });
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/admin/people', requireAdmin, async (req, res) => {
    try {
        const safePersonInfo = pickDefined(req.body || {}, [
            'name',
            'description',
            'photo_link',
        ]);
        if (!isNonEmptyString(safePersonInfo.name) || !isNonEmptyString(safePersonInfo.description)) {
            return res.status(400).json({ error: 'Missing required person information.' });
        }
        const { data, error } = await supabase.from('people').insert([safePersonInfo]).select().single();
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.put('/api/admin/people/:id', requireAdmin, async (req, res) => {
    try {
        const safePersonInfo = pickDefined(req.body || {}, [
            'name',
            'description',
            'photo_link',
        ]);
        if (Object.keys(safePersonInfo).length === 0) {
            return res.status(400).json({ error: 'No valid person fields provided.' });
        }
        const { data, error } = await supabase.from('people').update(safePersonInfo).eq('id', req.params.id).select().single();
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.delete('/api/admin/people/:id', requireAdmin, async (req, res) => {
    try {
        const { error } = await supabase.from('people').delete().eq('id', req.params.id);
        if (error)
            throw error;
        res.json({ success: true });
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// EMAIL TEMPLATES
app.get('/api/admin/email-logs', requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('email_logs')
            .select('*')
            .order('created_at', { ascending: false });
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.get('/api/admin/email-templates', requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase.from('email_templates').select('*').order('created_at', { ascending: false });
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/admin/email-templates', requireAdmin, async (req, res) => {
    const safeTemplate = pickDefined(req.body || {}, EMAIL_TEMPLATE_FIELDS);
    if (!isNonEmptyString(safeTemplate.subject_eng) ||
        !isNonEmptyString(safeTemplate.body_eng) ||
        !isNonEmptyString(safeTemplate.subject_el) ||
        !isNonEmptyString(safeTemplate.body_el)) {
        return res.status(400).json({ error: 'English and Greek subject/body fields are required.' });
    }
    try {
        const { data, error } = await supabase.from('email_templates').insert([safeTemplate]).select().single();
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.put('/api/admin/email-templates/:id', requireAdmin, async (req, res) => {
    const safeTemplate = pickDefined(req.body || {}, EMAIL_TEMPLATE_FIELDS);
    if (Object.keys(safeTemplate).length === 0) {
        return res.status(400).json({ error: 'No valid template fields provided.' });
    }
    const hasInvalidField = Object.values(safeTemplate).some((value) => !isNonEmptyString(value));
    if (hasInvalidField) {
        return res.status(400).json({ error: 'Template fields cannot be empty.' });
    }
    try {
        const { data, error } = await supabase.from('email_templates').update(safeTemplate).eq('id', req.params.id).select().single();
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.delete('/api/admin/email-templates/:id', requireAdmin, async (req, res) => {
    try {
        const templateId = req.params.id;
        const { error: logError } = await supabase
            .from('email_logs')
            .update({ template_id: null })
            .eq('template_id', templateId);
        if (logError) {
            throw logError;
        }
        const { error: purposeError } = await supabase
            .from('email_purposes')
            .update({ template_id: null })
            .eq('template_id', templateId);
        if (purposeError) {
            throw purposeError;
        }
        const { error } = await supabase.from('email_templates').delete().eq('id', templateId);
        if (error)
            throw error;
        res.json({ success: true });
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// EMAIL PURPOSES
app.get('/api/admin/email-purposes', requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase.from('email_purposes').select('*');
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.put('/api/admin/email-purposes', requireAdmin, async (req, res) => {
    const purpose = req.body?.purpose ?? req.body?.purposeId;
    const templateId = req.body?.templateId ?? null;
    if (!isNonEmptyString(purpose)) {
        return res.status(400).json({ error: 'Purpose is required.' });
    }
    try {
        console.log(`Updating purpose ${purpose} with template ${templateId}`);
        // Upsert by purpose (we assume purpose is a column in email_purposes)
        const { data, error } = await supabase
            .from('email_purposes')
            .upsert({ purpose, template_id: templateId }, { onConflict: 'purpose' })
            .select()
            .single();
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        console.error('Purpose update error:', error.message);
        res.status(500).json({ error: error.message });
    }
});
// EMAIL MANUAL
app.post('/api/admin/send-email', requireAdmin, async (req, res) => {
    const { to, subject, body } = req.body;
    if (!process.env.RESEND_API_KEY) {
        return res.status(500).json({ error: 'Resend API key missing' });
    }
    try {
        await resend.emails.send({
            from: process.env.EMAIL_FROM || 'info@weekplore.gr',
            to,
            subject,
            text: body,
            html: body.replace(/\n/g, '<br>'),
        });
        res.json({ success: true });
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// --- GLOBAL ERROR HANDLER ---
app.use((err, req, res, next) => {
    console.error('SERVER ERROR:', err.message);
    if (err.stack)
        console.error(err.stack);
    // Check if it's a CORS error
    if (err.message === 'Origin not allowed by CORS') {
        return res.status(403).json({ error: 'Origin not allowed by CORS policy' });
    }
    res.status(500).json({
        error: 'Internal Server Error',
        details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
