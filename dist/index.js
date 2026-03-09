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
const adminEmailAllowlist = (process.env.ADMIN_EMAILS || '')
    .split(',')
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean);
const allowedCorsOrigins = (process.env.CORS_ALLOWED_ORIGINS || 'http://localhost:3000,http://127.0.0.1:3000,http://weekplore.gr,https://weekplore.gr,http://www.weekplore.gr,https://www.weekplore.gr')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
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
const SERVER_URL = process.env.SERVER_URL || `http://localhost:${process.env.PORT || 3001}`;
const generateCancelToken = (bookingId) => {
    return crypto.createHmac('sha256', CANCEL_SECRET).update(String(bookingId)).digest('hex');
};
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
    <h1>Are you sure, <span class="name">${bookingName.split(' ')[0]}?</span></h1>
    <p style="margin-top: 16px;">You are about to cancel your booking for</p>
    <p class="event">${eventTitle}</p>
    <div class="warning">This action is permanent and cannot be undone.</div>
    <form method="POST" action="/api/cancel-booking/${bookingId}?token=${token}">
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
    <h1>Done, ${bookingName.split(' ')[0]}.</h1>
    <p>Your booking for <span class="event">${eventTitle}</span> has been successfully cancelled.</p>
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
    <p>${message}</p>
  </div>
</body>
</html>
`;
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
        products(*)
      `)
            .eq('is_hidden', false)
            .order('event_date', { ascending: true });
        if (error)
            throw error;
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
        products(*)
      `)
            .eq('slug', req.params.slug)
            .eq('is_hidden', false)
            .single();
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// --- BOOKINGS ---
app.post('/api/bookings', async (req, res) => {
    const { eventId, formData } = req.body ?? {};
    const normalizedEventId = Number(eventId);
    const normalizedShiftId = Number(formData?.shiftId);
    const normalizedPeople = Number(formData?.numberOfPeople);
    const selectedProducts = Array.isArray(formData?.products) ? formData.products : [];
    // --- 1. SERVER-SIDE VALIDATION & CAPACITY CHECKS ---
    if (!Number.isInteger(normalizedEventId) ||
        normalizedEventId < 1 ||
        !formData ||
        !Number.isInteger(normalizedShiftId) ||
        normalizedShiftId < 1 ||
        !isNonEmptyString(formData.fullName) ||
        !isNonEmptyString(formData.email) ||
        !isNonEmptyString(formData.phone)) {
        return res.status(400).json({ error: 'Missing required booking information' });
    }
    if (!Number.isInteger(normalizedPeople) || normalizedPeople < 1) {
        return res.status(400).json({ error: 'Invalid number of people.' });
    }
    try {
        const { data: event, error: eventError } = await supabase
            .from('events')
            .select('id, is_hidden, is_sold_out, booking_deadline')
            .eq('id', normalizedEventId)
            .single();
        if (eventError || !event) {
            return res.status(404).json({ error: 'Experience not found.' });
        }
        if (event.is_hidden || event.is_sold_out) {
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
            .select('id, event_id, people_counter, capacity, is_active, is_full, start_time, is_confirmed')
            .eq('id', normalizedShiftId)
            .single();
        if (fetchShiftError || !shift) {
            return res.status(404).json({ error: 'Experience shift not found.' });
        }
        if (shift.event_id !== normalizedEventId) {
            return res.status(400).json({ error: 'Shift does not belong to this experience.' });
        }
        if (!shift.is_active) {
            return res.status(400).json({ error: 'This shift is not active.' });
        }
        if (shift.is_full) {
            return res.status(400).json({ error: 'This shift is already full.' });
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
        // Verify products if any requested
        if (selectedProducts.length > 0) {
            const hasInvalidProductPayload = selectedProducts.some((product) => !product ||
                !isNonEmptyString(product.product_id) ||
                !Number.isInteger(product.quantity) ||
                product.quantity < 1);
            if (hasInvalidProductPayload) {
                return res.status(400).json({ error: 'Invalid product selection.' });
            }
            const totalProductQuantity = selectedProducts.reduce((sum, product) => sum + product.quantity, 0);
            if (totalProductQuantity !== normalizedPeople) {
                return res.status(400).json({ error: 'Product quantities must match the number of people.' });
            }
            const productIds = [...new Set(selectedProducts.map((product) => product.product_id))];
            const { data: validProducts, error: prodErr } = await supabase
                .from('products')
                .select('id')
                .in('id', productIds)
                .eq('event_id', normalizedEventId);
            if (prodErr)
                throw prodErr;
            if ((validProducts || []).length !== productIds.length) {
                return res.status(400).json({ error: 'Invalid product selected.' });
            }
        }
        // --- 2. Insert booking into Supabase ---
        const { data: booking, error: bookingError } = await supabase
            .from('bookings')
            .insert([
            {
                event_id: normalizedEventId,
                shift_id: normalizedShiftId,
                full_name: formData.fullName.trim(),
                email: formData.email.trim(),
                phone: formData.phone.trim(),
                number_of_people: normalizedPeople,
                payment_status: 'pending'
            }
        ])
            .select()
            .single();
        if (bookingError)
            throw bookingError;
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
            if (productsError)
                throw productsError;
        }
        // --- 4. Email Logic (Run asynchronously so it doesn't block the response) ---
        if (process.env.RESEND_API_KEY) {
            (async () => {
                try {
                    // Fetch Templates from mappings
                    const { data: purposeData } = await supabase
                        .from('email_purposes')
                        .select('purpose, template_id, email_templates(*)')
                        .in('purpose', ['interest_received', 'payment_invitation', 'confirmed_shift_booking']);
                    const interestReceivedMapping = purposeData?.find(p => p.purpose === 'interest_received');
                    const paymentInvitationMapping = purposeData?.find(p => p.purpose === 'payment_invitation');
                    const confirmedShiftMapping = purposeData?.find(p => p.purpose === 'confirmed_shift_booking');
                    const interestReceivedTemplate = interestReceivedMapping?.email_templates;
                    const paymentInvitationTemplate = paymentInvitationMapping?.email_templates;
                    const confirmedShiftTemplate = confirmedShiftMapping?.email_templates;
                    // Fetch Event and Shift Data
                    const { data: event } = await supabase
                        .from('events')
                        .select('id, title, location_name')
                        .eq('id', eventId)
                        .single();
                    const dateStr = shift ? new Date(shift.start_time).toLocaleString('en-GB', {
                        dateStyle: 'full',
                        timeStyle: 'short'
                    }) : 'TBD';
                    // Snippet formatter (includes cancel_url for all booking emails)
                    const formatEmail = (text, recipientName, bookingId) => {
                        const cancelToken = generateCancelToken(bookingId);
                        const cancelUrl = `${SERVER_URL}/api/cancel-booking/${bookingId}?token=${cancelToken}`;
                        return text
                            .replace(/{name}/g, recipientName)
                            .replace(/{event}/g, event?.title || 'Experience')
                            .replace(/{date}/g, dateStr)
                            .replace(/{location}/g, event?.location_name || 'TBD')
                            .replace(/{people}/g, formData.numberOfPeople.toString())
                            .replace(/{cancel_url}/g, cancelUrl);
                    };
                    // --- CALCULATE CURRENT TOTALS FOR EMAIL TRIGGER ---
                    const { data: allShiftBookings } = await supabase
                        .from('bookings')
                        .select('id, number_of_people, email, full_name')
                        .eq('shift_id', formData.shiftId);
                    const emailTotalPeople = allShiftBookings?.reduce((sum, b) => sum + (b.number_of_people || 0), 0) || 0;
                    const isGoalMetNow = shift && shift.people_counter > 0 && emailTotalPeople >= shift.people_counter;
                    // --- SEND TO THE NEW BOOKER ---
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
                    if (templateToUse) {
                        const body = formatEmail(templateToUse.body, formData.fullName, booking.id);
                        const subject = formatEmail(templateToUse.subject, formData.fullName, booking.id);
                        try {
                            const { error: sendError } = await resend.emails.send({
                                from: process.env.EMAIL_FROM || 'info@weekplore.gr',
                                to: formData.email,
                                subject: subject,
                                text: body,
                                html: body.replace(/\n/g, '<br>'),
                            });
                            if (sendError)
                                throw sendError;
                            await supabase.from('email_logs').insert([{
                                    booking_id: booking.id,
                                    shift_id: formData.shiftId,
                                    event_id: eventId,
                                    recipient_email: formData.email,
                                    email_purpose: purposeToUse,
                                    status: 'sent',
                                    template_id: templateToUse.id
                                }]);
                        }
                        catch (err) {
                            console.error(`Failed to send ${purposeToUse} email:`, err.message);
                            await supabase.from('email_logs').insert([{
                                    booking_id: booking.id,
                                    shift_id: formData.shiftId,
                                    event_id: eventId,
                                    recipient_email: formData.email,
                                    email_purpose: purposeToUse,
                                    status: 'failed',
                                    template_id: templateToUse.id,
                                    error_message: err.message
                                }]);
                        }
                    }
                    // --- 6. CHECK THRESHOLD FOR BULK EMAIL ---
                    console.log(`Checking threshold: emailTotalPeople=${emailTotalPeople}, people_counter=${shift?.people_counter}, is_confirmed=${shift?.is_confirmed}`);
                    if (isGoalMetNow && shift && !shift.is_confirmed) {
                        console.log(`Threshold MET for shift ${formData.shiftId}. Updating shift and sending bulk emails.`);
                        if (paymentInvitationTemplate && allShiftBookings) {
                            // Mark as confirmed in DB
                            const { error: updateError } = await supabase
                                .from('shifts')
                                .update({ is_confirmed: true })
                                .eq('id', formData.shiftId);
                            if (updateError) {
                                console.error('FAILED TO UPDATE SHIFT STATUS:', updateError.message);
                            }
                            else {
                                console.log('Shift status updated to is_confirmed=true successfully.');
                            }
                            // Send personalized emails to everyone who was ALREADY booked
                            // (Exclude the new booking, as they just received the Confirmation template)
                            const previousBookings = allShiftBookings.filter(b => b.id !== booking.id);
                            for (const b of previousBookings) {
                                const sub = formatEmail(paymentInvitationTemplate.subject, b.full_name, b.id);
                                const msg = formatEmail(paymentInvitationTemplate.body, b.full_name, b.id);
                                try {
                                    await resend.emails.send({
                                        from: process.env.EMAIL_FROM || 'info@weekplore.gr',
                                        to: b.email,
                                        subject: sub,
                                        text: msg,
                                        html: msg.replace(/\n/g, '<br>'),
                                    });
                                    await supabase.from('email_logs').insert([{
                                            booking_id: b.id,
                                            shift_id: formData.shiftId,
                                            event_id: eventId,
                                            recipient_email: b.email,
                                            email_purpose: 'payment_invitation',
                                            status: 'sent',
                                            template_id: paymentInvitationTemplate.id
                                        }]);
                                }
                                catch (err) {
                                    console.error(`Bulk send failed for ${b.email}:`, err.message);
                                }
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
        res.status(500).json({ error: error.message });
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
        products(*)
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
    const { eventData, imageUrls, shifts, products } = req.body;
    try {
        const safeImageUrls = Array.isArray(imageUrls) ? imageUrls.filter(isNonEmptyString) : [];
        const safeShifts = Array.isArray(shifts) ? shifts : [];
        const safeProducts = Array.isArray(products) ? products : [];
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
            }));
            await supabase.from('shifts').insert(shiftRecords);
        }
        if (safeProducts.length > 0) {
            const productRecords = safeProducts.map((p) => ({
                event_id: event.id,
                title: p.title,
                description: p.description,
                price: p.price,
                image_url: p.image_url || null
            }));
            await supabase.from('products').insert(productRecords);
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
            'base_price',
            'tag',
            'cover_image_url',
        ]);
        if (Object.keys(safeEventData).length === 0) {
            return res.status(400).json({ error: 'No valid event fields provided.' });
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
    const eventId = req.params.id;
    try {
        await supabase.from('event_images').delete().eq('event_id', eventId);
        const { data: shifts } = await supabase.from('shifts').select('id').eq('event_id', eventId);
        if (shifts && shifts.length > 0) {
            const shiftIds = shifts.map(s => s.id);
            const { data: bookings } = await supabase.from('bookings').select('id').in('shift_id', shiftIds);
            if (bookings && bookings.length > 0) {
                const bookingIds = bookings.map(b => b.id);
                await supabase.from('booking_products').delete().in('booking_id', bookingIds);
                await supabase.from('bookings').delete().in('id', bookingIds);
            }
            await supabase.from('shifts').delete().in('id', shiftIds);
        }
        await supabase.from('products').delete().eq('event_id', eventId);
        const { error } = await supabase.from('events').delete().eq('id', eventId);
        if (error)
            throw error;
        res.json({ success: true });
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
            ]),
            end_time: req.body?.end_time || null,
            capacity: req.body?.capacity ?? 999,
            people_counter: req.body?.people_counter || 0,
            is_confirmed: Boolean(req.body?.is_confirmed),
            is_full: Boolean(req.body?.is_full),
            is_active: req.body?.is_active ?? true,
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
        const safeShiftData = pickDefined(req.body || {}, [
            'start_time',
            'end_time',
            'capacity',
            'people_counter',
            'is_confirmed',
            'is_full',
            'is_active',
        ]);
        if (Object.keys(safeShiftData).length === 0) {
            return res.status(400).json({ error: 'No valid shift fields provided.' });
        }
        const { data, error } = await supabase.from('shifts').update(safeShiftData).eq('id', req.params.id).select().single();
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
        const shiftId = req.params.id;
        const { data: bookings } = await supabase.from('bookings').select('id').eq('shift_id', shiftId);
        if (bookings && bookings.length > 0) {
            const bookingIds = bookings.map(b => b.id);
            await supabase.from('booking_products').delete().in('booking_id', bookingIds);
            await supabase.from('bookings').delete().in('id', bookingIds);
        }
        const { error } = await supabase.from('shifts').delete().eq('id', shiftId);
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
            'event_id',
            'title',
            'description',
            'price',
            'image_url',
            'amount',
        ]);
        if (!safeProductInfo.event_id || !isNonEmptyString(safeProductInfo.title)) {
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
            'title',
            'description',
            'price',
            'image_url',
            'amount',
        ]);
        if (Object.keys(safeProductInfo).length === 0) {
            return res.status(400).json({ error: 'No valid product fields provided.' });
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
        email: req.body?.email,
        start: req.body?.start,
        review: req.body?.review,
        status: 'pending',
    };
    if (!isNonEmptyString(safeReview.email) || !Number.isInteger(safeReview.start) || safeReview.start < 1 || safeReview.start > 5 || !isNonEmptyString(safeReview.review)) {
        return res.status(400).json({ error: 'Invalid review payload.' });
    }
    try {
        const { data, error } = await supabase.from('reviews').insert([safeReview]).select().single();
        if (error)
            throw error;
        res.json(data);
    }
    catch (error) {
        res.status(500).json({ error: error.message });
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
    const safeTemplate = pickDefined(req.body || {}, ['subject', 'body']);
    if (!isNonEmptyString(safeTemplate.subject) || !isNonEmptyString(safeTemplate.body)) {
        return res.status(400).json({ error: 'Template subject and body are required.' });
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
    const safeTemplate = pickDefined(req.body || {}, ['subject', 'body']);
    if (Object.keys(safeTemplate).length === 0) {
        return res.status(400).json({ error: 'No valid template fields provided.' });
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
        const { error } = await supabase.from('email_templates').delete().eq('id', req.params.id);
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
