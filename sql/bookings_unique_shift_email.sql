-- Enforce one booking per email per shift, regardless of email casing.
-- Run this against the production database after removing any existing duplicates.

create unique index if not exists bookings_unique_shift_email_idx
on public.bookings (shift_id, lower(email));
