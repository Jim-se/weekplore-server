-- Allow multiple bookings for the same shift to share the same email address.
-- Run this in Supabase after deploying the matching API changes.

drop index if exists public.bookings_unique_shift_email_idx;
