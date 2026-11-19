-- Postal codes are stored as text because they are identifiers, not quantities.
-- Validation and space normalization are handled by the booking API.

alter table public.bookings
add column if not exists postal_code text;
