-- Lock down the legacy admins table.
-- This app handles admin authorization on the backend, so clients should not
-- be able to read or write rows from public.admins directly.

alter table public.admins enable row level security;

revoke all on table public.admins from anon, authenticated;

-- Intentionally no policies for anon/authenticated.
-- The backend uses privileged access where needed.
