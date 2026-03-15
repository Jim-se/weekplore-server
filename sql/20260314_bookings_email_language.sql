-- Store the browser-derived email language on each booking so follow-up emails
-- like shift cancellations and payment invites stay localized.

alter table public.bookings
add column if not exists email_language text not null default 'en';

do $$
begin
    if not exists (
        select 1
        from pg_constraint
        where conname = 'bookings_email_language_check'
    ) then
        alter table public.bookings
        add constraint bookings_email_language_check
        check (email_language in ('en', 'el'));
    end if;
end
$$;
