-- Keep inquiry history when an admin removes a private event template.
-- Existing inquiries should stay visible, but their template reference
-- should be cleared automatically.

alter table public.private_event_inquiries
drop constraint if exists private_event_inquiries_private_event_template_id_fkey;

alter table public.private_event_inquiries
add constraint private_event_inquiries_private_event_template_id_fkey
foreign key (private_event_template_id)
references public.private_events (id)
on delete set null;
