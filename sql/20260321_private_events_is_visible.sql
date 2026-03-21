-- Allow private event templates to be hidden from the public site
-- without deleting them or their inquiry history.

alter table public.private_events
add column if not exists is_visible boolean;

update public.private_events
set is_visible = true
where is_visible is null;

alter table public.private_events
alter column is_visible set default true;

alter table public.private_events
alter column is_visible set not null;
