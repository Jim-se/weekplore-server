-- Apply this in Supabase before scaling the API horizontally.
-- This script first removes duplicate bookings for the same shift + email,
-- then creates the case-insensitive unique index used by the API.
--
-- Preview duplicates first if you want to inspect what will be removed:
-- select
--   shift_id,
--   lower(email) as normalized_email,
--   count(*) as booking_count,
--   array_agg(id order by created_at asc nulls last, id asc) as booking_ids
-- from public.bookings
-- where shift_id is not null
--   and email is not null
-- group by shift_id, lower(email)
-- having count(*) > 1;

create temporary table tmp_duplicate_bookings_to_remove on commit drop as
with ranked_bookings as (
    select
        id,
        shift_id,
        lower(email) as normalized_email,
        payment_status,
        created_at,
        first_value(id) over (
            partition by shift_id, lower(email)
            order by
                case when payment_status = 'paid' then 0 else 1 end,
                created_at asc nulls last,
                id asc
        ) as keeper_id,
        row_number() over (
            partition by shift_id, lower(email)
            order by
                case when payment_status = 'paid' then 0 else 1 end,
                created_at asc nulls last,
                id asc
        ) as duplicate_rank
    from public.bookings
    where shift_id is not null
      and email is not null
)
select
    id as duplicate_id,
    keeper_id
from ranked_bookings
where duplicate_rank > 1;

-- Preserve historical email logs by pointing them at the surviving booking.
do $$
begin
    if to_regclass('public.email_logs') is not null then
        update public.email_logs as logs
        set booking_id = duplicates.keeper_id
        from tmp_duplicate_bookings_to_remove as duplicates
        where logs.booking_id = duplicates.duplicate_id;
    end if;
end
$$;

-- Remove products tied to the duplicate booking rows.
do $$
begin
    if to_regclass('public.booking_products') is not null then
        delete from public.booking_products
        where booking_id in (
            select duplicate_id
            from tmp_duplicate_bookings_to_remove
        );
    end if;
end
$$;

-- Remove the duplicate bookings themselves.
delete from public.bookings
where id in (
    select duplicate_id
    from tmp_duplicate_bookings_to_remove
);

create unique index if not exists bookings_unique_shift_email_idx
on public.bookings (shift_id, lower(email));
