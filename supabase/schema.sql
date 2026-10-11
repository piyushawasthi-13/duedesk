-- =====================================================================
-- DueDesk database — v2
-- Safe to run on a brand-new Supabase project AND on top of v1.
-- Safe to run more than once. Paste into Supabase → SQL Editor → Run.
-- =====================================================================
-- What v2 changes vs v1
--   * Dates use India time (IST), not UTC
--   * Missed months are back-filled automatically (v1 only billed "this" cycle)
--   * Rent changes keep history (old months keep old rent)
--   * Move-out prorates the last month and stops billing
--   * Due day 1–31 (29/30/31 fall on the month's last day in short months)
--   * Extra charges (electricity, food…) and waivers/discounts
--   * Security deposit can be adjusted against dues
--   * Multiple properties (limited by plan)
--   * Phone push alerts (daily 9 AM IST) + Razorpay subscription plumbing
--   * Tighter security: a member can only be added to your own property, etc.
-- v1 charges that already exist are kept exactly as they are (locked).
-- =====================================================================

create extension if not exists pgcrypto;

-- ---------- helpers ---------------------------------------------------
create or replace function today_ist() returns date
language sql stable as $$ select (now() at time zone 'Asia/Kolkata')::date $$;

-- The billing day inside a given month (31 → 30 in April, 28/29 in Feb)
create or replace function anchor_date(y int, m int, dd int) returns date
language sql immutable as $$
  select make_date(y, m, least(dd,
    extract(day from (make_date(y, m, 1) + interval '1 month - 1 day'))::int))
$$;

-- Start of the billing cycle that contains day d
create or replace function cycle_start_for(d date, dd int) returns date
language plpgsql immutable as $$
declare a date; p date;
begin
  a := anchor_date(extract(year from d)::int, extract(month from d)::int, dd);
  if a > d then
    p := (date_trunc('month', d) - interval '1 month')::date;
    a := anchor_date(extract(year from p)::int, extract(month from p)::int, dd);
  end if;
  return a;
end $$;

create or replace function next_anchor(c date, dd int) returns date
language sql immutable as $$
  select anchor_date(extract(year from (date_trunc('month', c) + interval '1 month'))::int,
                     extract(month from (date_trunc('month', c) + interval '1 month'))::int, dd)
$$;

-- ---------- plans -----------------------------------------------------
create table if not exists plans (
  id text primary key,
  name text not null,
  price_monthly int not null default 0,
  price_yearly int not null default 0,
  max_tenants int not null,
  max_properties int not null default 1,
  auto_messages boolean not null default false,
  razorpay_plan_monthly text,
  razorpay_plan_yearly text
);
insert into plans (id, name, price_monthly, price_yearly, max_tenants, max_properties, auto_messages) values
  ('trial',    'Free Trial', 0,   0,    5,      1,  false),
  ('basic',    'Basic',      199, 1990, 25,     1,  false),
  ('pro',      'Pro',        499, 4990, 100,    3,  true),
  ('business', 'Business',   999, 9990, 999999, 20, true)
on conflict (id) do nothing;

-- ---------- owners ----------------------------------------------------
create table if not exists owners (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  phone text,
  language text not null default 'en' check (language in ('en','hi')),
  push_token text,
  notify_in_app boolean not null default true,
  notify_sms boolean not null default true,
  notify_whatsapp boolean not null default true,
  plan_id text not null default 'trial' references plans(id),
  plan_status text not null default 'trialing'
    check (plan_status in ('trialing','active','past_due','cancelled','expired')),
  trial_ends_at timestamptz not null default (now() + interval '30 days'),
  plan_ends_at timestamptz,
  razorpay_customer_id text,
  razorpay_subscription_id text,
  created_at timestamptz not null default now()
);
alter table owners add column if not exists upi_id text;
alter table owners add column if not exists notify_push boolean not null default true;
alter table owners add column if not exists plan_cycle text;
alter table owners add column if not exists demo_pay boolean not null default true;

create or replace function handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into owners (id, phone) values (new.id, new.phone) on conflict do nothing;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function handle_new_user();

-- ---------- properties ------------------------------------------------
create table if not exists properties (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references owners(id) on delete cascade,
  name text not null,
  category text not null default 'pg' check (category in ('pg','library','gym','tuition','other')),
  created_at timestamptz not null default now()
);

-- ---------- tenants (members) -----------------------------------------
create table if not exists tenants (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references owners(id) on delete cascade,
  property_id uuid not null references properties(id) on delete cascade,
  name text not null,
  phone text,
  room text,
  rent_amount numeric(10,2) not null check (rent_amount >= 0),
  join_date date not null default current_date,
  due_day int not null default 1,
  security_deposit numeric(10,2) not null default 0,
  notify_enabled boolean not null default true,
  is_active boolean not null default true,
  left_date date,
  note text,
  created_at timestamptz not null default now()
);
alter table tenants add column if not exists billing_from date;
alter table tenants alter column join_date set default today_ist();
alter table tenants drop constraint if exists tenants_due_day_check;
alter table tenants add constraint tenants_due_day_check check (due_day between 1 and 31);
alter table tenants drop constraint if exists tenants_left_after_join;
alter table tenants add constraint tenants_left_after_join check (left_date is null or left_date >= join_date);
create index if not exists tenants_owner_idx on tenants(owner_id, is_active);

-- ---------- rent history ----------------------------------------------
create table if not exists rent_changes (
  tenant_id uuid not null references tenants(id) on delete cascade,
  owner_id uuid not null references owners(id) on delete cascade,
  effective_from date not null,
  amount numeric(10,2) not null check (amount >= 0),
  created_at timestamptz not null default now(),
  primary key (tenant_id, effective_from)
);

-- ---------- charges (what members owe) --------------------------------
create table if not exists charges (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references owners(id) on delete cascade,
  tenant_id uuid not null references tenants(id) on delete cascade,
  period_start date not null,
  period_end date not null,
  due_date date not null,
  days_charged int not null,
  amount numeric(10,2) not null,
  label text,
  created_at timestamptz not null default now()
);
alter table charges add column if not exists kind text not null default 'rent';
alter table charges add column if not exists locked boolean not null default false;
alter table charges drop constraint if exists charges_kind_check;
alter table charges add constraint charges_kind_check check (kind in ('rent','extra','waiver'));
alter table charges drop constraint if exists charges_amount_sign;
alter table charges add constraint charges_amount_sign
  check ((kind = 'waiver' and amount < 0) or (kind <> 'waiver' and amount >= 0));
alter table charges drop constraint if exists charges_tenant_id_period_start_key;
create unique index if not exists charges_rent_uniq on charges(tenant_id, period_start) where kind = 'rent';
create index if not exists charges_tenant_idx on charges(tenant_id, due_date);

-- ---------- payments --------------------------------------------------
create table if not exists payments (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references owners(id) on delete cascade,
  tenant_id uuid not null references tenants(id) on delete cascade,
  amount numeric(10,2) not null check (amount > 0),
  paid_on date not null default current_date,
  mode text not null default 'cash',
  note text,
  created_at timestamptz not null default now()
);
alter table payments alter column paid_on set default today_ist();
alter table payments drop constraint if exists payments_mode_check;
alter table payments add constraint payments_mode_check check (mode in ('cash','upi','bank','other','deposit','online'));
alter table payments add column if not exists source text not null default 'owner';
alter table payments add column if not exists ref text;
alter table payments drop constraint if exists payments_source_check;
alter table payments add constraint payments_source_check check (source in ('owner','online','upi'));
create unique index if not exists payments_online_ref on payments(ref) where source = 'online';
create index if not exists payments_tenant_idx on payments(tenant_id, paid_on);

-- ---------- misc ------------------------------------------------------
create table if not exists reminder_log (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references owners(id) on delete cascade,
  tenant_id uuid references tenants(id) on delete cascade,
  channel text not null,
  sent_on date not null default current_date,
  unique (owner_id, tenant_id, channel, sent_on)
);
create table if not exists subscription_events (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid references owners(id) on delete set null,
  event text not null,
  razorpay_payload jsonb,
  created_at timestamptz not null default now()
);
create table if not exists push_subscriptions (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references owners(id) on delete cascade,
  endpoint text not null unique,
  p256dh text not null,
  auth text not null,
  user_agent text,
  created_at timestamptz not null default now()
);

-- Server-only settings. The "private" schema is never exposed through the API.
create schema if not exists private;
revoke all on schema private from public;
create table if not exists private.config (
  id int primary key default 1 check (id = 1),
  project_url text not null,
  cron_secret text not null default (replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
  vapid_public text,
  vapid_private jsonb
);
-- >>> If you use a different Supabase project, change this URL <<<
insert into private.config (id, project_url) values (1, 'https://zxdeuotgjvbpoeptldnv.supabase.co')
on conflict (id) do nothing;
revoke all on private.config from public;

-- ---------- one-time upgrade of v1 data -------------------------------
-- Existing v1 charges are kept as-is; billing continues from the day after them.
update charges set locked = true
 where kind = 'rent' and not locked
   and exists (select 1 from tenants t where t.id = charges.tenant_id and t.billing_from is null);
update tenants t set billing_from = coalesce(
  (select max(c.period_end) + 1 from charges c where c.tenant_id = t.id and c.kind = 'rent'),
  t.join_date)
 where t.billing_from is null;
alter table tenants alter column billing_from set not null;

-- ---------- billing engine --------------------------------------------
-- Creates/updates rent charges for one member from billing_from up to `upto`.
-- full = true  → recompute every cycle and remove ones that no longer apply
-- full = false → only look at the last ~2 months (nightly job; idempotent)
create or replace function bill_tenant(tid uuid, upto date, p_full boolean default false) returns int
language plpgsql security definer set search_path = public as $$
declare
  t tenants; c_start date; c_end date; nx date; e_start date; e_end date;
  cyc int; used int; rate numeric; stop date; n int := 0; i int := 0; keep date[] := '{}';
begin
  select * into t from tenants where id = tid;
  if not found or t.billing_from is null or upto is null then return 0; end if;
  stop := case when t.left_date is null then upto else least(upto, t.left_date) end;
  c_start := cycle_start_for(case when p_full then t.billing_from
                                  else greatest(t.billing_from, upto - 70) end, t.due_day);
  loop
    nx := next_anchor(c_start, t.due_day);
    c_end := nx - 1;
    e_start := greatest(c_start, t.billing_from);
    exit when e_start > stop;
    i := i + 1;
    if i > 600 then raise exception 'BILLING_RANGE_TOO_LONG'; end if;  -- 50 years: safety stop
    e_end := case when t.left_date is null then c_end else least(c_end, t.left_date) end;
    if e_start <= e_end then
      cyc := c_end - c_start + 1;
      used := e_end - e_start + 1;
      rate := coalesce((select r.amount from rent_changes r
                         where r.tenant_id = tid and r.effective_from <= e_start
                         order by r.effective_from desc limit 1), t.rent_amount);
      insert into charges (owner_id, tenant_id, kind, period_start, period_end, due_date, days_charged, amount, label)
      values (t.owner_id, tid, 'rent', e_start, e_end, e_start, used, round(rate * used / cyc, 0),
              case when used < cyc then 'Rent · ' || used || ' days' else 'Monthly rent' end)
      on conflict (tenant_id, period_start) where kind = 'rent' do update
        set period_end = excluded.period_end, due_date = excluded.due_date,
            days_charged = excluded.days_charged, amount = excluded.amount, label = excluded.label
        where not charges.locked
          and (charges.period_end, charges.days_charged, charges.amount)
              is distinct from (excluded.period_end, excluded.days_charged, excluded.amount);
      keep := keep || e_start;
      n := n + 1;
    end if;
    c_start := nx;
  end loop;
  if p_full then
    delete from charges where tenant_id = tid and kind = 'rent' and not locked
      and not (period_start = any(keep));
  end if;
  if t.left_date is not null then
    delete from charges where tenant_id = tid and kind = 'rent' and not locked and period_start > t.left_date;
  end if;
  return n;
end $$;

-- Nightly job: closes finished move-outs and bills every member (catches up missed days)
create or replace function generate_charges(for_date date default today_ist()) returns int
language plpgsql security definer set search_path = public as $$
declare r record; made int := 0;
begin
  update tenants set is_active = false
   where is_active and left_date is not null and left_date < for_date;
  for r in select id from tenants
            where is_active or (left_date is not null and left_date >= for_date - 70) loop
    made := made + bill_tenant(r.id, for_date, false);
  end loop;
  return made;
end $$;

-- ---------- access & limits -------------------------------------------
create or replace function owner_has_access(oid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from owners o
    where o.id = oid and (
      (o.plan_status = 'trialing' and o.trial_ends_at > now()) or
      (o.plan_status = 'active' and (o.plan_ends_at is null or o.plan_ends_at > now() - interval '3 days')) or
      (o.plan_status in ('past_due','cancelled') and o.plan_ends_at > now() - interval '3 days')
    )
  );
$$;

create or replace function owner_plan_limit(oid uuid) returns int
language sql stable security definer set search_path = public as $$
  select p.max_tenants from owners o join plans p on p.id = o.plan_id where o.id = oid;
$$;

create or replace function enforce_property_limit() returns trigger
language plpgsql security definer set search_path = public as $$
declare cnt int; lim int;
begin
  select count(*) into cnt from properties where owner_id = new.owner_id;
  select p.max_properties into lim from owners o join plans p on p.id = o.plan_id where o.id = new.owner_id;
  if cnt >= coalesce(lim, 1) then raise exception 'PROPERTY_LIMIT_REACHED'; end if;
  return new;
end $$;
drop trigger if exists properties_limit on properties;
create trigger properties_limit before insert on properties
  for each row execute function enforce_property_limit();

-- ---------- member triggers -------------------------------------------
create or replace function tenants_before() returns trigger
language plpgsql security definer set search_path = public as $$
declare cnt int;
begin
  if not exists (select 1 from properties p where p.id = new.property_id and p.owner_id = new.owner_id) then
    raise exception 'BAD_PROPERTY';
  end if;
  if tg_op = 'INSERT' then
    new.billing_from := coalesce(new.billing_from, new.join_date);
  else
    if new.owner_id <> old.owner_id then raise exception 'NOT_ALLOWED'; end if;
    if new.join_date <> old.join_date then new.billing_from := new.join_date; end if;
    new.billing_from := coalesce(new.billing_from, old.billing_from, new.join_date);
    if not new.is_active and old.is_active and new.left_date is null then
      new.left_date := today_ist();
    end if;
    if new.is_active and not old.is_active then new.left_date := null; end if;
  end if;
  if new.is_active and (tg_op = 'INSERT' or not old.is_active) then
    if not owner_has_access(new.owner_id) then raise exception 'SUBSCRIPTION_EXPIRED'; end if;
    select count(*) into cnt from tenants
     where owner_id = new.owner_id and is_active and id <> new.id;
    if cnt >= owner_plan_limit(new.owner_id) then raise exception 'PLAN_LIMIT_REACHED'; end if;
  end if;
  return new;
end $$;

create or replace function tenants_after() returns trigger
language plpgsql security definer set search_path = public as $$
declare eff date;
begin
  if tg_op = 'INSERT' then
    insert into rent_changes (tenant_id, owner_id, effective_from, amount)
    values (new.id, new.owner_id, new.join_date, new.rent_amount) on conflict do nothing;
    perform bill_tenant(new.id, today_ist(), true);
    return null;
  end if;
  if new.rent_amount <> old.rent_amount then
    -- make sure the old rent is on record for older months
    insert into rent_changes (tenant_id, owner_id, effective_from, amount)
    values (new.id, new.owner_id, least(old.join_date, old.billing_from), old.rent_amount)
    on conflict do nothing;
    eff := coalesce(nullif(current_setting('duedesk.rent_from', true), '')::date,
                    cycle_start_for(today_ist(), new.due_day));
    insert into rent_changes (tenant_id, owner_id, effective_from, amount)
    values (new.id, new.owner_id, eff, new.rent_amount)
    on conflict (tenant_id, effective_from) do update set amount = excluded.amount;
  end if;
  if new.join_date <> old.join_date then
    delete from charges where tenant_id = new.id and kind = 'rent';  -- re-bill from the new date
  end if;
  if (new.join_date, new.due_day, new.rent_amount, new.left_date, new.is_active, new.billing_from)
     is distinct from (old.join_date, old.due_day, old.rent_amount, old.left_date, old.is_active, old.billing_from) then
    perform bill_tenant(new.id, today_ist(), true);
  end if;
  return null;
end $$;

drop trigger if exists tenants_limit on tenants;
drop trigger if exists tenants_first_charge on tenants;
drop function if exists first_charge_on_tenant();
drop function if exists enforce_tenant_limit();
drop trigger if exists tenants_before_trg on tenants;
create trigger tenants_before_trg before insert or update on tenants
  for each row execute function tenants_before();
drop trigger if exists tenants_after_trg on tenants;
create trigger tenants_after_trg after insert or update on tenants
  for each row execute function tenants_after();

-- Deposit adjustments can't exceed the deposit held
create or replace function payments_before() returns trigger
language plpgsql security definer set search_path = public as $$
declare dep numeric; used numeric;
begin
  if not exists (select 1 from tenants t where t.id = new.tenant_id and t.owner_id = new.owner_id) then
    raise exception 'BAD_TENANT';
  end if;
  if new.mode = 'deposit' then
    select security_deposit into dep from tenants where id = new.tenant_id;
    select coalesce(sum(amount), 0) into used from payments
     where tenant_id = new.tenant_id and mode = 'deposit' and id <> new.id;
    if used + new.amount > dep then raise exception 'DEPOSIT_EXCEEDED'; end if;
  end if;
  return new;
end $$;
drop trigger if exists payments_before_trg on payments;
create trigger payments_before_trg before insert or update on payments
  for each row execute function payments_before();

-- ---------- balances view ---------------------------------------------
drop view if exists tenant_balances;
create view tenant_balances with (security_invoker = true) as
select
  t.id as tenant_id, t.owner_id, t.property_id, t.name, t.phone, t.room, t.rent_amount, t.due_day,
  t.join_date, t.left_date, t.is_active, t.notify_enabled, t.note, t.security_deposit,
  coalesce(p.deposit_used, 0) as deposit_used,
  coalesce(c.total_charged, 0) as total_charged,
  coalesce(p.total_paid, 0) as total_paid,
  coalesce(c.total_charged, 0) - coalesce(p.total_paid, 0) as balance,
  coalesce(c.due_now, 0) - coalesce(p.total_paid, 0) as due_now
from tenants t
left join (select tenant_id, sum(amount) total_charged,
                  sum(amount) filter (where due_date <= today_ist()) due_now
             from charges group by tenant_id) c on c.tenant_id = t.id
left join (select tenant_id, sum(amount) total_paid,
                  sum(amount) filter (where mode = 'deposit') deposit_used
             from payments group by tenant_id) p on p.tenant_id = t.id;

-- ---------- app RPCs (called from the app, checked against the caller) --
create or replace function change_rent(p_tenant uuid, p_amount numeric, p_from date) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from tenants where id = p_tenant and owner_id = auth.uid()) then
    raise exception 'NOT_ALLOWED';
  end if;
  if p_amount is null or p_amount < 0 then raise exception 'BAD_AMOUNT'; end if;
  perform set_config('duedesk.rent_from', p_from::text, true);
  if exists (select 1 from tenants where id = p_tenant and rent_amount = p_amount) then
    insert into rent_changes (tenant_id, owner_id, effective_from, amount)
    values (p_tenant, auth.uid(), p_from, p_amount)
    on conflict (tenant_id, effective_from) do update set amount = excluded.amount;
    perform bill_tenant(p_tenant, today_ist(), true);
  else
    update tenants set rent_amount = p_amount where id = p_tenant;
  end if;
  perform set_config('duedesk.rent_from', '', true);
end $$;

create or replace function add_adjustment(p_tenant uuid, p_kind text, p_amount numeric, p_date date, p_label text)
returns uuid language plpgsql security definer set search_path = public as $$
declare new_id uuid;
begin
  if not exists (select 1 from tenants where id = p_tenant and owner_id = auth.uid()) then
    raise exception 'NOT_ALLOWED';
  end if;
  if not owner_has_access(auth.uid()) then raise exception 'SUBSCRIPTION_EXPIRED'; end if;
  if p_kind not in ('extra','waiver') or p_amount is null or p_amount <= 0 then raise exception 'BAD_AMOUNT'; end if;
  insert into charges (owner_id, tenant_id, kind, period_start, period_end, due_date, days_charged, amount, label)
  values (auth.uid(), p_tenant, p_kind, p_date, p_date, p_date, 0,
          case when p_kind = 'waiver' then -p_amount else p_amount end,
          nullif(trim(coalesce(p_label, '')), ''))
  returning id into new_id;
  return new_id;
end $$;

create or replace function delete_adjustment(p_charge uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  delete from charges where id = p_charge and owner_id = auth.uid() and kind in ('extra','waiver');
  if not found then raise exception 'NOT_ALLOWED'; end if;
end $$;

create or replace function get_vapid_public() returns text
language sql stable security definer set search_path = public as $$
  select vapid_public from private.config where id = 1
$$;

-- ---------- server-only RPCs (edge function, service role) ------------
create or replace function svc_check_cron(p_secret text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from private.config where id = 1 and cron_secret = p_secret)
$$;

create or replace function svc_get_vapid() returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object('public', vapid_public, 'private', vapid_private) from private.config where id = 1
$$;

create or replace function svc_set_vapid(p_public text, p_private jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  update private.config set vapid_public = p_public, vapid_private = p_private
   where id = 1 and vapid_public is null;
  return svc_get_vapid();
end $$;

-- One row per owner who should get today's alert
create or replace function svc_due_digest() returns table (
  owner_id uuid, language text, members int, amount numeric, names text)
language sql stable security definer set search_path = public as $$
  select o.id, o.language, count(*)::int, sum(b.due_now),
         string_agg(b.name, ', ' order by b.due_now desc)
    from owners o
    join tenant_balances b on b.owner_id = o.id
   where o.notify_push and b.due_now > 0 and b.notify_enabled
     and exists (select 1 from push_subscriptions s where s.owner_id = o.id)
   group by o.id, o.language
$$;

create or replace function svc_push_targets(p_owner uuid) returns setof push_subscriptions
language sql stable security definer set search_path = public as $$
  select * from push_subscriptions where owner_id = p_owner
$$;

create or replace function svc_drop_push(p_endpoint text) returns void
language sql security definer set search_path = public as $$
  delete from push_subscriptions where endpoint = p_endpoint
$$;

create or replace function svc_plan_for(p_plan text) returns plans
language sql stable security definer set search_path = public as $$
  select * from plans where id = p_plan
$$;

create or replace function svc_apply_subscription(
  p_owner uuid, p_plan text, p_status text, p_ends timestamptz, p_sub text, p_cycle text, p_event text, p_payload jsonb)
returns void language plpgsql security definer set search_path = public as $$
begin
  insert into subscription_events (owner_id, event, razorpay_payload) values (p_owner, p_event, p_payload);
  if p_owner is null then return; end if;
  update owners set
    plan_id = coalesce(p_plan, plan_id),
    plan_status = coalesce(p_status, plan_status),
    plan_ends_at = coalesce(p_ends, plan_ends_at),
    plan_cycle = coalesce(p_cycle, plan_cycle),
    razorpay_subscription_id = coalesce(p_sub, razorpay_subscription_id)
  where id = p_owner;
end $$;

-- ---------- security --------------------------------------------------
alter table owners enable row level security;
alter table properties enable row level security;
alter table tenants enable row level security;
alter table charges enable row level security;
alter table payments enable row level security;
alter table reminder_log enable row level security;
alter table subscription_events enable row level security;
alter table plans enable row level security;
alter table rent_changes enable row level security;
alter table push_subscriptions enable row level security;

drop policy if exists "plans readable" on plans;
drop policy if exists "owner reads self" on owners;
drop policy if exists "owner updates self" on owners;
drop policy if exists "own properties" on properties;
drop policy if exists "own tenants" on tenants;
drop policy if exists "own charges read" on charges;
drop policy if exists "own payments" on payments;
drop policy if exists "own reminder log" on reminder_log;
drop policy if exists "own rent changes" on rent_changes;
drop policy if exists "own push subs" on push_subscriptions;

create policy "plans readable" on plans for select using (true);
create policy "owner reads self" on owners for select using (id = auth.uid());
create policy "owner updates self" on owners for update using (id = auth.uid()) with check (id = auth.uid());
create policy "own properties" on properties for all using (owner_id = auth.uid()) with check (owner_id = auth.uid());
create policy "own tenants" on tenants for all using (owner_id = auth.uid()) with check (owner_id = auth.uid());
create policy "own charges read" on charges for select using (owner_id = auth.uid());
create policy "own payments" on payments for all using (owner_id = auth.uid())
  with check (owner_id = auth.uid() and owner_has_access(auth.uid()));
create policy "own reminder log" on reminder_log for select using (owner_id = auth.uid());
create policy "own rent changes" on rent_changes for select using (owner_id = auth.uid());
create policy "own push subs" on push_subscriptions for all using (owner_id = auth.uid()) with check (owner_id = auth.uid());

revoke update on owners from authenticated;
grant update (full_name, phone, language, push_token, notify_in_app, notify_sms, notify_whatsapp,
              notify_push, upi_id) on owners to authenticated;
revoke insert, update, delete on charges, rent_changes, subscription_events, plans from anon, authenticated;
revoke all on tenant_balances from anon;

-- server-side functions: nobody but the server may call them
do $$
declare f text;
begin
  foreach f in array array[
    'generate_charges(date)', 'bill_tenant(uuid,date,boolean)', 'svc_check_cron(text)', 'svc_get_vapid()',
    'svc_set_vapid(text,jsonb)', 'svc_due_digest()', 'svc_push_targets(uuid)', 'svc_drop_push(text)',
    'svc_plan_for(text)', 'svc_apply_subscription(uuid,text,text,timestamptz,text,text,text,jsonb)'] loop
    execute format('revoke execute on function %s from public, anon, authenticated', f);
    execute format('grant execute on function %s to service_role', f);
  end loop;
  foreach f in array array['change_rent(uuid,numeric,date)', 'add_adjustment(uuid,text,numeric,date,text)',
                           'delete_adjustment(uuid)'] loop
    execute format('revoke execute on function %s from public, anon', f);
    execute format('grant execute on function %s to authenticated', f);
  end loop;
end $$;
grant execute on function get_vapid_public() to anon, authenticated;

-- =====================================================================
-- ONLINE PAYMENTS BY MEMBERS
--   * every member gets a private pay link  (pay.html?t=<token>)
--   * "Pay online" uses the OWNER'S OWN Razorpay account → money goes straight to the owner
--   * "Pay by UPI" goes to the owner's UPI ID; the member enters the UTR, the owner confirms
--   * everything shows up live on the owner's dashboard
-- =====================================================================
alter table tenants add column if not exists pay_token text;
update tenants set pay_token = replace(gen_random_uuid()::text, '-', '') where pay_token is null;
alter table tenants alter column pay_token set default replace(gen_random_uuid()::text, '-', '');
alter table tenants alter column pay_token set not null;
create unique index if not exists tenants_pay_token_idx on tenants(pay_token);

create table if not exists online_orders (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references owners(id) on delete cascade,
  tenant_id uuid not null references tenants(id) on delete cascade,
  amount numeric(10,2) not null check (amount > 0),
  rzp_order_id text not null unique,
  status text not null default 'created' check (status in ('created','paid')),
  rzp_payment_id text,
  payment_id uuid references payments(id) on delete set null,
  created_at timestamptz not null default now(),
  paid_at timestamptz
);
create index if not exists online_orders_open_idx on online_orders(owner_id, status, created_at);

create table if not exists payment_claims (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references owners(id) on delete cascade,
  tenant_id uuid not null references tenants(id) on delete cascade,
  amount numeric(10,2) not null check (amount > 0),
  utr text not null,
  paid_on date not null default today_ist(),
  status text not null default 'pending' check (status in ('pending','confirmed','rejected')),
  payment_id uuid references payments(id) on delete set null,
  created_at timestamptz not null default now(),
  decided_at timestamptz,
  unique (tenant_id, utr)
);

-- owner's own Razorpay keys: server-only, the app can never read the secret
create table if not exists private.gateways (
  owner_id uuid primary key references owners(id) on delete cascade,
  key_id text not null,
  key_secret text not null,
  webhook_secret text,
  updated_at timestamptz not null default now()
);
revoke all on private.gateways from public;

-- App users can't fake or edit online payments (server functions are not affected)
create or replace function payments_guard() returns trigger language plpgsql as $$
begin
  if current_user in ('authenticated', 'anon') then
    if tg_op = 'INSERT' and (new.source <> 'owner' or new.mode = 'online') then raise exception 'NOT_ALLOWED'; end if;
    if tg_op in ('UPDATE', 'DELETE') and old.source = 'online' then raise exception 'ONLINE_LOCKED'; end if;
    if tg_op = 'UPDATE' and (new.source <> old.source or new.mode = 'online') then raise exception 'NOT_ALLOWED'; end if;
  end if;
  return coalesce(new, old);
end $$;
drop trigger if exists payments_guard_trg on payments;
create trigger payments_guard_trg before insert or update or delete on payments
  for each row execute function payments_guard();

-- ---------- member pay page (public, needs the secret link) ----------
create or replace function portal(p_token text) returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object(
    'name', t.name, 'room', t.room, 'place', p.name, 'category', p.category,
    'owner', o.full_name, 'owner_phone', o.phone, 'upi', o.upi_id, 'lang', o.language,
    'rent', t.rent_amount, 'due_day', t.due_day, 'active', t.is_active,
    'balance', b.balance, 'due_now', b.due_now,
    'online', exists (select 1 from private.gateways g where g.owner_id = o.id),
    'demo', o.demo_pay and not exists (select 1 from private.gateways g where g.owner_id = o.id),
    'history', coalesce((select jsonb_agg(h order by h->>'d' desc, h->>'k') from (
        select jsonb_build_object('d', c.due_date, 'k', c.kind, 'a', c.amount, 'l', c.label, 'n', c.days_charged) h
          from charges c where c.tenant_id = t.id
        union all
        select jsonb_build_object('d', y.paid_on, 'k', 'pay', 'a', y.amount, 'm', y.mode, 'ref', y.ref)
          from payments y where y.tenant_id = t.id
        order by 1 desc limit 300) x), '[]'::jsonb),
    'pending', coalesce((select jsonb_agg(jsonb_build_object('amount', c.amount, 'utr', c.utr, 'at', c.created_at) order by c.created_at desc)
          from payment_claims c where c.tenant_id = t.id and c.status = 'pending'), '[]'::jsonb)
  )
  from tenants t
  join properties p on p.id = t.property_id
  join owners o on o.id = t.owner_id
  join tenant_balances b on b.tenant_id = t.id
  where t.pay_token = p_token and length(p_token) >= 24
$$;

-- ---------- owner actions ----------
create or replace function confirm_claim(p_claim uuid, p_amount numeric default null) returns uuid
language plpgsql security definer set search_path = public as $$
declare c payment_claims; pid uuid;
begin
  select * into c from payment_claims where id = p_claim and owner_id = auth.uid() for update;
  if not found or c.status <> 'pending' then raise exception 'NOT_ALLOWED'; end if;
  insert into payments (owner_id, tenant_id, amount, mode, source, ref, paid_on, note)
  values (c.owner_id, c.tenant_id, coalesce(p_amount, c.amount), 'upi', 'upi', c.utr, c.paid_on, 'UTR ' || c.utr)
  returning id into pid;
  update payment_claims set status = 'confirmed', payment_id = pid, decided_at = now() where id = p_claim;
  return pid;
end $$;

create or replace function reject_claim(p_claim uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  update payment_claims set status = 'rejected', decided_at = now()
   where id = p_claim and owner_id = auth.uid() and status = 'pending';
  if not found then raise exception 'NOT_ALLOWED'; end if;
end $$;

create or replace function new_pay_link(p_tenant uuid) returns text
language plpgsql security definer set search_path = public as $$
declare tok text := replace(gen_random_uuid()::text, '-', '');
begin
  update tenants set pay_token = tok where id = p_tenant and owner_id = auth.uid();
  if not found then raise exception 'NOT_ALLOWED'; end if;
  return tok;
end $$;

create or replace function my_gateway() returns jsonb
language sql stable security definer set search_path = public as $$
  select coalesce((select jsonb_build_object('connected', true, 'key_id', g.key_id,
                    'live', g.key_id like 'rzp_live_%', 'webhook', g.webhook_secret is not null)
                   from private.gateways g where g.owner_id = auth.uid()), '{"connected": false}'::jsonb)
$$;

-- ---------- server-only (edge function) ----------
create or replace function svc_portal_ctx(p_token text) returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object('tenant_id', t.id, 'owner_id', t.owner_id, 'name', t.name, 'room', t.room, 'phone', t.phone,
           'place', p.name, 'lang', o.language, 'balance', b.balance, 'due_now', b.due_now,
           'key_id', g.key_id, 'key_secret', g.key_secret)
    from tenants t join properties p on p.id = t.property_id join owners o on o.id = t.owner_id
    join tenant_balances b on b.tenant_id = t.id
    left join private.gateways g on g.owner_id = t.owner_id
   where t.pay_token = p_token and length(p_token) >= 24
$$;

create or replace function svc_create_order(p_token text, p_amount numeric, p_rzp_order text) returns uuid
language plpgsql security definer set search_path = public as $$
declare t tenants; oid uuid;
begin
  select * into t from tenants where pay_token = p_token;
  if not found then raise exception 'NOT_FOUND'; end if;
  insert into online_orders (owner_id, tenant_id, amount, rzp_order_id) values (t.owner_id, t.id, p_amount, p_rzp_order)
  returning id into oid;
  return oid;
end $$;

-- how many orders this link opened recently (abuse guard)
create or replace function svc_recent_orders(p_token text) returns int
language sql stable security definer set search_path = public as $$
  select count(*)::int from online_orders o join tenants t on t.id = o.tenant_id
   where t.pay_token = p_token and o.created_at > now() - interval '1 hour'
$$;

-- Records a paid order exactly once. p_token (if given) must match the order's member.
create or replace function svc_mark_order_paid(p_rzp_order text, p_rzp_payment text, p_token text default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare o online_orders; t tenants; pid uuid; bal numeric;
begin
  select * into o from online_orders where rzp_order_id = p_rzp_order for update;
  if not found then raise exception 'NOT_FOUND'; end if;
  select * into t from tenants where id = o.tenant_id;
  if p_token is not null and t.pay_token <> p_token then raise exception 'NOT_FOUND'; end if;
  if o.status = 'paid' then
    select balance into bal from tenant_balances where tenant_id = t.id;
    return jsonb_build_object('already', true, 'amount', o.amount, 'payment', o.rzp_payment_id, 'balance', bal);
  end if;
  insert into payments (owner_id, tenant_id, amount, mode, source, ref, paid_on, note)
  values (o.owner_id, o.tenant_id, o.amount, 'online', 'online', p_rzp_payment, today_ist(), 'Online · ' || p_rzp_payment)
  returning id into pid;
  update online_orders set status = 'paid', rzp_payment_id = p_rzp_payment, payment_id = pid, paid_at = now() where id = o.id;
  select balance into bal from tenant_balances where tenant_id = t.id;
  return jsonb_build_object('already', false, 'owner_id', o.owner_id, 'name', t.name, 'amount', o.amount,
    'payment', p_rzp_payment, 'balance', bal, 'lang', (select language from owners where id = o.owner_id));
end $$;

-- Unpaid orders from the last 3 days (to check with Razorpay in case the member closed the page)
create or replace function svc_open_orders(p_owner uuid default null, p_token text default null) returns table (
  rzp_order_id text, key_id text, key_secret text)
language sql stable security definer set search_path = public as $$
  select o.rzp_order_id, g.key_id, g.key_secret
    from online_orders o join tenants t on t.id = o.tenant_id join private.gateways g on g.owner_id = o.owner_id
   where o.status = 'created' and o.created_at > now() - interval '3 days'
     and (p_owner is null or o.owner_id = p_owner) and (p_token is null or t.pay_token = p_token)
     and (p_owner is not null or p_token is not null)
   order by o.created_at desc limit 50
$$;

create or replace function svc_submit_claim(p_token text, p_amount numeric, p_utr text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare t tenants; u text := upper(regexp_replace(coalesce(p_utr, ''), '\s', '', 'g'));
begin
  select * into t from tenants where pay_token = p_token and length(p_token) >= 24;
  if not found then raise exception 'NOT_FOUND'; end if;
  if u !~ '^[A-Z0-9]{6,30}$' then raise exception 'BAD_UTR'; end if;
  if p_amount is null or p_amount < 1 or p_amount > 500000 then raise exception 'BAD_AMOUNT'; end if;
  if (select count(*) from payment_claims where tenant_id = t.id and status = 'pending') >= 3 then raise exception 'TOO_MANY'; end if;
  insert into payment_claims (owner_id, tenant_id, amount, utr) values (t.owner_id, t.id, round(p_amount, 2), u);
  return jsonb_build_object('owner_id', t.owner_id, 'name', t.name, 'amount', round(p_amount, 2),
                            'lang', (select language from owners where id = t.owner_id));
exception when unique_violation then raise exception 'DUPLICATE_UTR';
end $$;

create or replace function svc_set_gateway(p_owner uuid, p_key_id text, p_key_secret text, p_webhook_secret text) returns void
language sql security definer set search_path = public as $$
  insert into private.gateways (owner_id, key_id, key_secret, webhook_secret)
  values (p_owner, p_key_id, p_key_secret, nullif(p_webhook_secret, ''))
  on conflict (owner_id) do update set key_id = excluded.key_id, key_secret = excluded.key_secret,
    webhook_secret = excluded.webhook_secret, updated_at = now()
$$;

create or replace function svc_clear_gateway(p_owner uuid) returns void
language sql security definer set search_path = public as $$
  delete from private.gateways where owner_id = p_owner
$$;

create or replace function svc_gateway_for(p_owner uuid) returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object('key_id', key_id, 'key_secret', key_secret, 'webhook_secret', webhook_secret)
    from private.gateways where owner_id = p_owner
$$;

-- ---------- security for the online-payment tables ----------
alter table online_orders enable row level security;
alter table payment_claims enable row level security;
drop policy if exists "own orders read" on online_orders;
drop policy if exists "own claims read" on payment_claims;
create policy "own orders read" on online_orders for select using (owner_id = auth.uid());
create policy "own claims read" on payment_claims for select using (owner_id = auth.uid());
revoke insert, update, delete on online_orders, payment_claims from anon, authenticated;

do $$
declare f text;
begin
  foreach f in array array[
    'svc_portal_ctx(text)', 'svc_create_order(text,numeric,text)', 'svc_recent_orders(text)',
    'svc_mark_order_paid(text,text,text)', 'svc_open_orders(uuid,text)', 'svc_submit_claim(text,numeric,text)',
    'svc_set_gateway(uuid,text,text,text)', 'svc_clear_gateway(uuid)', 'svc_gateway_for(uuid)'] loop
    execute format('revoke execute on function %s from public, anon, authenticated', f);
    execute format('grant execute on function %s to service_role', f);
  end loop;
  foreach f in array array['confirm_claim(uuid,numeric)', 'reject_claim(uuid)', 'new_pay_link(uuid)', 'my_gateway()'] loop
    execute format('revoke execute on function %s from public, anon', f);
    execute format('grant execute on function %s to authenticated', f);
  end loop;
end $$;
grant execute on function portal(text) to anon, authenticated;

-- ---------- live updates on the dashboard (Supabase Realtime) ----------
do $$
declare tb text;
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    foreach tb in array array['payments', 'payment_claims', 'online_orders'] loop
      if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and tablename = tb) then
        execute format('alter publication supabase_realtime add table public.%I', tb);
      end if;
    end loop;
  end if;
end $$;


-- =====================================================================
-- TENANT LOGIN (phone number + PIN)
-- Tenant auth users carry user_metadata.role = 'tenant' and are never made owners.
-- Accounts are created by the `tenant-login` Edge Function when the owner sets a PIN.
-- =====================================================================
create or replace function handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if coalesce(new.raw_user_meta_data->>'role', '') = 'tenant' then return new; end if;
  insert into owners (id, phone) values (new.id, new.phone) on conflict do nothing;
  return new;
end $$;
revoke execute on function handle_new_user() from public, anon, authenticated;

create table if not exists tenant_logins (
  tenant_id uuid primary key references tenants(id) on delete cascade,
  owner_id uuid not null references owners(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  phone text not null,
  created_at timestamptz not null default now()
);
create index if not exists tenant_logins_user_idx on tenant_logins(user_id);
alter table tenant_logins enable row level security;
drop policy if exists "owner reads own tenant logins" on tenant_logins;
drop policy if exists "owner removes own tenant logins" on tenant_logins;
drop policy if exists "tenant reads own login" on tenant_logins;
create policy "owner reads own tenant logins" on tenant_logins for select using (owner_id = auth.uid());
create policy "owner removes own tenant logins" on tenant_logins for delete using (owner_id = auth.uid());
create policy "tenant reads own login" on tenant_logins for select using (user_id = auth.uid());
revoke insert, update on tenant_logins from anon, authenticated;

create or replace function my_tenancies() returns table (pay_token text, name text, place text, room text, active boolean)
language sql stable security definer set search_path = public as $$
  select t.pay_token, t.name, p.name, t.room, t.is_active
    from tenant_logins l join tenants t on t.id = l.tenant_id join properties p on p.id = t.property_id
   where l.user_id = auth.uid()
   order by t.is_active desc, t.created_at desc
$$;
revoke execute on function my_tenancies() from public, anon;
grant execute on function my_tenancies() to authenticated;

create or replace function svc_tenant_for_owner(p_owner uuid, p_tenant uuid) returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object('name', t.name, 'phone', t.phone, 'place', p.name)
    from tenants t join properties p on p.id = t.property_id
   where t.id = p_tenant and t.owner_id = p_owner
$$;
create or replace function svc_user_by_email(p_email text) returns uuid
language sql stable security definer set search_path = public, auth as $$
  select id from auth.users where lower(email) = lower(p_email) limit 1
$$;
create or replace function svc_link_tenant_login(p_owner uuid, p_tenant uuid, p_user uuid, p_phone text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from tenants where id = p_tenant and owner_id = p_owner) then raise exception 'NOT_ALLOWED'; end if;
  insert into tenant_logins (tenant_id, owner_id, user_id, phone) values (p_tenant, p_owner, p_user, p_phone)
  on conflict (tenant_id) do update set user_id = excluded.user_id, phone = excluded.phone, created_at = now();
end $$;
do $$
declare f text;
begin
  foreach f in array array['svc_tenant_for_owner(uuid,uuid)', 'svc_user_by_email(text)', 'svc_link_tenant_login(uuid,uuid,uuid,text)'] loop
    execute format('revoke execute on function %s from public, anon, authenticated', f);
    execute format('grant execute on function %s to service_role', f);
  end loop;
end $$;


-- =====================================================================
-- TEST (DEMO) ONLINE PAYMENTS — work without Razorpay, no real money, marked "test"
-- =====================================================================
grant update (demo_pay) on owners to authenticated;

create or replace function payments_guard() returns trigger language plpgsql set search_path = public as $$
begin
  if current_user in ('authenticated', 'anon') then
    if tg_op = 'INSERT' and (new.source <> 'owner' or new.mode = 'online') then raise exception 'NOT_ALLOWED'; end if;
    if tg_op in ('UPDATE', 'DELETE') and old.source = 'online' and coalesce(old.ref, '') not like 'test\_%' then raise exception 'ONLINE_LOCKED'; end if;
    if tg_op = 'UPDATE' and (new.source <> old.source or new.mode = 'online') then raise exception 'NOT_ALLOWED'; end if;
  end if;
  return coalesce(new, old);
end $$;

create or replace function portal_demo_pay(p_token text, p_amount numeric) returns jsonb
language plpgsql security definer set search_path = public as $$
declare t tenants; o owners; v_ref text; bal numeric; amt numeric := round(p_amount, 0);
begin
  select * into t from tenants where pay_token = p_token and length(p_token) >= 24;
  if not found then raise exception 'NOT_FOUND'; end if;
  select * into o from owners where id = t.owner_id;
  if not o.demo_pay or exists (select 1 from private.gateways g where g.owner_id = o.id) then raise exception 'DEMO_OFF'; end if;
  if amt is null or amt < 1 or amt > 500000 then raise exception 'BAD_AMOUNT'; end if;
  if (select count(*) from payments y where y.tenant_id = t.id and y.ref like 'test\_%' and y.created_at > now() - interval '1 hour') >= 20 then
    raise exception 'TOO_MANY';
  end if;
  v_ref := 'test_' || substr(replace(gen_random_uuid()::text, '-', ''), 1, 14);
  insert into payments (owner_id, tenant_id, amount, mode, source, ref, paid_on, note)
  values (t.owner_id, t.id, amt, 'online', 'online', v_ref, today_ist(), 'Test payment (demo) · no real money');
  select balance into bal from tenant_balances where tenant_id = t.id;
  return jsonb_build_object('amount', amt, 'payment', v_ref, 'balance', bal);
end $$;
revoke execute on function portal_demo_pay(text, numeric) from public;
grant execute on function portal_demo_pay(text, numeric) to anon, authenticated;


-- =====================================================================
-- SECURITY DEPOSIT RECEIVED (cash / UPI …), separate from rent
-- =====================================================================
create table if not exists deposit_payments (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references owners(id) on delete cascade,
  tenant_id uuid not null references tenants(id) on delete cascade,
  amount numeric(10,2) not null check (amount > 0),
  mode text not null default 'cash' check (mode in ('cash','upi','bank','other')),
  paid_on date not null default today_ist(),
  note text,
  created_at timestamptz not null default now()
);
create index if not exists deposit_payments_tenant_idx on deposit_payments(tenant_id);
alter table deposit_payments enable row level security;
drop policy if exists "own deposit payments" on deposit_payments;
create policy "own deposit payments" on deposit_payments for all using (owner_id = auth.uid()) with check (owner_id = auth.uid());

create or replace function deposit_payments_before() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from tenants t where t.id = new.tenant_id and t.owner_id = new.owner_id) then
    raise exception 'BAD_TENANT';
  end if;
  return new;
end $$;
revoke execute on function deposit_payments_before() from public, anon, authenticated;
drop trigger if exists deposit_payments_before_trg on deposit_payments;
create trigger deposit_payments_before_trg before insert or update on deposit_payments
  for each row execute function deposit_payments_before();

insert into deposit_payments (owner_id, tenant_id, amount, mode, paid_on, note)
select t.owner_id, t.id, t.security_deposit, 'other', t.join_date, 'Recorded before deposit tracking'
  from tenants t where t.security_deposit > 0
   and not exists (select 1 from deposit_payments d where d.tenant_id = t.id);

create or replace view tenant_balances with (security_invoker = true) as
select
  t.id as tenant_id, t.owner_id, t.property_id, t.name, t.phone, t.room, t.rent_amount, t.due_day,
  t.join_date, t.left_date, t.is_active, t.notify_enabled, t.note, t.security_deposit,
  coalesce(p.deposit_used, 0) as deposit_used,
  coalesce(c.total_charged, 0) as total_charged,
  coalesce(p.total_paid, 0) as total_paid,
  coalesce(c.total_charged, 0) - coalesce(p.total_paid, 0) as balance,
  coalesce(c.due_now, 0) - coalesce(p.total_paid, 0) as due_now,
  coalesce(d.deposit_received, 0) as deposit_received
from tenants t
left join (select tenant_id, sum(amount) total_charged,
                  sum(amount) filter (where due_date <= today_ist()) due_now
             from charges group by tenant_id) c on c.tenant_id = t.id
left join (select tenant_id, sum(amount) total_paid,
                  sum(amount) filter (where mode = 'deposit') deposit_used
             from payments group by tenant_id) p on p.tenant_id = t.id
left join (select tenant_id, sum(amount) deposit_received from deposit_payments group by tenant_id) d on d.tenant_id = t.id;
revoke all on tenant_balances from anon;

create or replace function payments_before() returns trigger
language plpgsql security definer set search_path = public as $$
declare got numeric; used numeric;
begin
  if not exists (select 1 from tenants t where t.id = new.tenant_id and t.owner_id = new.owner_id) then
    raise exception 'BAD_TENANT';
  end if;
  if new.mode = 'deposit' then
    select coalesce(sum(amount), 0) into got from deposit_payments where tenant_id = new.tenant_id;
    select coalesce(sum(amount), 0) into used from payments
     where tenant_id = new.tenant_id and mode = 'deposit' and id <> new.id;
    if used + new.amount > got then raise exception 'DEPOSIT_EXCEEDED'; end if;
  end if;
  return new;
end $$;

create or replace function portal(p_token text) returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object(
    'name', t.name, 'room', t.room, 'place', p.name, 'category', p.category,
    'owner', o.full_name, 'owner_phone', o.phone, 'upi', o.upi_id, 'lang', o.language,
    'rent', t.rent_amount, 'due_day', t.due_day, 'active', t.is_active,
    'balance', b.balance, 'due_now', b.due_now,
    'deposit', t.security_deposit, 'deposit_received', b.deposit_received, 'deposit_used', b.deposit_used,
    'online', exists (select 1 from private.gateways g where g.owner_id = o.id),
    'demo', o.demo_pay and not exists (select 1 from private.gateways g where g.owner_id = o.id),
    'history', coalesce((select jsonb_agg(h order by h->>'d' desc, h->>'k') from (
        select jsonb_build_object('d', c.due_date, 'k', c.kind, 'a', c.amount, 'l', c.label, 'n', c.days_charged) h
          from charges c where c.tenant_id = t.id
        union all
        select jsonb_build_object('d', y.paid_on, 'k', 'pay', 'a', y.amount, 'm', y.mode, 'ref', y.ref)
          from payments y where y.tenant_id = t.id
        order by 1 desc limit 300) x), '[]'::jsonb),
    'deposits', coalesce((select jsonb_agg(jsonb_build_object('d', d.paid_on, 'a', d.amount, 'm', d.mode) order by d.paid_on)
          from deposit_payments d where d.tenant_id = t.id), '[]'::jsonb),
    'pending', coalesce((select jsonb_agg(jsonb_build_object('amount', c.amount, 'utr', c.utr, 'at', c.created_at) order by c.created_at desc)
          from payment_claims c where c.tenant_id = t.id and c.status = 'pending'), '[]'::jsonb)
  )
  from tenants t
  join properties p on p.id = t.property_id
  join owners o on o.id = t.owner_id
  join tenant_balances b on b.tenant_id = t.id
  where t.pay_token = p_token and length(p_token) >= 24
$$;

-- ---------- owners created before this script --------------------------
insert into owners (id, phone) select id, phone from auth.users
 where coalesce(raw_user_meta_data->>'role', '') <> 'tenant' on conflict do nothing;

-- ---------- scheduled jobs (Supabase) ----------------------------------
--   00:35 IST  bill everyone          (19:05 UTC)
--   09:00 IST  phone alert to owners  (03:30 UTC)
do $$
begin
  create extension if not exists pg_cron;
  perform cron.schedule('duedesk-charges', '5 19 * * *', 'select generate_charges(today_ist())');
  begin
    create extension if not exists pg_net;
    perform cron.schedule('duedesk-alerts', '30 3 * * *', $job$
      select net.http_post(
        url := (select project_url from private.config where id = 1) || '/functions/v1/duedesk',
        headers := jsonb_build_object('Content-Type', 'application/json',
                     'x-cron-secret', (select cron_secret from private.config where id = 1)),
        body := '{"action":"daily"}'::jsonb)
    $job$);
  exception when others then
    raise notice 'pg_net not available: enable it in Database → Extensions, then run this script again.';
  end;
exception when others then
  raise notice 'pg_cron not available: enable it in Database → Extensions, then run this script again.';
end $$;

-- ---------- catch up billing now --------------------------------------
select generate_charges(today_ist());

-- ---------- status (this is what the SQL editor shows at the end) -----
select
  (select count(*) from owners)  as owners,
  (select count(*) from tenants) as members,
  (select count(*) from charges) as charges,
  exists (select 1 from pg_extension where extname = 'pg_cron') as cron_on,
  exists (select 1 from pg_extension where extname = 'pg_net')  as net_on,
  'v3 ready' as status;
