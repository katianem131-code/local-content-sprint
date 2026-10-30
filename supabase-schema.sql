-- Local Content Sprint - Supabase schema
-- Run this in Supabase SQL Editor before enabling production persistence.

create table if not exists public.profiles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references auth.users(id) on delete cascade,
  business_name text default '',
  category text default '',
  audience text default '',
  offer text default '',
  problem text default '',
  tone text default 'Clear and practical',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.saved_posts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  moment text not null,
  platform text not null,
  hook text default '',
  body text default '',
  cta text default '',
  created_at timestamptz not null default now()
);

create table if not exists public.calendar_progress (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  day_number integer not null check (day_number between 1 and 30),
  status text not null default 'completed',
  completed_at timestamptz,
  unique(user_id, day_number)
);

create table if not exists public.worksheets (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  worksheet_type text not null,
  data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(user_id, worksheet_type)
);

create table if not exists public.weekly_plans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  week_start date not null,
  data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(user_id, week_start)
);

create table if not exists public.entitlements (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  product_key text not null,
  status text not null default 'active',
  source text not null default 'cakto',
  external_order_id text,
  purchased_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(user_id, product_key)
);

alter table public.profiles enable row level security;
alter table public.saved_posts enable row level security;
alter table public.calendar_progress enable row level security;
alter table public.worksheets enable row level security;
alter table public.weekly_plans enable row level security;
alter table public.entitlements enable row level security;

create policy "Users manage their profile" on public.profiles for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "Users manage their saved posts" on public.saved_posts for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "Users manage their calendar progress" on public.calendar_progress for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "Users manage their worksheets" on public.worksheets for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "Users manage their weekly plans" on public.weekly_plans for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "Users read their entitlements" on public.entitlements for select using (auth.uid() = user_id);

