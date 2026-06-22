-- Run this in your Supabase project → SQL Editor

create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  phone text unique not null,
  webauthn_credentials jsonb not null default '[]',
  streak_dates text[] not null default '{}',
  custom_categories jsonb not null default '[]',
  created_at timestamptz not null default now()
);

create table if not exists tasks (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  title text not null,
  notes text,
  priority text not null default 'medium',
  category text not null default 'Personal',
  due_date timestamptz,
  has_time boolean not null default false,
  recurrence text,
  completed boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists auth_challenges (
  key text primary key,
  challenge text not null,
  expiry timestamptz not null
);

create table if not exists auth_otps (
  phone text primary key,
  code text not null,
  expiry timestamptz not null
);

create index if not exists tasks_user_id_idx on tasks(user_id);

-- Disable RLS so the service role key has full access
alter table users disable row level security;
alter table tasks disable row level security;
alter table auth_challenges disable row level security;
alter table auth_otps disable row level security;
