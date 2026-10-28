create extension if not exists pgcrypto;

create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  email text unique not null,
  password_hash text not null,
  created_at timestamptz not null default now()
);

create table if not exists cases (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references users(id) on delete cascade,
  title text not null,
  token text unique not null,
  expires_at timestamptz not null,
  status text not null default 'open',
  created_at timestamptz not null default now()
);

create table if not exists submissions (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references cases(id) on delete cascade,
  consent_location boolean not null default false,
  consent_phone boolean not null default false,
  consent_photo boolean not null default false,
  phone text,
  latitude double precision,
  longitude double precision,
  photo_path text,
  created_at timestamptz not null default now()
);

-- Create a private Storage bucket named: consent-photos
-- Do not make it public. In production, serve files through authenticated,
-- short-lived signed URLs.
