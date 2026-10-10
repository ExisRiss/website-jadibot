-- By AlzRiss - Usanagi Umi AI
-- Private platform data schema. Browser clients do not receive service-role access.

create extension if not exists pgcrypto;

create table if not exists public.platform_profiles (
  auth_id text primary key,
  email text not null unique check (email = lower(email)),
  username text not null default '' check (char_length(username) <= 40),
  roles text[] not null default array['user']::text[],
  locked boolean not null default false,
  banned boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  constraint platform_profiles_roles_valid check (
    roles <@ array['user','admin','partner','owner','developer']::text[]
    and cardinality(roles) between 1 and 5
  )
);

create unique index if not exists platform_profiles_username_unique on public.platform_profiles(lower(username)) where username <> '';

create table if not exists public.global_messages (
  id bigint generated always as identity primary key,
  auth_id text not null,
  email text not null,
  roles text[] not null default array['user']::text[],
  body text not null check (char_length(body) between 1 and 1000),
  created_at timestamptz not null default now()
);
create index if not exists global_messages_created_idx on public.global_messages(created_at desc);

create table if not exists public.plugin_catalog (
  id uuid primary key default gen_random_uuid(),
  slug text not null unique check (slug ~ '^[a-z0-9][a-z0-9_-]{1,63}$'),
  filename text not null check (filename ~ '^[a-zA-Z0-9_.-]+\\.js$'),
  description text not null default '',
  code text not null check (octet_length(code) between 1 and 524288),
  uploader_id text not null,
  uploader_email text not null,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.plugin_installs (
  id uuid primary key default gen_random_uuid(),
  plugin_id uuid not null references public.plugin_catalog(id) on delete cascade,
  auth_id text not null,
  session_id text not null check (session_id ~ '^[0-9]{7,15}$'),
  status text not null default 'pending' check (status in ('pending','installed','failed','removed')),
  error text,
  installed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(plugin_id, auth_id, session_id)
);

create table if not exists public.media_assets (
  id uuid primary key default gen_random_uuid(),
  auth_id text not null,
  session_id text not null check (session_id ~ '^[0-9]{7,15}$'),
  kind text not null check (kind in ('logo','menu_banner','menu_video','menu_audio','welcome_image','goodbye_image','thumbnail')),
  storage_path text,
  source_url text not null,
  mime_type text,
  size_bytes bigint not null default 0,
  created_at timestamptz not null default now()
);
create index if not exists media_assets_session_idx on public.media_assets(auth_id, session_id, kind, created_at desc);

-- Migration for existing projects created before Foto Goodbye was available.
alter table public.media_assets drop constraint if exists media_assets_kind_check;
alter table public.media_assets add constraint media_assets_kind_check check (
  kind in ('logo','menu_banner','menu_video','menu_audio','welcome_image','goodbye_image','thumbnail')
);

create table if not exists public.platform_audit_logs (
  id bigint generated always as identity primary key,
  actor_id text not null,
  actor_email text not null,
  action text not null,
  target text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists platform_audit_created_idx on public.platform_audit_logs(created_at desc);

alter table public.platform_profiles enable row level security;
alter table public.global_messages enable row level security;
alter table public.plugin_catalog enable row level security;
alter table public.plugin_installs enable row level security;
alter table public.media_assets enable row level security;
alter table public.platform_audit_logs enable row level security;

revoke all on table public.platform_profiles from anon, authenticated;
revoke all on table public.global_messages from anon, authenticated;
revoke all on table public.plugin_catalog from anon, authenticated;
revoke all on table public.plugin_installs from anon, authenticated;
revoke all on table public.media_assets from anon, authenticated;
revoke all on table public.platform_audit_logs from anon, authenticated;
grant all on table public.platform_profiles to service_role;
grant all on table public.global_messages to service_role;
grant all on table public.plugin_catalog to service_role;
grant all on table public.plugin_installs to service_role;
grant all on table public.media_assets to service_role;
grant all on table public.platform_audit_logs to service_role;
grant usage, select on all sequences in schema public to service_role;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'umi-media',
  'umi-media',
  true,
  33554432,
  array['image/jpeg','image/png','image/webp','image/gif','video/mp4','video/webm','audio/mpeg','audio/mp4','audio/ogg','audio/opus']
)
on conflict (id) do update set
  public = excluded.public,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;
