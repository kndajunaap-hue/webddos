create extension if not exists pgcrypto;

create table if not exists public.api_keys (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  key_hash text not null unique,
  key_prefix text not null,
  label text not null default 'My application' check (char_length(label) between 1 and 80),
  created_at timestamptz not null default now(),
  expires_at timestamptz,
  revoked_at timestamptz,
  last_used_at timestamptz
);
create index if not exists api_keys_user_created_idx on public.api_keys(user_id, created_at desc);

create table if not exists public.script_posts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  username text not null,
  caption text not null check (char_length(caption) between 1 and 500),
  file_name text not null check (char_length(file_name) between 1 and 120),
  language text not null default 'text' check (char_length(language) <= 24),
  source_code text not null check (octet_length(source_code) <= 50000),
  downloads integer not null default 0 check (downloads >= 0),
  created_at timestamptz not null default now()
);
create index if not exists script_posts_created_idx on public.script_posts(created_at desc);

create table if not exists public.script_likes (
  script_id uuid not null references public.script_posts(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key(script_id, user_id)
);

create table if not exists public.script_comments (
  id uuid primary key default gen_random_uuid(),
  script_id uuid not null references public.script_posts(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  username text not null,
  body text not null check (char_length(body) between 1 and 1200),
  created_at timestamptz not null default now()
);
create index if not exists script_comments_post_created_idx on public.script_comments(script_id, created_at);

alter table public.api_keys enable row level security;
alter table public.script_posts enable row level security;
alter table public.script_likes enable row level security;
alter table public.script_comments enable row level security;

revoke all on public.api_keys, public.script_posts, public.script_likes, public.script_comments from anon, authenticated;
grant select, insert, update, delete on public.api_keys, public.script_posts, public.script_likes, public.script_comments to service_role;

create or replace function public.increment_script_download(p_script_id uuid)
returns void
language sql
security definer
set search_path = public
as $$
  update public.script_posts set downloads = downloads + 1 where id = p_script_id;
$$;

revoke all on function public.increment_script_download(uuid) from public, anon, authenticated;
grant execute on function public.increment_script_download(uuid) to service_role;
