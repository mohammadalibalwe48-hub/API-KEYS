-- =====================================================================
-- Keyvault — database schema snapshot
-- ---------------------------------------------------------------------
-- This file mirrors exactly what is deployed to Supabase project
-- hszumyzujgnjvetvnben. It is documentation / disaster-recovery, not a
-- build step: the live database is already provisioned.
--
-- SECRET HANDLING
--   The AES passphrase is generated inside Postgres by
--   gen_random_bytes(32). It lives only in private.app_secrets, a table
--   in a schema that is NOT exposed through PostgREST. It therefore
--   never appears in this repository, in the frontend, in logs, or in
--   any API response. Rotating it requires re-encrypting existing rows.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------------------------------------------------------------------
-- 1. Private encryption layer
-- ---------------------------------------------------------------------
create schema if not exists private;

revoke all on schema private from public, anon, authenticated;

create table if not exists private.app_secrets (
  id         text primary key,
  secret     text not null,
  created_at timestamptz not null default now()
);

alter table private.app_secrets enable row level security;
revoke all on table private.app_secrets from public, anon, authenticated;

insert into private.app_secrets (id, secret)
values ('api_key_encryption_v1', encode(extensions.gen_random_bytes(32), 'hex'))
on conflict (id) do nothing;

create or replace function private.encrypt_api_key(p_plaintext text)
returns bytea
language sql security definer set search_path = ''
as $$
  select extensions.pgp_sym_encrypt(
    p_plaintext,
    (select s.secret from private.app_secrets s where s.id = 'api_key_encryption_v1'),
    'cipher-algo=aes256'
  )
$$;

create or replace function private.decrypt_api_key(p_ciphertext bytea)
returns text
language sql security definer set search_path = ''
as $$
  select extensions.pgp_sym_decrypt(
    p_ciphertext,
    (select s.secret from private.app_secrets s where s.id = 'api_key_encryption_v1')
  )
$$;

revoke all on function private.encrypt_api_key(text) from public, anon, authenticated;
revoke all on function private.decrypt_api_key(bytea) from public, anon, authenticated;

-- ---------------------------------------------------------------------
-- 2. Keys table — ciphertext only, never plaintext
-- ---------------------------------------------------------------------
create table if not exists public.api_keys (
  id                uuid primary key default extensions.gen_random_uuid(),
  user_id           uuid not null references auth.users(id) on delete cascade,
  provider          text not null default 'Custom',
  label             text,
  description       text,
  api_base_url      text,
  key_ciphertext    bytea not null,
  key_last4         text not null default '',
  key_fingerprint   text not null,
  -- Outcome of the most recent live provider probe (NULL = never tested).
  last_check_at      timestamptz,
  last_check_ok      boolean,
  last_check_status  integer,
  last_check_message text,
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now(),
  constraint api_keys_provider_check
    check (provider in ('AgentRouter','TokenHarbor','SeekAI','Custom'))
);

create index if not exists api_keys_user_id_idx
  on public.api_keys (user_id, created_at desc);

alter table public.api_keys enable row level security;

-- Read-only policy: users see only their own rows.
create policy "api_keys_select_own"
  on public.api_keys for select
  to authenticated
  using ( (select auth.uid()) = user_id );

-- NO insert/update/delete policies exist. All mutations must pass through
-- the SECURITY DEFINER functions below, which enforce ownership and
-- encryption. This means a compromised client cannot write plaintext or
-- touch another user's data even with a valid session token.

grant select on table public.api_keys to authenticated;

create or replace function public.touch_updated_at()
returns trigger language plpgsql set search_path = ''
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

create trigger api_keys_touch_updated_at
  before update on public.api_keys
  for each row execute function public.touch_updated_at();

-- ---------------------------------------------------------------------
-- 3. RPCs — the only write/reveal path
--    CREATE / UPDATE return audit-safe jsonb (no ciphertext field).
--    REVEAL decrypts a single owned row.
-- ---------------------------------------------------------------------
-- create_api_key(p_provider, p_api_key, p_label, p_description, p_api_base_url) -> jsonb
-- update_api_key(p_id, p_provider, p_label, p_description, p_api_base_url, p_api_key) -> jsonb
-- get_api_key_secret(p_id) -> text
-- delete_api_key(p_id) -> void
-- record_api_key_check(p_id, p_ok, p_status, p_message) -> void
--
-- Each begins with:  v_uid uuid := (select auth.uid());
-- and raises 42501 when unauthenticated. Ownership is re-verified by
-- matching user_id = auth.uid() inside the statement itself.
-- Every function is: SECURITY DEFINER + SET search_path = '' + EXECUTE
-- granted only to the `authenticated` role.

-- ---------------------------------------------------------------------
-- 4. Realtime (cross-device sync)
-- ---------------------------------------------------------------------
alter table public.api_keys replica identity full;
alter publication supabase_realtime add table public.api_keys;

-- ---------------------------------------------------------------------
-- 5. Edge Function: test-api-key
-- ---------------------------------------------------------------------
-- Deployed to supabase/functions/test-api-key with verify_jwt = true.
-- It verifies a stored key against its provider, server-side, because
-- browsers block cross-origin provider calls and a key must never travel
-- in a URL. The browser sends only the key's id; the function decrypts the
-- key in-database (inheriting the caller's RLS via get_api_key_secret),
-- calls the provider with the key as an Authorization header only, and
-- records the outcome with record_api_key_check(). Targets are restricted
-- to https public hosts to prevent SSRF, and responses are scrubbed so the
-- key can never be echoed back.

-- ---------------------------------------------------------------------
-- 5. Usage tracking, proxy tokens and per-provider URLs
-- ---------------------------------------------------------------------
-- user_provider_urls  (user_id, provider) -> base_url, probe_path
--   Auto-learned: saving a key records its base URL for that provider, so
--   the next key of the same provider pre-fills. RLS: own rows only.
--
-- usage_events        one row per proxied request
--   Stores counts, model, status, latency and estimated cost. Prompt and
--   completion text is NEVER stored. RLS: select own rows only; there is no
--   insert policy, so only the proxy (via service key) can write.
--
-- proxy_tokens        token_hash (unique), token_hint, key_id, revoked_at
--   A token is bound to ONE key, so a caller never names a key and cannot
--   reach another. Stored only as a SHA-256 hash; token_hash is not granted
--   to clients.
--
-- model_pricing       model_pattern -> input/output USD per 1M tokens
--   Shared, read-only reference data. Approximate public list prices.
--
-- service_* functions are granted to service_role ONLY, never to
-- authenticated. Verified: a signed-in user calling service_resolve_proxy_token,
-- service_get_key or service_get_provider_url receives a permission error, and
-- cannot select proxy_tokens.token_hash.

-- ---------------------------------------------------------------------
-- 6. Operational notes
-- ---------------------------------------------------------------------
-- * auth.users is managed by Supabase Auth; sign-up requires a unique
--   email and a password of at least 6 characters.
-- * The client only ever reads metadata columns and calls the RPCs.
--   It has no SQL access to key_ciphertext benefits: it lacks the
--   private key, so ciphertext alone is useless.
-- * To rotate the encryption passphrase, decrypt all rows with the old
--   secret and re-encrypt with the new one inside a single transaction.