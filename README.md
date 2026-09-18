# KeyVault — AI API Key Manager

A small, modern, fully working web app for storing AI provider API keys.
Built on Supabase (Auth + Postgres + RLS + Realtime). Plain HTML, CSS, and
JavaScript — no build step, no framework, no bundler.

Keys are **encrypted at rest with AES-256**, **isolated per user by Row Level
Security**, and **decrypted only on demand**, in memory, for a few seconds.

---

## Features

| Area | What works |
|---|---|
| **Auth** | Email/password sign up, log in, log out, persistent sessions, same account across phone / iPad / desktop |
| **Providers** | `AgentRouter`, `TokenHarbor`, `SeekAI`, plus `Custom` for anything else |
| **Keys** | Add, edit, delete, reveal/hide, one-click copy, search, provider filter chips |
| **Expiry** | Give a key a lifetime — preset or exact date. Expired keys are kept but *cannot be used*, enforced in the database. See [Key expiry](#key-expiry) |
| **Groups** | Name and colour-code buckets, filter by group, and manage them in Account. See [Key groups](#key-groups) |
| **Bulk actions** | Tick several keys, then assign a group, set an expiry, validate them all, export, or delete |
| **Export** | Download metadata for the filtered or selected keys as JSON — **never the secrets** |
| **Validation** | Verify a key actually works against its provider, from the server — see [Connectivity check](#connectivity-check-test-button) |
| **Usage** | Route provider traffic through a proxy and record tokens plus estimated spend per key |
| **Proxy tokens** | Revocable per-key tokens (`kv_...`) so an SDK can talk through the vault without ever holding the real key |
| **Fields** | Provider, API key, optional label, description, API Base URL, group and expiry |
| **Masking** | Keys show as `••••••••••••••••XXXX` by default (mask + last 4) |
| **Sync** | Supabase Realtime pushes changes to every signed-in device instantly |
| **Design** | A unified design system — see [Interface](#interface) |

---

## Interface

The UI is built on one design system rather than per-page styling.

**Tokens.** Every colour is authored in OKLCH and resolved through CSS
`light-dark()`, so light and dark are two expressions of the same palette
instead of two hand-tuned themes. Each token is written with a plain fallback
first, so a browser without `light-dark()` still renders a coherent light theme.
Type, spacing (4px rhythm), radii, depth and motion are all tokenised in the
`tokens` layer; components never hard-code a value.

**Colour system.** A cream canvas, deep forest-green surfaces and a single mint
accent. A green-tinted neutral ramp (`--ink` → `--ink-faint`) carries the text,
and three semantic families (ok / warn / danger) each have base, quiet and line
variants for composed surfaces. The four providers get evenly spaced categorical
hues, applied through a `--provider-hue` custom property so a provider's identity
carries into dots, filter pills and dashboard meters.

Two deliberate details sit inside the palette. First, **green is both the brand
and the "healthy" state**, so the semantic families were tuned to sit beside it
rather than clash: `warn` is a warm amber, `danger` a soft brick. Second, the
mint is a *surface* colour, not a text colour — at its lightness it cannot carry
small type on cream. A darker sibling, `--accent-text`, exists for exactly that,
and every textual use of the accent goes through it. The mint's label colour is
the deep green too, since white on a 0.712-lightness green is not readable.

**Shape.** Generous radii: cards are 22px, dialogs 28px, controls 12px, and only
true status chips are full pills. Depth is soft, green-tinted and low-contrast,
so a card reads as paper on cream rather than a floating panel.

**Iconography.** Zero emoji. A 32-symbol inline SVG sprite carries its own
stroke attributes so geometry survives any cascade context. Icons are referenced
by `<use href="#i-...">` in markup and by a small `icon()` helper in JS.

**Layout.** Two shells that swap at 1024px: a mobile-first stack with a bottom
tab bar, and a desktop layout with a sticky sidebar rail. Navigation is
hash-routed (`#overview`, `#keys`, `#account`), so refresh, back and forward all
behave, and the active view is reflected in `aria-current`.

**Views.** An Overview that opens on a centred hero, then summary metrics, a
provider distribution, the security posture, recent validation results, and a
**keys needing attention** panel that appears when anything has expired or is
close to it. An API keys view that renders a real `<table>` at ≥900px and a card
stack below it — both from the same data, so desktop gets density and mobile gets
legibility — with row selection, provider and group filters, and a sticky bulk
bar. An Account view for identity, group management, theme choice and session
control.

**Inversion.** The deep green appears wherever a surface should feel decisive:
the brand mark, the active navigation item, the active filter chip, the auth
brand panel and the primary CTA. This is what gives the interface a single
hierarchy — the cream is the canvas, the white is the content, and the green is
the act.

**States.** Every interactive element defines hover, active, focus-visible,
disabled and busy states. Buttons carry a spinner via `data-busy`, async actions
show inline progress, empty and loading states are explicit, and errors appear
in context rather than only as a toast.

**Accessibility.** A skip link, a screen-reader-only utility, labelled controls,
`aria-live` regions for result and validation announcements, `aria-pressed` on
toggles, focus moved to the view heading on navigation, dialog focus trapping via
native `<dialog>`, full keyboard operation including `Ctrl`/`Cmd`+`K` to search,
and a `prefers-reduced-motion` guard that collapses all transitions.

**Theme.** System by default, overridable per device from the app bar or Account
view, applied before first paint by a tiny inline script so there is no flash.

**Typography.** Inter, loaded from Google Fonts, for interface text — with a
system fallback stack so it degrades cleanly offline. Display type (the hero, the
auth headline, panel titles) is heavy and tightly tracked; body type is quiet.
A monospace stack carries keys and URLs, `tabular-nums` keeps figures aligned,
and `text-wrap: balance` is applied to the hero and auth headline.

---

## Quick start

Any static file server works. The only hard requirement is that the app is not
opened via `file://`, because ES modules and Supabase Auth need an `http(s)`
origin.

```bash
# Option 1 — Node
npx serve . -l 5200

# Option 2 — Python
python -m http.server 5200
```

Then open <http://localhost:5200>.

### Configuration

Everything already points at the provisioned Supabase project. See
[`config.js`](config.js:1):

```js
export const SUPABASE_URL = 'https://hszumyzujgnjvetvnben.supabase.co';
export const SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_…'; // public by design
```

> The publishable/anon key is safe in the browser. It grants nothing on its
> own — every row is protected by RLS. **The `service_role` key is never used
> in the frontend and must never be added.**

### Email confirmation (important)

This project currently has **email confirmation enabled**, which is the secure
default. The flow is:

1. **Sign up** → account is created, no session yet.
2. A confirmation email is sent (from `noreply@mail.app.supabase.io`, so check
   spam on the first sign-up).
3. Click the link, then **log in**.

To disable it (convenient for local testing, not recommended for production):
Supabase Dashboard → **Authentication → Sign In / Providers → Email** → turn
off *Confirm email*.

If you skip confirmation and try to log in, the app shows
*"Please confirm your email address first."*

---

## Key expiry

A key can be given a lifetime in the editor: **No expiry**, `1 hour`, `24 hours`,
`7 / 30 / 90 / 180 / 365 days`, or a **custom** date and time.

Expiry is enforced **in the database**, not in the browser. When the proxy
resolves a token to its key, [`service_get_key()`](supabase-schema.sql:1) returns
`expired: true` and **withholds the plaintext entirely**:

```sql
v_expired := v_row.expires_at is not null and v_row.expires_at <= now();
-- 'secret', case when v_expired then null
--           else private.decrypt_api_key(v_row.key_ciphertext) end
```

That has three consequences worth stating plainly:

- An expired key **cannot be used**, even by a caller holding a valid proxy token.
  The refusal is not a client-side check that could be bypassed.
- The key is **not deleted**. The record, its metadata and its history all remain,
  so an expiry is reversible — extend it and the key works again.
- An expired key is **not silently dropped** either. It stays visible in the list,
  tagged `Expired`, and appears in a **Keys needing attention** panel on Overview
  with a one-click **Extend** action.

The Overview also counts **Expiring soon**, defined as within
[`EXPIRY_WARNING_DAYS`](config.js:1) (7 by default) so nothing lapses unnoticed.

## Key groups

Groups are named, colour-coded buckets — by project, team or environment.

- Create, rename, recolour and delete them in **Account → Groups**.
- Assign a key to a group in the key editor, or select several keys and use
  **Assign group** in the bulk bar.
- Filter the keys view by group; an **Ungrouped** filter appears whenever any
  key has no group.
- The search box matches group names too. Sort offers **Group A–Z**.

Groups are designed to be safe to delete: the foreign key is
`ON DELETE SET NULL`, so removing a group never removes a key — the key simply
becomes ungrouped, and the confirmation dialog says so.

Colours are stored as one of eight names, constrained by a database `CHECK`
(`slate`, `indigo`, `rose`, `amber`, `emerald`, `sky`, `violet`, `teal`), and
mapped to OKLCH hues in [`group-palette.js`](group-palette.js:1). Because the
mapping uses `light-dark()`, one stored name resolves to a coherent colour in
both themes.

## Bulk actions and export

Tick keys in the list (or on a card) to open the bulk bar. From there you can:

| Action | Effect |
|---|---|
| **Assign group** | Move every selected key into a group |
| **Set expiry** | Apply a preset lifetime to all of them |
| **Validate** | Run the provider check sequentially, so no provider is stampeded |
| **Export** | Download the selected keys as JSON |
| **Delete** | Remove them, behind a confirmation that states the count |

**Export is metadata only.** The JSON carries label, provider, description, base
URL, group name, `key_last4`, fingerprint, expiry and validation history — and
states `"secrets_included": false` explicitly. It is not a backup of the
credentials, and cannot be turned into one: the frontend never has them all at
once.

## Security architecture

This is the part that matters. Four layers cooperate.

### 1. Encrypted at rest (`private` schema)

An AES-256 passphrase is generated inside Postgres via
`extensions.gen_random_bytes(32)` and stored in `private.app_secrets`:

- the `private` schema is **not exposed through PostgREST**;
- `anon` and `authenticated` have **no grants** on it at all;
- it has RLS enabled with **zero policies** (deny-all), so even a leaked
  session token cannot read the passphrase.

Because the key is generated in the database, it has **never existed** in the
frontend, in this repository, in URL parameters, in logs, or in any API
response. Only the `SECURITY DEFINER` helpers `private.encrypt_api_key()` and
`private.decrypt_api_key()` (owned by `postgres`) can use it.

### 2. Row Level Security

`public.api_keys` has RLS enabled with exactly one policy:

```sql
create policy "api_keys_select_own" on public.api_keys
  for select to authenticated
  using ( (select auth.uid()) = user_id );
```

There are deliberately **no INSERT, UPDATE, or DELETE policies**. Writes are
impossible except through the RPCs below, so a tampered client cannot inject
plaintext values or touch another user's rows even with a valid token.

### 3. RPCs as the single mutation path

| Function | Purpose |
|---|---|
| `create_api_key(provider, api_key, label, description, api_base_url, expires_at, group_id)` | Validate → encrypt → insert |
| `update_api_key(id, provider, label, description, api_base_url, api_key, expires_at, group_id)` | Re-encrypt only when a new key is supplied |
| `get_api_key_secret(id)` | Decrypt one owned key, on demand |
| `delete_api_key(id)` | Delete one owned key |
| `set_api_key_expiry(id, expires_at)` | Set or clear a key's lifetime |
| `set_api_key_group(id, group_id)` | Move a key into a group, or out of one |
| `create_key_group(name, color)` / `update_key_group(id, name, color)` | Create or rename/recolour a group |
| `delete_key_group(id)` | Delete a group; its keys become ungrouped |

Every one of them:

- starts with `(select auth.uid())` and raises `42501` when unauthenticated;
- re-verifies ownership by matching `user_id = auth.uid()` in the statement
  itself (not by trusting an argument) — including `p_group_id`, which is
  honoured **only** when the group belongs to the caller;
- is `SECURITY DEFINER` **with `SET search_path = ''`** (schema-hijack safe);
- is `EXECUTE`-granted **only to `authenticated`** — `anon` and `public` are
  revoked;
- returns only `jsonb` of audit-safe columns, so **ciphertext is not even
  serialisable to the client**.

`key_groups` follows the same shape as `api_keys`: RLS on, a **SELECT-only**
policy scoped to `auth.uid()`, and no INSERT/UPDATE/DELETE policy at all.
Verified after the migration: the new group and expiry functions are granted to
`authenticated` and **not** to `anon`, and `service_get_key` — which now
enforces expiry — gained no client grant.

### 4. Frontend hygiene

- Decrypted values live in an in-memory `Map` only.
- Revealed keys auto-hide after 30s, and immediately when the tab is hidden.
- Keys are never placed in the URL, `localStorage`, `sessionStorage`, or the
  console.
- All user-controlled strings are rendered with `textContent`, never
  `innerHTML` — stored XSS is not possible via labels or descriptions.
- No `service_role` key, no `.env` secrets, no plaintext key in the bundle.

### Connectivity check (Test button)

Each card has a **Test** button that confirms the key genuinely works against
its provider. It cannot be done from the browser directly: provider APIs do not
send CORS headers, and a key must never be put in a URL where it leaks into
access logs and history. So a small Edge Function performs the call.

**Flow**

1. The browser sends `supabase.functions.invoke('test-api-key', { key_id })`.
   It sends **only the id** — never the API key.
2. The function is deployed with `verify_jwt = true`, so a valid user session
   is required to reach it at all.
3. It creates a client carrying the caller's JWT, so every query runs as that
   user under RLS.
4. It calls [`get_api_key_secret(p_id)`](supabase-schema.sql:148) to decrypt the
   key. That function re-verifies `user_id = auth.uid()` internally, so the
   caller can only ever decrypt their **own** key.
5. It probes the provider, passing the key **only** as an `Authorization:`
   header, and interprets the response:
   - `2xx/3xx` → valid
   - `401/403` → rejected (the provider's own message is surfaced)
   - `429` → valid but throttled
   - network/DNS/TLS failure → reported as unreachable, not as a bad key
6. The result is stored via [`record_api_key_check()`](supabase-schema.sql:174)
   and returns over Realtime, so the verdict appears on your phone and iPad too.

**Probe endpoint.** Defaults to `GET /models` — the lightest read-only call and
the de-facto convention across OpenAI-compatible providers. If a provider does
not expose it, the honest result is `404 (the key was not rejected, but this
probe endpoint did not match)` rather than a false pass or fail. Change
[`TEST_PROBE_PATH`](config.js:31) to probe a different endpoint; the server
validates it strictly as a relative path.

**SSRF protection.** The function never accepts a caller-supplied host. It
builds the target from the row's own `api_base_url` (or a known provider
default) plus a validated relative path, and refuses anything that is not
`https` on a public host — blocking `localhost`, `127.0.0.1`, `10.x`, `172.16–31.x`,
`192.168.x`, `169.254.x`, IPv6 literals and `.internal` names.

**Response hygiene.** Upstream bodies are truncated to 4 KB, and the key plus
anything matching a credential pattern is replaced with `[redacted]` before the
snippet is returned or logged. The key is never written to the function log.

**Default base URLs** are assumed for `AgentRouter`, `TokenHarbor` and `SeekAI`
(see [`PROVIDER_BASE_URLS`](supabase/functions/test-api-key/index.ts:39)). If a
provider's real host differs, set the key's **API Base URL** in the app and the
stored value takes precedence — `Custom` keys require one.

## Usage tracking

Route a client through the vault and every request is measured. This is
server-side: the real key stays in the database and is never handed to the
caller.

**Set it up**

1. Open **Account**, create a **proxy token**, and choose the key it may reach.
   The token is shown once and stored only as a SHA-256 hash.
2. Point any OpenAI-compatible client at the proxy, using the token as its API
   key:

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://hszumyzujgnjvetvnben.supabase.co/functions/v1/ai-proxy/v1",
    api_key="kv_...",          # the vault proxy token, not the provider key
)

client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello"}],
)
```

```bash
curl https://hszumyzujgnjvetvnben.supabase.co/functions/v1/ai-proxy/v1/chat/completions \
  -H "Authorization: Bearer kv_..." \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}'
```

3. The **Usage** view fills in: request count, tokens, estimated spend, spend by
   key and by model, and a table of recent requests.

**Why a token rather than the key**

| Property | Effect |
|---|---|
| Bound to one key at creation | The caller never names a key, so it cannot reach another |
| Stored as a SHA-256 hash | A database leak does not yield usable tokens |
| Revocable in one click | Kill a compromised client without rotating the real key |
| `token_hash` not granted to clients | Even a signed-in user cannot read it |

**What is and is not stored.** Counts, model, status, latency and estimated cost
are recorded. **Prompt and completion text is never persisted** — the body is
read only to count tokens when the provider does not report usage.

**Non-JSON responses are treated as failures.** A provider that answers with
HTML has not served the request — bot and WAF checks, CDN interstitials and
captive portals all return a `200` with an HTML body. Treating that as success
would log a fabricated token count and a cost for a request no model ever saw,
so any non-JSON response is recorded as a failure with the cause named, and
tokens and cost are left blank.

**Cost is estimated.** Figures come from `model_pricing`, seeded with
approximate public list prices. Providers change prices and add models, so an
unrecognised model records tokens with the cost left blank rather than guessing.
Correct the row in `public.model_pricing` to improve accuracy.

---

## Provider URLs

Configured defaults, each confirmed to speak the OpenAI-compatible API shape:

| Provider | Base URL |
|---|---|
| AgentRouter | `https://agentrouter.org/v1` |
| TokenHarbor | `https://tokenharbor.ai/v1` |
| SeekAI | `https://seekai.cc/v1` |

All three answer `/v1/models` and `/v1/chat/completions` with a JSON
authentication error rather than a 404, which is how the endpoint shape was
established.

The value is also **auto-learned**. Save one key with a different URL and it is
remembered for that provider, then pre-filled next time. Resolution order is:

1. a URL you already saved for that provider (`user_provider_urls`),
2. a URL already used by one of your keys of that provider,
3. the default in [`config.js`](config.js:41).

Your own saved value always wins.

### Known limitation: AgentRouter blocks server-side requests

Tested directly, **AgentRouter returns an HTTP 200 with an HTML CAPTCHA page**
when called from a datacenter IP — its Aliyun WAF rejects cloud and server
traffic and expects a real browser. That is a deliberate policy on their side,
not a bug here, and no amount of retrying will get around it.

The consequence is honest and specific: validation and proxied calls to
AgentRouter report a failure explaining exactly that, rather than a false
pass. TokenHarbor and SeekAI connect correctly and do serve requests.

If you need AgentRouter through the vault, the practical options are their own
documented allowance for server clients, or routing from an IP range their WAF
permits.

---

### Verified behaviour

These were executed against the live database (inside rolled-back
transactions, so no test data remains):

| Test | Result |
|---|---|
| Encrypt → decrypt round-trip | `sk-test-1234567890` recovered exactly; 84–86 byte ciphertext |
| User A creates and reveals own key | passed — `rows_visible_to_a = 1` |
| User B reads user A's rows | passed — `rows_visible_to_b = 0` |
| User B calls `get_api_key_secret` on A's key | blocked — `API key not found` |
| Anonymous (logged out) SELECT | blocked — `permission denied for table api_keys` |
| Anonymous RPC call | blocked — `permission denied for function create_api_key` |
| Duplicate group name in one account | blocked by `key_groups_user_name_key` |
| Expired key resolved by the proxy | `expired: true`, and **`secret` withheld** (`null`) |
| Key with no expiry, same path | `secret` returned as normal |
| Group / expiry RPC grants | `authenticated` only — `anon` revoked |
| `service_get_key` grants | unchanged — no client role |

The expiry and group checks were run inside a rolled-back transaction, so no
test rows remain.

Connectivity-check tests against the deployed function:

| Test | Result |
|---|---|
| Invalid key vs. a real provider (`api.openai.com`) | reached provider, surfaced its own `401` message |
| Plaintext key echoed back in the response | `leaked_key_in_response = False` |
| Private target (`https://127.0.0.1/v1`) | refused — "https required, private addresses blocked" |
| Custom key with no base URL | clear error plus an actionable hint |
| Unknown / non-owned key id | `404 API key not found` (RLS-scoped) |

Usage-tracking tests against the deployed proxy:

| Test | Result |
|---|---|
| No token supplied | `401 Missing or malformed proxy token` |
| Bogus token | `401 Invalid or revoked proxy token` |
| Valid token, key with no base URL | `400` with an actionable message, not a silent guess |
| Valid token, real provider, invalid key | reached the provider's correct endpoint; `401` returned verbatim, key masked |
| Signed-in user calls any `service_*` function | blocked |
| Signed-in user selects `proxy_tokens.token_hash` | blocked |
| Usage row recorded after a proxied call | yes — status, tokens, latency persisted; cost left blank for an invalid key |

---

## Database

Live schema reference: [`supabase-schema.sql`](supabase-schema.sql:1).

```
auth.users
   │ 1:N (on delete cascade)
   ├───────────────────────────────┐
   ▼                               ▼
public.api_keys ── id, user_id, provider, label, description,
                   api_base_url, key_ciphertext (bytea, AES-256),
                   key_last4, key_fingerprint (sha256),
                   expires_at (NULL = never expires),
                   group_id (NULL = ungrouped), created_at, updated_at,
                   last_check_at, last_check_ok, last_check_status,
                   last_check_message
                        │
                        │ N:1  ON DELETE SET NULL
                        ▼
            public.key_groups ── id, user_id, name, color,
                                 created_at, updated_at
                                 unique (user_id, lower(btrim(name)))

private.app_secrets ── id, secret (never exposed via the API)
```

`key_fingerprint` is a SHA-256 of the plaintext, useful for detecting duplicate
keys without decrypting anything. `key_last4` powers the masked display.

Deleting a group **never** deletes a key: `group_id` is `ON DELETE SET NULL`, so
the key survives as ungrouped.

---

## Project structure

```
├── index.html            # Markup: auth screen, app screen, dialogs
├── styles.css            # Mobile-first styles, light + dark, responsive
├── app.js                # Auth, CRUD, groups, expiry, bulk, search, Realtime
├── config.js             # Public Supabase URL + publishable key, presets
├── group-palette.js      # Group colour names → OKLCH hues (shared mapping)
├── supabase-schema.sql   # Documented snapshot of the deployed database
├── smoke-test.ps1        # End-to-end auth + CRUD test
├── test-function.ps1     # End-to-end test of the connectivity-check function
├── supabase/
│   ├── config.toml
│   └── functions/
│       ├── test-api-key/
│       │   ├── index.ts  # Server-side provider probe (validate a key)
│       │   └── deno.json
│       └── ai-proxy/
│           ├── index.ts  # Routes provider traffic, measures usage and cost
│           └── deno.json
└── README.md
```

---

## How to use

1. **Sign up** with an email and a password (6+ characters).
2. Confirm your email if confirmation is enabled, then **log in**.
3. Tap **Add key**, choose a provider, paste the key, and optionally add a
   label, description, base URL, **group** and **expiry**.
4. The key is encrypted server-side and appears masked as
   `••••••••••••••••XXXX`.
5. **Reveal** decrypts it for 30 seconds. **Copy** copies it to the clipboard
   without displaying it. **Validate** checks it against the provider. **Edit**
   changes metadata — including group and expiry — and optionally rotates the
   key. **Delete** removes it permanently. The validation control and status
   pill show the last verdict.
6. Tick several keys to open the **bulk bar**, then assign a group, set an
   expiry, validate them all, export, or delete in one pass.
7. Open the app on another device with the same account — keys **and groups**
   appear there, and edits propagate live via Realtime.

---

## Testing

[`smoke-test.ps1`](smoke-test.ps1:1) exercises the real REST/Auth API — the same
path the browser uses — including encryption and decryption:

```powershell
# Full flow (sign up, create, list, reveal, update, delete) against a new throwaway account
./smoke-test.ps1

# Same flow against an existing, already-confirmed account
./smoke-test.ps1 -Email you@example.com
```

Expected output:

```
LOGIN={"has_token":true}
CREATE={"provider":"TokenHarbor","returned_fields":"id,label,provider,key_last4,...","last4":"ABCD"}
LIST={"count":1,"has_ciphertext":false}     <-- ciphertext never leaves the database
REVEAL={"exact_match":true}                 <-- decrypt round-trip is lossless
UPDATE={"label":"Renamed","provider":"SeekAI","key_unchanged":true}
DELETE={"remaining":0}
RESULT=DONE
```

Delete throwaway accounts afterwards from
Dashboard → **Authentication → Users**.

[`test-function.ps1`](test-function.ps1:1) exercises the deployed
connectivity-check function, including its guard rails:

```powershell
./test-function.ps1 -Email you@example.com
```

```
CASE_INVALID_KEY:      ok=False status=401   <- reached the provider, returned its own message
CASE_SSRF_BLOCK:       ok=False "https required, private addresses blocked"
CASE_NO_BASE_URL:      ok=False "No API Base URL is set..." + hint
CASE_UNKNOWN_KEY:      ok=False "API key not found"
CLEANUP remaining_keys=0
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Blank page, console shows a module/CORS error | You opened the file directly. Serve it over `http://localhost`. |
| “Check your email to confirm” after sign-up | Confirm the email, or disable *Confirm email* in the Supabase dashboard while testing. |
| Sync badge shows *Offline* | Realtime is blocked (proxy/offline). CRUD still works; data refreshes on reload. |
| Copy does nothing on `http://` over LAN | Browsers restrict the clipboard API to secure contexts. The app falls back to `execCommand`; if that fails, use **Reveal** and copy manually. |
| “permission denied for function ...” | Your session expired. Log out and back in. |
| Test says “No API Base URL is set… and this provider has no default” | Edit the key and add its API Base URL. |
| Test says “not an allowed target” | The base URL is not https, or points at a private/loopback address. |
| Test says “provider server error — the key could not be verified” | The provider is down or returned 5xx; try again later. |
| Test fails but the app works fine | The probe path (`/models`) may not exist on that provider. Adjust [`TEST_PROBE_PATH`](config.js:31). |
| A key stopped working through the proxy | It has probably expired. Check the **Expired** count on Overview and extend it. |
| “A group with that name already exists” | Group names are unique per account, compared case-insensitively. Pick another name. |

---

## Deploying

Deploy the five static files (`index.html`, `styles.css`, `app.js`, `config.js`,
`group-palette.js`) to any static host — Netlify, Vercel, Cloudflare Pages,
GitHub Pages, S3. No environment variables and no build command are required.
Remember to enable **Confirm email** in Supabase for production.

The [`test-api-key`](supabase/functions/test-api-key/index.ts:1) Edge Function is
already deployed. To redeploy after editing it:

```bash
supabase functions deploy test-api-key --project-ref hszumyzujgnjvetvnben
```

It needs no custom secrets — only the environment variables Supabase provides to
Edge Functions automatically.