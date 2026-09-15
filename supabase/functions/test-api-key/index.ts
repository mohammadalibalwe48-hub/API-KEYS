/**
 * test-api-key — server-side proxy that verifies a stored API key actually
 * works against its provider.
 *
 * Why a proxy is required:
 *   - Browsers block cross-origin calls to most provider APIs (CORS).
 *   - A key must never be placed in a URL/query string where it leaks into
 *     access logs and browser history. It travels only as an Authorization
 *     header, set here, server-side.
 *
 * Security model:
 *   - verify_jwt is left ON, so only a signed-in user with a valid session
 *     JWT can invoke this function at all.
 *   - The caller sends ONLY a key id. It never sends the API key.
 *   - The plaintext key is decrypted inside the database by
 *     public.get_api_key_secret(), which re-verifies ownership against
 *     auth.uid() and is granted only to the `authenticated` role. The
 *     user-scoped client below therefore inherits exactly the caller's
 *     RLS permissions and cannot read another user's key.
 *   - The upstream target is built from the row's OWN api_base_url (or a
 *     known provider default) plus a strictly-validated relative path, so
 *     this cannot be used as an open proxy / SSRF pivot.
 *   - The upstream response is truncated and scrubbed; the key is never
 *     logged, echoed, or returned.
 */

import { createClient } from 'npm:@supabase/supabase-js@2';

const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

/** Known provider defaults, used when the row has no api_base_url. */
const PROVIDER_BASE_URLS: Record<string, string> = {
    AgentRouter: 'https://api.agentrouter.com/v1',
    TokenHarbor: 'https://api.tokenharbor.com/v1',
    SeekAI: 'https://api.seekai.com/v1',
    Custom: '',
};

/** Time budget for the upstream provider call. */
const UPSTREAM_TIMEOUT_MS = 12_000;
/** Hard cap on how much of the provider body we look at / return. */
const MAX_BODY_CHARS = 4_000;
/** How much of the (scrubbed) body we send back to the browser. */
const SNIPPET_CHARS = 400;

type Probe = {
    method: 'GET' | 'POST';
    path: string;
    body?: unknown;
};

function json(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
}

/**
 * Accept only a same-origin relative path. Rejects absolute URLs, protocol
 * handlers, traversal, and control characters.
 */
function safeRelativePath(raw: unknown, fallback: string): string | null {
    if (raw === undefined || raw === null || raw === '') return fallback;
    if (typeof raw !== 'string') return null;

    const trimmed = raw.trim();
    if (trimmed.length > 120) return null;
    if (!/^\/[A-Za-z0-9._\-/]*$/.test(trimmed)) return null;   // no scheme, no query, no spaces
    if (trimmed.includes('..')) return null;
    if (trimmed.includes('//')) return null;
    return trimmed;
}

/**
 * Block SSRF targets: private, loopback, link-local and unique-local ranges,
 * plus non-https schemes and localhost aliases.
 */
function isAllowedTarget(url: URL): boolean {
    if (url.protocol !== 'https:') return false;

    const host = url.hostname.toLowerCase();
    if (host === 'localhost' || host.endsWith('.localhost')) return false;
    if (host === 'metadata.google.internal') return false;
    if (host.endsWith('.internal') || host.endsWith('.local')) return false;

    // IPv4 literal in a private / loopback / link-local range.
    const v4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (v4) {
        const [a, b] = v4.slice(1).map(Number);
        if (v4.slice(1).some((n) => Number(n) > 255)) return false;
        if (a === 10 || a === 127 || a === 0) return false;
        if (a === 169 && b === 254) return false;
        if (a === 172 && b >= 16 && b <= 31) return false;
        if (a === 192 && b === 168) return false;
        return true;
    }

    // IPv6 literals (including bracketed forms): reject all to be safe.
    if (host.includes(':')) return false;

    return true;
}

/**
 * Remove anything resembling a credential from text we intend to surface.
 */
function scrub(text: string, secrets: string[]): string {
    let out = text;
    for (const secret of secrets) {
        if (secret && secret.length >= 8) out = out.split(secret).join('[redacted]');
    }
    return out
        .replace(/\b(?:sk|pk|api|key|token)[-_][A-Za-z0-9_-]{8,}\b/gi, '[redacted]')
        .replace(/\bBearer\s+[A-Za-z0-9._-]{12,}\b/gi, 'Bearer [redacted]');
}

function toSnippet(text: string): string {
    const cleaned = text.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
    return cleaned.slice(0, SNIPPET_CHARS);
}

/**
 * Pull a concise human-readable reason out of a provider error body.
 */
function extractReason(status: number, text: string): string {
    if (text) {
        try {
            const parsed = JSON.parse(text);
            const candidates = [
                parsed?.error?.message,
                parsed?.error?.type,
                parsed?.error,
                parsed?.message,
                parsed?.detail,
                parsed?.error_description,
            ];
            for (const candidate of candidates) {
                if (typeof candidate === 'string' && candidate.trim()) {
                    return toSnippet(candidate);
                }
            }
        } catch {
            const snippet = toSnippet(text);
            if (snippet) return snippet;
        }
    }
    if (status === 401) return 'Provider rejected the key as unauthorized.';
    if (status === 403) return 'The key is valid but lacks permission for this endpoint.';
    if (status === 404) return 'Endpoint not found — check the API Base URL.';
    if (status === 429) return 'Rate limited, but the key was accepted.';
    if (status >= 500) return 'Provider server error — the key could not be verified.';
    return `Provider responded with HTTP ${status}.`;
}

Deno.serve(async (req: Request) => {
    if (req.method === 'OPTIONS') {
        return new Response('ok', { headers: corsHeaders });
    }
    if (req.method !== 'POST') {
        return json({ ok: false, error: 'Method not allowed' }, 405);
    }

    // Read the API key from the environment, supporting both the new
    // publishable keys and the legacy anon JWT.
    const supabaseUrl = Deno.env.get('SUPABASE_URL') ?? '';
    const anonKey = (() => {
        const publishable = Deno.env.get('SUPABASE_PUBLISHABLE_KEYS');
        if (publishable) {
            try {
                const parsed = JSON.parse(publishable);
                if (parsed?.default) return parsed.default as string;
            } catch { /* fall through to legacy */ }
        }
        return Deno.env.get('SUPABASE_ANON_KEY') ?? '';
    })();

    const authHeader = req.headers.get('Authorization') ?? '';
    if (!authHeader.startsWith('Bearer ')) {
        return json({ ok: false, error: 'Missing authorization header' }, 401);
    }

    let keyId: string | undefined;
    let requestedPath: unknown;
    try {
        const payload = await req.json();
        keyId = payload?.key_id ?? payload?.p_id;
        requestedPath = payload?.path;
    } catch {
        return json({ ok: false, error: 'Invalid JSON body' }, 400);
    }

    const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (typeof keyId !== 'string' || !uuidRe.test(keyId)) {
        return json({ ok: false, error: 'A valid key_id is required' }, 400);
    }

    // User-scoped client: every query below runs with the caller's JWT,
    // so RLS and the RPC ownership checks apply to them, not to the server.
    const supabase = createClient(supabaseUrl, anonKey, {
        global: { headers: { Authorization: authHeader } },
        auth: { persistSession: false, autoRefreshToken: false },
    });

    // Confirm the JWT is genuinely valid (and get the user for the log line).
    const { data: userData, error: userError } = await supabase.auth.getUser();
    if (userError || !userData?.user) {
        return json({ ok: false, error: 'Invalid or expired session' }, 401);
    }

    // Metadata for the target URL. RLS restricts this to the caller's rows.
    const { data: rows, error: rowError } = await supabase
        .from('api_keys')
        .select('id, provider, api_base_url')
        .eq('id', keyId)
        .maybeSingle();

    if (rowError) {
        return json({ ok: false, error: 'Could not load the key' }, 400);
    }
    if (!rows) {
        return json({ ok: false, error: 'API key not found' }, 404);
    }

    // Decrypt, on demand, inside Postgres. Ownership is re-verified there.
    const { data: secret, error: secretError } = await supabase.rpc('get_api_key_secret', {
        p_id: keyId,
    });
    if (secretError || typeof secret !== 'string' || !secret) {
        return json({ ok: false, error: 'Could not decrypt the key' }, 400);
    }

    // --- Build the upstream target -------------------------------------
    const baseUrlRaw = (rows.api_base_url as string | null)?.trim()
        || PROVIDER_BASE_URLS[rows.provider as string]
        || '';
    if (!baseUrlRaw) {
        return json({
            ok: false,
            error: 'No API Base URL is set for this key, and this provider has no default.',
            hint: 'Edit the key and add its API Base URL (for example https://api.example.com/v1).',
        }, 400);
    }

    let base: URL;
    try {
        base = new URL(baseUrlRaw);
    } catch {
        return json({ ok: false, error: 'The stored API Base URL is not a valid URL.' }, 400);
    }
    if (!isAllowedTarget(base)) {
        return json({ ok: false, error: 'That API Base URL is not an allowed target (https required, private addresses blocked).' }, 400);
    }

    const probe = buildProbe(rows.provider as string, requestedPath);
    if (!probe) {
        return json({ ok: false, error: 'Invalid probe path.' }, 400);
    }

    const target = new URL(
        base.pathname.replace(/\/+$/, '') + probe.path.replace(/^\/+/, '/'),
        base.origin,
    );
    if (!isAllowedTarget(target)) {
        return json({ ok: false, error: 'That target is not allowed.' }, 400);
    }

    // --- Call the provider ---------------------------------------------
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

    let status = 0;
    let bodyText = '';
    let networkError: string | null = null;

    try {
        const upstream = await fetch(target.toString(), {
            method: probe.method,
            headers: {
                // The key goes ONLY here — never in the URL, never in logs.
                Authorization: `Bearer ${secret}`,
                Accept: 'application/json',
                ...(probe.body ? { 'Content-Type': 'application/json' } : {}),
                'User-Agent': 'KeyVault/1.0 (key-connectivity-check)',
            },
            body: probe.body ? JSON.stringify(probe.body) : undefined,
            signal: controller.signal,
            redirect: 'error',
        });

        status = upstream.status;
        const raw = (await upstream.text()).slice(0, MAX_BODY_CHARS);
        bodyText = scrub(raw, [secret]);
    } catch (error) {
        networkError = error instanceof Error && error.name === 'AbortError'
            ? `No response within ${UPSTREAM_TIMEOUT_MS / 1000}s.`
            : 'Could not reach the provider (DNS, TLS, or network failure).';
    } finally {
        clearTimeout(timeout);
    }

    // --- Interpret the result ------------------------------------------
    let ok: boolean;
    let message: string;

    if (networkError) {
        ok = false;
        message = networkError;
    } else if (status === 401 || status === 403) {
        ok = false;
        message = extractReason(status, bodyText);
    } else if (status === 429) {
        ok = true;                       // reachable, key accepted, just throttled
        message = extractReason(status, bodyText);
    } else if (status >= 200 && status < 400) {
        ok = true;
        message = 'Key is valid and the provider responded successfully.';
    } else if (status === 404 || status === 405) {
        // Reachable and not rejected for auth: the endpoint differs, key is
        // very likely fine. Report honestly rather than claiming success.
        ok = false;
        message = `${extractReason(status, bodyText)} (The key was not rejected, but this probe endpoint did not match.)`;
    } else {
        ok = false;
        message = extractReason(status, bodyText);
    }

    // Persist the outcome so it syncs to the user's other devices.
    // Failure to persist must not mask the probe result.
    await supabase.rpc('record_api_key_check', {
        p_id: keyId,
        p_ok: ok,
        p_status: status || null,
        p_message: message,
    });

    // Never log the key. Only the non-sensitive identifiers.
    console.log(
        JSON.stringify({
            event: 'key_test',
            user: userData.user.id,
            key_id: keyId,
            provider: rows.provider,
            status,
            ok,
        }),
    );

    return json({
        ok,
        status: status || null,
        message,
        snippet: networkError ? null : toSnippet(bodyText) || null,
        checked_at: new Date().toISOString(),
    });
});

/**
 * Choose the probe request. The path is either the safe default for the
 * provider or a validated relative path supplied by the client.
 */
function buildProbe(provider: string, requestedPath: unknown): Probe | null {
    const fallback = '/models';
    const path = safeRelativePath(requestedPath, fallback);
    if (path === null) return null;

    // A models listing is the lightest read-only call and is the de-facto
    // convention across OpenAI-compatible providers. If it is not available,
    // the caller can pass a different safe relative path.
    if (path === '/chat/completions' || path === '/completions') {
        return {
            method: 'POST',
            path,
            body: {
                model: 'gpt-3.5-turbo',
                messages: [{ role: 'user', content: 'ping' }],
                max_tokens: 1,
            },
        };
    }

    void provider;
    return { method: 'GET', path };
}