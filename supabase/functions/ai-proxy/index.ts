/**
 * ai-proxy — routes provider traffic through the vault so usage and cost
 * can be recorded per key.
 *
 * Point any OpenAI-compatible client at:
 *     https://<project>.supabase.co/functions/v1/ai-proxy/v1/chat/completions
 * with the vault proxy token as the API key. The proxy swaps that token for
 * the real provider key, forwards the call, records token counts and an
 * estimated cost, then returns the provider's response unmodified.
 *
 * ─ Authentication ────────────────────────────────────────────────────
 * A proxy token (`kv_…`) is bound to exactly one key at creation. The
 * caller therefore never names a key, so it is structurally impossible for
 * a token to reach a different one. Tokens are stored only as a SHA-256
 * hash and resolve through service_resolve_proxy_token().
 *
 * ── Why verify_jwt is disabled ────────────────────────────────────────
 * Callers are non-Supabase clients (SDKs, CLIs) holding a revocable vault
 * token, not a user session JWT. Authentication happens in-code below via
 * the token hash lookup, and the function runs with the secret key purely
 * to resolve that token and decrypt its bound key. No browser and no user
 * session ever invokes this function.
 *
 * ── What is deliberately NOT stored ───────────────────────────────────
 * Prompt and completion bodies are never persisted. Only counts, model,
 * status, latency and estimated cost. Request bodies are read solely to
 * count tokens when the provider does not report usage.
 */
import { createClient } from 'npm:@supabase/supabase-js@2';

const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-proxy-token',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

/** Provider fallbacks used when the key has no base URL of its own. */
const PROVIDER_BASE_URLS: Record<string, string> = {
    AgentRouter: 'https://api.agentrouter.com/v1',
    TokenHarbor: 'https://api.tokenharbor.com/v1',
    SeekAI: 'https://api.seekai.com/v1',
    Custom: '',
};

/** This function's own slug, used to strip the routing prefix from req.url. */
const FUNCTION_SLUG = 'ai-proxy';

const UPSTREAM_TIMEOUT_MS = 120_000;
const MAX_CAPTURE_BYTES = 2_000_000;   // refuse to buffer huge responses

/* ---------------------------------------------------------------------
 * Token estimation, used only when the provider omits usage data.
 * ------------------------------------------------------------------- */
function estimateTokens(value: unknown): number {
    let text = '';
    try {
        text = typeof value === 'string' ? value : JSON.stringify(value);
    } catch {
        return 0;
    }
    // ~4 characters per token is the usual English heuristic. Deliberately
    // labelled as an estimate wherever it surfaces in the UI.
    return Math.max(0, Math.round(text.length / 4));
}

/* ---------------------------------------------------------------------
 * SSRF guards — identical policy to the validation function.
 * ------------------------------------------------------------------- */
function isAllowedTarget(url: URL): boolean {
    if (url.protocol !== 'https:') return false;

    const host = url.hostname.toLowerCase();
    if (host === 'localhost' || host.endsWith('.localhost')) return false;
    if (host === 'metadata.google.internal') return false;
    if (host.endsWith('.internal') || host.endsWith('.local')) return false;

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

    if (host.includes(':')) return false;   // reject IPv6 literals
    return true;
}

function json(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
}

/** Strip anything credential-shaped from text we might surface or log. */
function scrub(text: string, secrets: string[]): string {
    let out = text;
    for (const secret of secrets) {
        if (secret && secret.length >= 8) out = out.split(secret).join('[redacted]');
    }
    return out
        .replace(/\b(?:sk|pk|kv)[-_][A-Za-z0-9_-]{8,}\b/gi, '[redacted]')
        .replace(/\bBearer\s+[A-Za-z0-9._-]{12,}\b/gi, 'Bearer [redacted]');
}

/* ---------------------------------------------------------------------
 * Cost estimation from model_pricing.
 * ------------------------------------------------------------------- */
type Pricing = { input: number; output: number; pattern: string };

function estimateCost(
    pricing: Pricing[],
    model: string | null,
    promptTokens: number | null,
    completionTokens: number | null,
): number | null {
    if (!model || !pricing.length) return null;
    const lower = model.toLowerCase();

    // Longest matching pattern wins, so "gpt-4o-mini" beats "gpt-4o".
    const match = pricing
        .filter((row) => lower.includes(row.pattern))
        .sort((a, b) => b.pattern.length - a.pattern.length)[0];

    if (!match) return null;

    const input = ((promptTokens ?? 0) / 1_000_000) * match.input;
    const output = ((completionTokens ?? 0) / 1_000_000) * match.output;
    return Number((input + output).toFixed(6));
}

/* ---------------------------------------------------------------------
 * Request handler
 * ------------------------------------------------------------------- */
Deno.serve(async (req: Request) => {
    if (req.method === 'OPTIONS') {
        return new Response('ok', { headers: corsHeaders });
    }

    const started = Date.now();

    const supabaseUrl = Deno.env.get('SUPABASE_URL') ?? '';
    const secretKey = (() => {
        const bag = Deno.env.get('SUPABASE_SECRET_KEYS');
        if (bag) {
            try {
                const parsed = JSON.parse(bag);
                if (parsed?.default) return parsed.default as string;
            } catch { /* fall through to legacy */ }
        }
        return Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '';
    })();

    if (!supabaseUrl || !secretKey) {
        return json({ error: { message: 'Proxy is not configured.' } }, 500);
    }

    const admin = createClient(supabaseUrl, secretKey, {
        auth: { persistSession: false, autoRefreshToken: false },
    });

    /* ---- 1. Authenticate the proxy token ------------------------------ */
    const rawAuth = req.headers.get('authorization') ?? '';
    const bearer = rawAuth.toLowerCase().startsWith('bearer ')
        ? rawAuth.slice(7).trim()
        : '';
    const token = req.headers.get('x-proxy-token')?.trim() || bearer;

    if (!token || !token.startsWith('kv_')) {
        return json({ error: { message: 'Missing or malformed proxy token.', type: 'invalid_request_error' } }, 401);
    }

    const { data: resolved, error: resolveError } = await admin.rpc('service_resolve_proxy_token', {
        p_token: token,
    });

    if (resolveError) {
        console.error(JSON.stringify({ event: 'proxy_resolve_error', message: resolveError.message }));
        return json({ error: { message: 'Token lookup failed.' } }, 500);
    }
    if (!resolved) {
        return json({ error: { message: 'Invalid or revoked proxy token.', type: 'invalid_request_error' } }, 401);
    }

    const userId = resolved.user_id as string;
    const keyId = resolved.key_id as string;

    /* ---- 2. Resolve the bound key ------------------------------------ */
    const { data: keyRow, error: keyError } = await admin.rpc('service_get_key', {
        p_key_id: keyId,
        p_user_id: userId,
    });

    if (keyError || !keyRow) {
        return json({ error: { message: 'The key for this token is no longer available.' } }, 404);
    }

    const secret = keyRow.secret as string;
    const provider = (keyRow.provider as string) ?? 'Custom';

    // User-specific URL first, then the shared provider fallback.
    const { data: userUrl } = await admin.rpc('service_get_provider_url', {
        p_user_id: userId,
        p_provider: provider,
    });

    const baseUrlRaw =
        (keyRow.api_base_url as string | null)?.trim()
        || (userUrl?.base_url as string | null)
        || PROVIDER_BASE_URLS[provider]
        || '';

    if (!baseUrlRaw) {
        return json({
            error: {
                message: 'No API base URL is configured for this key. Add one in Keyvault, or use a matching provider token.',
                type: 'invalid_request_error',
            },
        }, 400);
    }

    /* ---- 3. Build the upstream URL ----------------------------------- */
    /**
     * Recover the client's API path.
     *
     * The platform strips the routing prefix before invoking the function, so
     * `req.url` arrives as `/ai-proxy/v1/chat/completions` rather than
     * `/functions/v1/ai-proxy/v1/chat/completions` — and the shape differs
     * between environments. Rather than hard-code one prefix, locate the
     * function's own slug and take everything after it. That is correct for
     * both forms and immune to the routing prefix changing.
     */
    const incoming = new URL(req.url);
    const allSegments = incoming.pathname.split('/').filter(Boolean);
    const slugIndex = allSegments.lastIndexOf(FUNCTION_SLUG);

    const clientSegments = slugIndex >= 0
        ? allSegments.slice(slugIndex + 1)
        : allSegments;

    const suffix = `/${clientSegments.join('/')}`;

    if (suffix.includes('..') || suffix.includes('//')) {
        return json({ error: { message: 'Invalid request path.' } }, 400);
    }

    let base: URL;
    try {
        base = new URL(baseUrlRaw);
    } catch {
        return json({ error: { message: 'The stored API base URL is not a valid URL.' } }, 400);
    }
    if (!isAllowedTarget(base)) {
        return json({ error: { message: 'That API base URL is not an allowed target.' } }, 400);
    }

    /**
     * Join the client path onto the stored base path without duplicating a
     * shared version segment.
     *
     * A base URL of `https://api.openai.com/v1` combined with a client path
     * of `/v1/chat/completions` must resolve to `/v1/chat/completions`, not
     * `/v1/v1/chat/completions`. Clients conventionally set their base_url to
     * `<proxy>/v1` and then append `/chat/completions`, so both forms arrive
     * and both have to work.
     */
    const baseSegments = base.pathname.split('/').filter(Boolean);
    const suffixSegments = [...clientSegments];

    if (
        baseSegments.length > 0
        && suffixSegments.length > 0
        && baseSegments[baseSegments.length - 1] === suffixSegments[0]
    ) {
        suffixSegments.shift();
    }

    const targetPath = baseSegments.length
        ? `/${[...baseSegments, ...suffixSegments].join('/')}`
        : `/${suffixSegments.join('/')}`;

    const target = new URL(targetPath, base.origin);
    target.search = incoming.search;

    if (!isAllowedTarget(target)) {
        return json({ error: { message: 'That target is not allowed.' } }, 400);
    }

    /* ---- 4. Read the body (for token counting) ----------------------- */
    const isStream = (req.headers.get('accept') ?? '').includes('text/event-stream');

    let rawBody = '';
    let parsedBody: Record<string, unknown> | null = null;
    if (req.method !== 'GET' && req.method !== 'HEAD') {
        rawBody = await req.text();
        if (rawBody) {
            try { parsedBody = JSON.parse(rawBody); } catch { parsedBody = null; }
        }
    }

    const model = typeof parsedBody?.model === 'string' ? (parsedBody.model as string) : null;

    /* ---- 5. Forward to the provider ---------------------------------- */
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

    let upstream: Response;
    try {
        upstream = await fetch(target.toString(), {
            method: req.method,
            headers: {
                // The real key travels only here, to the provider only.
                Authorization: `Bearer ${secret}`,
                'Content-Type': req.headers.get('content-type') ?? 'application/json',
                Accept: isStream ? 'text/event-stream' : (req.headers.get('accept') ?? 'application/json'),
                'User-Agent': 'Keyvault-Proxy/1.0',
            },
            body: rawBody || undefined,
            signal: controller.signal,
            redirect: 'error',
        });
    } catch (error) {
        clearTimeout(timeout);

        const message = error instanceof Error && error.name === 'AbortError'
            ? `Provider did not respond within ${UPSTREAM_TIMEOUT_MS / 1000}s.`
            : 'Could not reach the provider.';

        await record(admin, {
            user_id: userId, key_id: keyId, provider, model,
            path: suffix, status_code: 0, ok: false,
            latency_ms: Date.now() - started, error: message,
        });

        return json({ error: { message, type: 'upstream_error' } }, 502);
    }

    /* ---- 6. Pass the response through, capturing usage if JSON ------- */
    const contentType = upstream.headers.get('content-type') ?? '';

    let usage: { prompt: number | null; completion: number | null } = { prompt: null, completion: null };
    let responseBody: ArrayBuffer | null = null;

    if (!isStream && contentType.includes('application/json')) {
        const buffer = await upstream.arrayBuffer();
        if (buffer.byteLength <= MAX_CAPTURE_BYTES) {
            responseBody = buffer;
            try {
                const text = new TextDecoder().decode(buffer);
                const payload = JSON.parse(text);
                const reported = payload?.usage;
                if (reported) {
                    usage.prompt = Number.isFinite(reported.prompt_tokens) ? reported.prompt_tokens : null;
                    usage.completion = Number.isFinite(reported.completion_tokens) ? reported.completion_tokens : null;
                }
            } catch { /* non-JSON body — leave usage empty */ }
        }
    }

    clearTimeout(timeout);

    // Fall back to estimation only when the provider reported nothing.
    if (usage.prompt === null && parsedBody) {
        usage.prompt = estimateTokens({
            messages: parsedBody.messages,
            prompt: parsedBody.prompt,
            input: parsedBody.input,
        });
    }
    if (usage.completion === null && responseBody) {
        try {
            const payload = JSON.parse(new TextDecoder().decode(responseBody));
            const choiceText = payload?.choices?.[0]?.message?.content ?? payload?.choices?.[0]?.text;
            if (choiceText) usage.completion = estimateTokens(choiceText);
        } catch { /* leave null */ }
    }

    const total = (usage.prompt ?? 0) + (usage.completion ?? 0) || null;

    /* ---- 7. Price it and record the row ----------------------------- */
    const { data: pricingRows } = await admin
        .from('model_pricing')
        .select('model_pattern, input_usd_per_mtok, output_usd_per_mtok');

    const pricing: Pricing[] = (pricingRows ?? []).map((row: Record<string, unknown>) => ({
        pattern: String(row.model_pattern ?? '').toLowerCase(),
        input: Number(row.input_usd_per_mtok) || 0,
        output: Number(row.output_usd_per_mtok) || 0,
    }));

    const cost = upstream.ok
        ? estimateCost(pricing, model, usage.prompt, usage.completion)
        : null;

    const errorText = upstream.ok
        ? null
        : scrub(new TextDecoder().decode(responseBody ?? new ArrayBuffer(0)).slice(0, 300) || upstream.statusText, [secret]);

    await record(admin, {
        user_id: userId,
        key_id: keyId,
        provider,
        model,
        path: suffix,
        status_code: upstream.status,
        ok: upstream.ok,
        prompt_tokens: usage.prompt,
        completion_tokens: usage.completion,
        total_tokens: total,
        cost_usd: cost,
        latency_ms: Date.now() - started,
        error: errorText,
    });

    /* ---- 8. Return the provider response unmodified ----------------- */
    console.log(JSON.stringify({
        event: 'proxy_request',
        user: userId,
        key_id: keyId,
        provider,
        model,
        status: upstream.status,
        total_tokens: total,
        cost_usd: cost,
        latency_ms: Date.now() - started,
    }));

    if (isStream || !responseBody) {
        // Streaming or oversized: relay the stream untouched.
        return new Response(upstream.body, {
            status: upstream.status,
            headers: {
                ...corsHeaders,
                'Content-Type': contentType || 'application/json',
            },
        });
    }

    return new Response(responseBody, {
        status: upstream.status,
        headers: { ...corsHeaders, 'Content-Type': contentType || 'application/json' },
    });
});

/* ---------------------------------------------------------------------
 * Insert a usage row. Failures here must never break the proxied call,
 * so errors are logged and swallowed.
 * ------------------------------------------------------------------- */
async function record(
    admin: ReturnType<typeof createClient>,
    row: Record<string, unknown>,
): Promise<void> {
    try {
        const { error } = await admin.from('usage_events').insert(row);
        if (error) {
            console.error(JSON.stringify({ event: 'usage_insert_error', message: error.message }));
        }
    } catch (error) {
        console.error(JSON.stringify({
            event: 'usage_insert_threw',
            message: error instanceof Error ? error.message : String(error),
        }));
    }
}