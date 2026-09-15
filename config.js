/**
 * Public client configuration.
 *
 * Only the publishable/anon key belongs here. It is DESIGNED to be public:
 * it grants no privileges by itself. All data access is gated by Row Level
 * Security, so an anonymous visitor with this key sees zero rows.
 *
 * NEVER put the service_role / secret key in this file or anywhere in the
 * frontend. Doing so would bypass every RLS policy in the database.
 */
export const SUPABASE_URL = 'https://hszumyzujgnjvetvnben.supabase.co';
export const SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_ZykahRBEZrE3FoQ0BdvaDw_oHRoamki';

/** Providers offered in the UI. "Custom" allows adding anything else. */
export const PROVIDERS = ['AgentRouter', 'TokenHarbor', 'SeekAI', 'Custom'];

/** How long (ms) a revealed key stays visible before auto-hiding. */
export const REVEAL_TIMEOUT_MS = 30_000;

/**
 * Server-side probe used by the validate action.
 *
 * The browser never sends the API key. It sends only the key's id, and the
 * Edge Function decrypts the key inside the database, checks ownership via
 * RLS, and calls the provider from the server — which also sidesteps the
 * browser's cross-origin restrictions. The key is passed upstream only as
 * an Authorization header, never in a URL.
 */
export const TEST_FUNCTION_NAME = 'test-api-key';

/**
 * Relative endpoint probed to confirm a key works. Defaults to the models
 * listing — the lightest read-only call and the de-facto convention across
 * OpenAI-compatible providers. All three supported providers expose it.
 */
export const TEST_PROBE_PATH = '/models';

/**
 * API base URLs for the supported providers.
 *
 * Verified reachable: each of these answers `/v1/models` and
 * `/v1/chat/completions` with a JSON authentication error rather than a 404,
 * confirming the endpoint shape (OpenAI-compatible).
 *
 * You rarely need to edit this. Saving a key with a URL stores it per
 * provider in public.user_provider_urls, and your saved value always takes
 * precedence over the default here.
 */
export const PROVIDER_BASE_URLS = {
    AgentRouter: 'https://agentrouter.org/v1',
    TokenHarbor: 'https://tokenharbor.ai/v1',
    SeekAI: 'https://seekai.cc/v1',
    Custom: '',
};

/**
 * The defaults above are verified reachable, so the interface no longer
 * needs to label them as unverified guesses. Set back to true if you change
 * them to a host you have not confirmed.
 */
export const PROVIDER_URLS_ARE_PLACEHOLDERS = false;

/**
 * Server-side proxy that routes provider traffic so usage and cost can be
 * recorded per key. Point any OpenAI-compatible client at
 * `<SUPABASE_URL>/functions/v1/ai-proxy/v1/...` using a vault proxy token.
 */
export const PROXY_FUNCTION_NAME = 'ai-proxy';

/** How many recent requests to list in the Usage view. */
export const USAGE_PAGE_SIZE = 25;