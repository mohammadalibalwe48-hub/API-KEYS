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
 * listing, the lightest read-only call and the de-facto convention across
 * OpenAI-compatible providers.
 */
export const TEST_PROBE_PATH = '/models';

/**
 * Default API base URLs.
 *
 * IMPORTANT — THESE ARE UNVERIFIED PLACEHOLDERS. They are not confirmed
 * vendor endpoints. They exist so the form can pre-fill something rather
 * than nothing, and so a probe has a target out of the box.
 *
 * You do not have to maintain this list: save a key once with the correct
 * URL and the app stores it per provider in public.user_provider_urls, then
 * pre-fills it automatically from then on. Your saved value always wins
 * over the value here.
 *
 * To replace these permanently, edit the constants below.
 */
export const PROVIDER_BASE_URLS = {
    AgentRouter: 'https://api.agentrouter.com/v1',
    TokenHarbor: 'https://api.tokenharbor.com/v1',
    SeekAI: 'https://api.seekai.com/v1',
    Custom: '',
};

/**
 * Flags the defaults above as unverified, so the interface says so plainly
 * instead of presenting a guess as fact. Set to false once the URLs are
 * confirmed.
 */
export const PROVIDER_URLS_ARE_PLACEHOLDERS = true;

/**
 * Server-side proxy that routes provider traffic so usage and cost can be
 * recorded per key. Point any OpenAI-compatible client at
 * `<SUPABASE_URL>/functions/v1/ai-proxy/v1/...` using a vault proxy token.
 */
export const PROXY_FUNCTION_NAME = 'ai-proxy';

/** How many recent requests to list in the Usage view. */
export const USAGE_PAGE_SIZE = 25;