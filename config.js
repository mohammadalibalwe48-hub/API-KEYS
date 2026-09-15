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
 * Server-side probe used by the "Test" button.
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