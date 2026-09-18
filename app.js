/**
 * Keyvault — AI API key manager
 * ---------------------------------------------------------------------
 * SECURITY MODEL (unchanged by the redesign)
 *
 *  · Only the publishable key ships to the browser. No service-role key
 *    exists anywhere in the frontend.
 *  · Key metadata is read directly, filtered by RLS, which restricts rows
 *    to the signed-in user.
 *  · Create, update, delete and decrypt all pass through Postgres RPCs
 *    (SECURITY DEFINER) that re-verify ownership in the database.
 *  · Live validation calls an Edge Function with the key *id* only. The
 *    plaintext is decrypted server-side and sent to the provider solely as
 *    an Authorization header — never in a URL, never to the browser.
 *  · Plaintext is held in memory for a 30 second reveal, and is never
 *    written to storage, the URL, the console, or the document markup.
 *  · Every user-controlled string is rendered with textContent, so stored
 *    content cannot inject markup.
 */
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.45.4';
import {
    SUPABASE_URL,
    SUPABASE_PUBLISHABLE_KEY,
    PROVIDERS,
    REVEAL_TIMEOUT_MS,
    TEST_FUNCTION_NAME,
    TEST_PROBE_PATH,
    PROVIDER_BASE_URLS,
    PROVIDER_URLS_ARE_PLACEHOLDERS,
    PROXY_FUNCTION_NAME,
    USAGE_PAGE_SIZE,
    EXPIRY_PRESETS,
    EXPIRY_WARNING_DAYS,
    GROUP_COLORS,
    EXPORT_FILENAME_PREFIX,
} from './config.js';
import { groupHueStyle, GROUP_COLOR_LABELS } from './group-palette.js';

const supabase = createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
    auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: false },
});

/* ==================================================================== *
 * Constants
 * ==================================================================== */
const MASK = '•'.repeat(16);
const THEME_KEY = 'keyvault-theme';
const SEARCH_DEBOUNCE_MS = 130;

const KEY_COLUMNS = [
    'id', 'provider', 'label', 'description', 'api_base_url',
    'key_last4', 'key_fingerprint',
    'last_check_at', 'last_check_ok', 'last_check_status', 'last_check_message',
    'expires_at', 'group_id',
    'created_at', 'updated_at',
].join(', ');

const GROUP_COLUMNS = [
    'id', 'name', 'color', 'created_at', 'updated_at',
].join(', ');

const TOKEN_COLUMNS = [
    'id', 'key_id', 'name', 'token_hint', 'last_used_at', 'revoked_at', 'created_at',
].join(', ');

const USAGE_COLUMNS = [
    'id', 'key_id', 'provider', 'model', 'path', 'status_code', 'ok',
    'prompt_tokens', 'completion_tokens', 'total_tokens',
    'cost_usd', 'latency_ms', 'error', 'created_at',
].join(', ');

const VIEWS = {
    overview: { title: 'Overview', subtitle: 'A summary of every key you hold.' },
    keys: { title: 'API keys', subtitle: 'Stored, encrypted and validated on demand.' },
    usage: { title: 'Usage', subtitle: 'Requests routed through the vault, and what they cost.' },
    account: { title: 'Account', subtitle: 'Your identity, proxy tokens and workspace preferences.' },
};

/* ==================================================================== *
 * Element references
 * ==================================================================== */
const $ = (id) => document.getElementById(id);

const el = {
    // Auth
    auth: $('auth'),
    tabLogin: $('tab-login'),
    tabSignup: $('tab-signup'),
    panelLogin: $('panel-login'),
    panelSignup: $('panel-signup'),
    loginEmail: $('login-email'),
    loginPassword: $('login-password'),
    signupEmail: $('signup-email'),
    signupPassword: $('signup-password'),
    loginError: $('login-error'),
    signupError: $('signup-error'),

    // Shell
    app: $('app'),
    viewTitle: $('view-title'),
    viewSubtitle: $('view-subtitle'),
    sync: $('sync'),
    syncLabel: $('sync-label'),
    railKeyCount: $('nav-key-count'),
    railAvatar: $('rail-avatar'),
    railEmail: $('rail-email'),
    accountAvatar: $('account-avatar'),
    accountEmail: $('account-email'),
    accountId: $('account-id'),

    // Views
    viewOverview: $('view-overview'),
    viewKeys: $('view-keys'),
    viewUsage: $('view-usage'),
    viewAccount: $('view-account'),
    stats: $('stats'),
    providerBreakdown: $('provider-breakdown'),
    activity: $('activity'),
    expiringPanel: $('panel-expiring'),
    expiring: $('expiring'),

    // Usage
    usageStats: $('usage-stats'),
    proxyEndpoint: $('proxy-endpoint'),
    usageByKey: $('usage-by-key'),
    usageByModel: $('usage-by-model'),
    usageTable: $('usage-table'),
    usageTableBody: $('usage-table-body'),
    usageEmpty: $('usage-empty'),

    // Groups
    groupList: $('group-list'),
    groupDialog: $('group-dialog'),
    groupForm: $('group-form'),
    groupDialogTitle: $('group-dialog-title'),
    groupName: $('g-name'),
    groupColors: $('g-colors'),
    groupError: $('group-error'),
    groupSave: $('group-save'),

    // Proxy tokens
    tokenList: $('token-list'),
    tokenDialog: $('token-dialog'),
    tokenForm: $('token-form'),
    tokenCreate: $('token-create'),
    tokenKey: $('t-key'),
    tokenName: $('t-name'),
    tokenReveal: $('token-reveal'),
    tokenValue: $('token-value'),
    tokenError: $('token-error'),

    // Keys
    search: $('search'),
    searchKbd: $('search-kbd'),
    searchClear: $('search-clear'),
    sort: $('sort'),
    providerFilters: $('provider-filters'),
    groupFilters: $('group-filters'),
    resultLine: $('result-line'),
    keysHost: $('keys-host'),
    keysEmpty: $('keys-empty'),
    bulkBar: $('bulk-bar'),
    bulkCount: $('bulk-count'),
    bulkGroup: $('bulk-group'),
    bulkExpiry: $('bulk-expiry'),

    // Dialogs
    keyDialog: $('key-dialog'),
    keyDialogTitle: $('key-dialog-title'),
    keyDialogSub: $('key-dialog-sub'),
    keyForm: $('key-form'),
    dialogSave: $('dialog-save'),
    keyError: $('key-error'),
    fProvider: $('f-provider'),
    fApiKey: $('f-api-key'),
    fLabel: $('f-label'),
    fDescription: $('f-description'),
    fBaseUrl: $('f-base-url'),
    fGroup: $('f-group'),
    fExpiry: $('f-expiry'),
    fExpiryCustomWrap: $('f-expiry-custom-wrap'),
    fExpiryCustom: $('f-expiry-custom'),
    fExpiryHint: $('f-expiry-hint'),
    keyOptional: $('key-optional'),

    confirmDialog: $('confirm-dialog'),
    confirmTitle: $('confirm-title'),
    confirmText: $('confirm-text'),
    confirmNote: $('confirm-note'),
    confirmOk: $('confirm-ok'),
    confirmOkLabel: $('confirm-ok-label'),
    confirmGlyph: $('confirm-glyph'),

    toasts: $('toasts'),
};

/* ==================================================================== *
 * In-memory state. Nothing here is ever persisted.
 * ==================================================================== */
const state = {
    user: null,
    keys: [],
    groups: [],
    checks: new Map(),      // id -> { state, message, status, at }
    revealed: new Map(),    // id -> plaintext, only while revealed
    revealTimers: new Map(),
    query: '',
    providerFilter: 'All',
    groupFilter: 'All',     // 'All' | 'ungrouped' | a group id
    sort: 'updated',
    view: 'overview',
    editingId: null,
    busyIds: new Set(),
    selected: new Set(),    // ids ticked for a bulk action
    channel: null,
    groupsChannel: null,
    providerUrls: new Map(),  // provider -> { base_url, probe_path }, per user
    tokens: [],
    usage: [],
    usageChannel: null,
    newTokenValue: null,      // held in memory only, cleared on dialog close
    editingGroupId: null,
    groupColor: GROUP_COLORS[0],
    pendingAction: null,      // { kind, ids } awaiting confirmation
};

/* ==================================================================== *
 * Utilities
 * ==================================================================== */
function node(tag, props = {}, children = []) {
    const element = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
        if (value === undefined || value === null || value === false) continue;
        if (key === 'class') element.className = value;
        else if (key === 'text') element.textContent = value;
        else if (key === 'dataset') Object.assign(element.dataset, value);
        else if (key.startsWith('on') && typeof value === 'function') {
            element.addEventListener(key.slice(2).toLowerCase(), value);
        } else if (value === true) element.setAttribute(key, '');
        else element.setAttribute(key, value);
    }
    for (const child of [].concat(children)) {
        if (child === null || child === undefined || child === false) continue;
        element.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return element;
}

/** SVG element that references a sprite symbol. */
function icon(id, cls = 'icon') {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('class', cls);
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    use.setAttribute('href', `#${id}`);
    svg.append(use);
    return svg;
}

/* ---- Formatting ---- */
const dateTimeFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });
const relFmt = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

function formatDateTime(iso) {
    const date = new Date(iso);
    return Number.isNaN(date.getTime()) ? '' : dateTimeFmt.format(date);
}

function formatDate(iso) {
    const date = new Date(iso);
    return Number.isNaN(date.getTime()) ? '' : dateFmt.format(date);
}

function formatRelative(iso) {
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return '';
    const seconds = Math.round((date.getTime() - Date.now()) / 1000);
    const abs = Math.abs(seconds);
    if (abs < 45) return 'just now';
    if (abs < 3600) return relFmt.format(Math.round(seconds / 60), 'minute');
    if (abs < 86400) return relFmt.format(Math.round(seconds / 3600), 'hour');
    if (abs < 604800) return relFmt.format(Math.round(seconds / 86400), 'day');
    return formatDate(iso);
}

function initialsFrom(email) {
    if (!email) return '·';
    const name = email.split('@')[0].replace(/[^a-zA-Z0-9]/g, ' ').trim();
    const parts = name.split(/\s+/).filter(Boolean);
    if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
    return (email[0] + (email[1] ?? '')).toUpperCase();
}

function maskFor(item) {
    return item.key_last4 ? `${MASK}${item.key_last4}` : MASK;
}

/* ---- Expiry -------------------------------------------------------- */
const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

/** True once a key carries an expiry that has already passed. */
function isExpired(item) {
    return Boolean(item.expires_at) && new Date(item.expires_at).getTime() <= Date.now();
}

/** Milliseconds until expiry (negative once passed), or null when unset. */
function msUntilExpiry(item) {
    if (!item.expires_at) return null;
    const at = new Date(item.expires_at).getTime();
    return Number.isNaN(at) ? null : at - Date.now();
}

/** Set to expire inside the warning window, but not yet expired. */
function isExpiringSoon(item) {
    const ms = msUntilExpiry(item);
    return ms !== null && ms > 0 && ms <= EXPIRY_WARNING_DAYS * DAY_MS;
}

/** Human summary of an expiry, e.g. "Expires in 3 days". */
function expiryLabel(item) {
    if (!item.expires_at) return 'No expiry';
    const ms = msUntilExpiry(item);
    if (ms === null) return 'No expiry';
    const abs = Math.abs(ms);
    const unit = abs < HOUR_MS ? 'minute' : (abs < DAY_MS ? 'hour' : 'day');
    const amount = unit === 'minute'
        ? Math.round(ms / 60_000)
        : (unit === 'hour' ? Math.round(ms / HOUR_MS) : Math.round(ms / DAY_MS));
    return ms <= 0
        ? `Expired ${relFmt.format(amount, unit)}`
        : `Expires ${relFmt.format(amount, unit)}`;
}

/** ISO string to the local value a datetime-local input expects. */
function toLocalInputValue(iso) {
    if (!iso) return '';
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return '';
    const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
    return local.toISOString().slice(0, 16);
}

/** datetime-local value back to an ISO string, or null. */
function fromLocalInputValue(value) {
    if (!value) return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

/** Resolve an expiry preset (plus any custom date) to an ISO timestamp. */
function expiresAtFromPreset(presetValue, customValue) {
    const preset = EXPIRY_PRESETS.find((entry) => entry.value === presetValue);
    if (!preset) return null;
    if (preset.value === 'custom') return fromLocalInputValue(customValue);
    if (preset.hours) return new Date(Date.now() + preset.hours * HOUR_MS).toISOString();
    if (preset.days) return new Date(Date.now() + preset.days * DAY_MS).toISOString();
    return null;   // 'never'
}

/** Pick the preset that best matches a stored expiry, for editing. */
function presetForExpiry(iso) {
    if (!iso) return 'never';
    const ms = new Date(iso).getTime() - Date.now();
    if (Number.isNaN(ms)) return 'never';
    for (const preset of EXPIRY_PRESETS) {
        if (!preset.days && !preset.hours) continue;
        const target = preset.hours ? preset.hours * HOUR_MS : preset.days * DAY_MS;
        // Snap to a preset only when it is close; otherwise the exact date wins.
        if (Math.abs(ms - target) < 90 * 60_000) return preset.value;
    }
    return 'custom';
}

/**
 * Translate library/Postgres errors into language a person can act on,
 * without leaking internals.
 */
function friendlyError(error) {
    if (!error) return 'Something went wrong.';
    const code = error.code ?? '';
    const message = String(error.message ?? '').toLowerCase();

    if (message.includes('invalid login credentials')) return 'Email or password is incorrect.';
    if (message.includes('email not confirmed')) return 'Confirm your email address, then log in.';
    if (message.includes('user already registered')) return 'That email already has an account. Log in instead.';
    if (message.includes('not authenticated')) return 'Your session expired. Log in again to continue.';
    if (message.includes('not found')) return 'That key no longer exists.';
    if (message.includes('cannot be empty')) return 'Enter the API key before saving.';
    if (message.includes('too long')) return 'That key is longer than the 1024 character limit.';
    if (message.includes('password should be at least')) return 'Use a password of at least 6 characters.';
    if (message.includes('failed to fetch') || message.includes('networkerror')) {
        return 'Network problem. Check your connection and try again.';
    }
    if (code === '23505') return 'That value already exists.';
    return error.message || 'Something went wrong.';
}

/* ---- Toasts ---- */
function toast(message, kind = 'info', timeout) {
    const glyph = kind === 'ok' ? 'i-check-circle' : (kind === 'error' ? 'i-x-circle' : 'i-info');
    const element = node('div', { class: `toast toast--${kind}`, role: 'status' }, [
        node('span', { class: 'toast__icon' }, [icon(glyph)]),
        node('span', { class: 'toast__text', text: message }),
    ]);
    el.toasts.append(element);

    const duration = timeout ?? (kind === 'error' ? 5200 : 3000);
    setTimeout(() => {
        element.dataset.leaving = 'true';
        element.addEventListener('animationend', () => element.remove(), { once: true });
        setTimeout(() => element.remove(), 400);
    }, duration);
}

/* ---- Clipboard ---- */
async function copyText(text) {
    try {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
            return true;
        }
    } catch { /* fall through to the legacy path */ }

    const scratch = node('textarea', { style: 'position:fixed;top:-1000px;opacity:0' });
    scratch.value = text;
    document.body.append(scratch);
    scratch.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    scratch.remove();
    return ok;
}

/** Save a JSON payload as a download, without a server round-trip. */
function downloadJson(filename, payload) {
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = node('a', { href: url, download: filename });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/* ==================================================================== *
 * Theme
 * ==================================================================== */
function applyTheme(preference) {
    const resolved = preference === 'light' || preference === 'dark' ? preference : 'system';
    document.documentElement.setAttribute('data-theme', resolved);
    try { localStorage.setItem(THEME_KEY, resolved); } catch { /* ignore */ }

    for (const button of document.querySelectorAll('[data-theme-option]')) {
        button.classList.toggle('is-active', button.dataset.themeOption === resolved);
        button.setAttribute('aria-pressed', String(button.dataset.themeOption === resolved));
    }
}

function initTheme() {
    applyTheme(document.documentElement.getAttribute('data-theme') || 'system');
    for (const button of document.querySelectorAll('[data-theme-option]')) {
        button.addEventListener('click', () => applyTheme(button.dataset.themeOption));
    }
}

/* ==================================================================== *
 * View routing (hash based, so refresh and back/forward both work)
 * ==================================================================== */
function setView(view, { focus = false } = {}) {
    const next = VIEWS[view] ? view : 'overview';
    state.view = next;

    for (const [name, section] of Object.entries({
        overview: el.viewOverview,
        keys: el.viewKeys,
        usage: el.viewUsage,
        account: el.viewAccount,
    })) {
        section.hidden = name !== next;
    }

    el.viewTitle.textContent = VIEWS[next].title;
    el.viewSubtitle.textContent = VIEWS[next].subtitle;

    for (const link of document.querySelectorAll('[data-view-link]')) {
        const active = link.dataset.viewLink === next;
        link.classList.toggle('is-active', active);
        if (active) link.setAttribute('aria-current', 'page');
        else link.removeAttribute('aria-current');
    }

    if (next === 'keys' && focus) el.search.focus();
    if (next === 'overview') renderOverview();
}

function initRouter() {
    const fromHash = () => {
        const name = window.location.hash.replace(/^#/, '');
        setView(VIEWS[name] ? name : 'overview');
    };

    window.addEventListener('hashchange', fromHash);

    for (const link of document.querySelectorAll('[data-view-link]')) {
        link.addEventListener('click', () => {
            // Let the hash change, then move focus for keyboard and screen readers.
            setTimeout(() => {
                el.viewTitle.setAttribute('tabindex', '-1');
                el.viewTitle.focus({ preventScroll: true });
            }, 0);
        });
    }

    return fromHash;
}

/* ==================================================================== *
 * Auth
 * ==================================================================== */
function switchAuthTab(mode) {
    const isLogin = mode === 'login';
    el.tabLogin.classList.toggle('is-active', isLogin);
    el.tabSignup.classList.toggle('is-active', !isLogin);
    el.tabLogin.setAttribute('aria-selected', String(isLogin));
    el.tabSignup.setAttribute('aria-selected', String(!isLogin));
    el.panelLogin.hidden = !isLogin;
    el.panelSignup.hidden = isLogin;
    clearFormError(el.loginError);
    clearFormError(el.signupError);
    (isLogin ? el.loginEmail : el.signupEmail).focus();
}

function clearFormError(target) {
    target.hidden = true;
    target.textContent = '';
}

function showFormError(target, message) {
    target.textContent = message;
    target.hidden = false;
}

function setFormBusy(form, busy) {
    const button = form.querySelector('button[type="submit"]');
    if (!button) return;
    button.disabled = busy;
    if (busy) button.dataset.busy = 'true';
    else delete button.dataset.busy;
}

function initAuth() {
    el.tabLogin.addEventListener('click', () => switchAuthTab('login'));
    el.tabSignup.addEventListener('click', () => switchAuthTab('signup'));

    el.panelLogin.addEventListener('submit', async (event) => {
        event.preventDefault();
        clearFormError(el.loginError);

        const email = el.loginEmail.value.trim();
        const password = el.loginPassword.value;
        if (!email || !password) {
            showFormError(el.loginError, 'Enter both your email address and password.');
            return;
        }

        setFormBusy(el.panelLogin, true);
        const { error } = await supabase.auth.signInWithPassword({ email, password });
        setFormBusy(el.panelLogin, false);

        if (error) {
            showFormError(el.loginError, friendlyError(error));
            return;
        }
        el.loginPassword.value = '';
    });

    el.panelSignup.addEventListener('submit', async (event) => {
        event.preventDefault();
        clearFormError(el.signupError);

        const email = el.signupEmail.value.trim();
        const password = el.signupPassword.value;
        if (!email || !password) {
            showFormError(el.signupError, 'Enter both an email address and a password.');
            return;
        }
        if (password.length < 6) {
            showFormError(el.signupError, 'Use a password of at least 6 characters.');
            return;
        }

        setFormBusy(el.panelSignup, true);
        const { data, error } = await supabase.auth.signUp({ email, password });
        setFormBusy(el.panelSignup, false);

        if (error) {
            showFormError(el.signupError, friendlyError(error));
            return;
        }

        el.signupPassword.value = '';
        if (data.session) toast('Account created. Welcome to Keyvault.', 'ok');
        else toast('Account created. Confirm your email, then log in.', 'info', 6000);
    });
}

async function signOut() {
    teardownRealtime();
    clearRevealed();
    await supabase.auth.signOut();
    toast('Signed out of this device.', 'info');
}

/* ==================================================================== *
 * Session lifecycle
 * ==================================================================== */
function enterAuthScreen() {
    teardownRealtime();
    teardownGroupsRealtime();
    clearRevealed();
    state.keys = [];
    state.groups = [];
    state.checks.clear();
    state.user = null;
    state.busyIds.clear();
    state.selected.clear();

    el.app.hidden = true;
    el.auth.hidden = false;
    el.loginPassword.value = '';
    el.signupPassword.value = '';
    switchAuthTab('login');
}

async function enterApp(user) {
    state.user = user;
    const email = user.email ?? '';

    el.railEmail.textContent = email;
    el.accountEmail.textContent = email;
    el.accountId.textContent = user.id;
    const initials = initialsFrom(email);
    el.railAvatar.textContent = initials;
    el.accountAvatar.textContent = initials;

    el.auth.hidden = true;
    el.app.hidden = false;

    el.search.value = '';
    state.query = '';
    state.providerFilter = 'All';
    state.groupFilter = 'All';
    el.sort.value = 'updated';
    state.sort = 'updated';

    renderSkeleton();
    renderProxyEndpoint();
    await Promise.all([loadKeys(), loadGroups(), loadProviderUrls(), loadTokens(), loadUsage()]);
    subscribeRealtime();
    subscribeGroupsRealtime();
}

supabase.auth.onAuthStateChange((_event, session) => {
    // Defer so supabase-js releases its internal lock first.
    setTimeout(() => {
        if (session?.user) enterApp(session.user);
        else enterAuthScreen();
    }, 0);
});

/* ==================================================================== *
 * Data loading
 * ==================================================================== */
function renderSkeleton() {
    const skeletonCard = node('div', { class: 'skeleton', style: 'height:132px' });
    const rows = Array.from({ length: 4 }, () =>
        node('div', { class: 'skeleton', style: 'height:44px;border-radius:0' }));

    el.keysHost.replaceChildren(
        node('div', { class: 'cards' }, [skeletonCard, skeletonCard]),
        node('div', { class: 'tablecard' }, [node('div', { style: 'padding:12px' }, rows)]),
    );
    el.keysEmpty.hidden = true;
    el.resultLine.textContent = 'Loading your keys…';
}

async function loadKeys() {
    const { data, error } = await supabase
        .from('api_keys')
        .select(KEY_COLUMNS)
        .order('created_at', { ascending: false });

    if (error) {
        el.keysHost.replaceChildren();
        el.resultLine.textContent = '';
        showFormError(el.keyError, '');
        toast(friendlyError(error), 'error');
        return;
    }

    state.keys = data ?? [];
    renderAll();
}

/**
 * Per-user provider defaults, learned from keys you have already saved.
 * Used to pre-fill the base URL so you never type the same host twice.
 */
async function loadProviderUrls() {
    const { data, error } = await supabase
        .from('user_provider_urls')
        .select('provider, base_url, probe_path');

    if (error) return;   // non-fatal: pre-fill simply falls back to config

    state.providerUrls.clear();
    for (const row of data ?? []) {
        state.providerUrls.set(row.provider, {
            base_url: row.base_url,
            probe_path: row.probe_path,
        });
    }
}

async function loadGroups() {
    const { data, error } = await supabase
        .from('key_groups')
        .select(GROUP_COLUMNS)
        .order('name', { ascending: true });

    if (error) {
        // Non-fatal on its own, but it also means key.group_id cannot be
        // labelled, so it is surfaced rather than hidden.
        el.groupList.replaceChildren(
            node('p', { class: 'activity__empty', text: friendlyError(error) }),
        );
        return;
    }

    state.groups = data ?? [];
    renderGroups();
    renderAll();
}

async function loadTokens() {
    const { data, error } = await supabase
        .from('proxy_tokens')
        .select(TOKEN_COLUMNS)
        .order('created_at', { ascending: false });

    if (error) {
        el.tokenList.replaceChildren(
            node('p', { class: 'activity__empty', text: friendlyError(error) }),
        );
        return;
    }

    state.tokens = data ?? [];
    renderTokens();
}

async function loadUsage() {
    const { data, error } = await supabase
        .from('usage_events')
        .select(USAGE_COLUMNS)
        .order('created_at', { ascending: false })
        .limit(USAGE_PAGE_SIZE);

    if (error) {
        el.usageEmpty.hidden = false;
        el.usageEmpty.textContent = friendlyError(error);
        return;
    }

    state.usage = data ?? [];
    renderUsage();
}

/**
 * Resolve the base URL to pre-fill for a provider, in priority order:
 *   1. a URL this user has already saved for that provider (learned)
 *   2. a URL already used by one of their keys of that provider
 *   3. the configured default, which is an unverified placeholder
 */
function resolveProviderUrl(provider) {
    const learned = state.providerUrls.get(provider);
    if (learned?.base_url) return { value: learned.base_url, source: 'learned' };

    const existing = state.keys.find((item) => item.provider === provider && item.api_base_url);
    if (existing) return { value: existing.api_base_url, source: 'learned' };

    const fallback = PROVIDER_BASE_URLS[provider];
    if (fallback) {
        return { value: fallback, source: PROVIDER_URLS_ARE_PLACEHOLDERS ? 'placeholder' : 'default' };
    }

    return { value: '', source: 'none' };
}

/* ==================================================================== *
 * Realtime
 * ==================================================================== */
function setSync(stateName, label) {
    el.sync.dataset.state = stateName;
    el.syncLabel.textContent = label;
}

function teardownRealtime() {
    if (state.channel) {
        supabase.removeChannel(state.channel);
        state.channel = null;
    }
}

function teardownGroupsRealtime() {
    if (state.groupsChannel) {
        supabase.removeChannel(state.groupsChannel);
        state.groupsChannel = null;
    }
}

function subscribeRealtime() {
    teardownRealtime();
    if (!state.user) return;

    setSync('connecting', 'Connecting');
    state.channel = supabase
        .channel(`api_keys:${state.user.id}`)
        .on(
            'postgres_changes',
            { event: '*', schema: 'public', table: 'api_keys', filter: `user_id=eq.${state.user.id}` },
            () => { loadKeys(); },
        )
        .subscribe((status) => {
            if (status === 'SUBSCRIBED') setSync('online', 'Live');
            else if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') setSync('offline', 'Offline');
            else if (status === 'CLOSED') setSync('connecting', 'Paused');
        });
}

function subscribeGroupsRealtime() {
    teardownGroupsRealtime();
    if (!state.user) return;

    state.groupsChannel = supabase
        .channel(`key_groups:${state.user.id}`)
        .on(
            'postgres_changes',
            { event: '*', schema: 'public', table: 'key_groups', filter: `user_id=eq.${state.user.id}` },
            () => { loadGroups(); },
        )
        .subscribe();
}

/* ==================================================================== *
 * Selection: filter + sort
 * ==================================================================== */
function visibleKeys() {
    const query = state.query.trim().toLowerCase();

    const filtered = state.keys.filter((item) => {
        if (state.providerFilter !== 'All' && item.provider !== state.providerFilter) return false;

        if (state.groupFilter === 'ungrouped') {
            if (item.group_id) return false;
        } else if (state.groupFilter !== 'All') {
            if (item.group_id !== state.groupFilter) return false;
        }

        if (!query) return true;
        const groupName = groupFor(item)?.name ?? '';
        return [item.provider, item.label, item.description, item.api_base_url, item.key_last4, groupName]
            .filter(Boolean)
            .some((value) => String(value).toLowerCase().includes(query));
    });

    const expiryValue = (item) => {
        const at = item.expires_at ? new Date(item.expires_at).getTime() : null;
        return at === null || Number.isNaN(at) ? Infinity : at;
    };

    const sorters = {
        updated: (a, b) => new Date(b.updated_at) - new Date(a.updated_at),
        created: (a, b) => new Date(b.created_at) - new Date(a.created_at),
        provider: (a, b) => a.provider.localeCompare(b.provider) || (a.label ?? '').localeCompare(b.label ?? ''),
        name: (a, b) => (a.label ?? a.provider).localeCompare(b.label ?? b.provider),
        group: (a, b) => (groupFor(a)?.name ?? '~').localeCompare(groupFor(b)?.name ?? '~')
            || (a.label ?? a.provider).localeCompare(b.label ?? b.provider),
        expiry: (a, b) => expiryValue(a) - expiryValue(b),
    };

    return filtered.sort(sorters[state.sort] ?? sorters.updated);
}

/* ==================================================================== *
 * Rendering — shared pieces
 * ==================================================================== */
function providerChip(provider) {
    return node('span', { class: 'provider', dataset: { provider } }, [
        node('span', { class: 'provider__dot' }),
        provider,
    ]);
}

/** The group a key belongs to, if it still exists. */
function groupFor(item) {
    if (!item.group_id) return null;
    return state.groups.find((group) => group.id === item.group_id) ?? null;
}

function groupChip(group, { interactive = false, onClick } = {}) {
    if (!group) {
        return node('span', { class: 'group group--none', title: 'No group' }, [
            node('span', { class: 'group__dot' }),
            'Ungrouped',
        ]);
    }

    const props = {
        class: 'group',
        style: groupHueStyle(group.color),
        dataset: { groupId: group.id },
        title: group.name,
    };
    if (interactive) {
        props.type = 'button';
        props.onclick = onClick;
    }
    return node(interactive ? 'button' : 'span', props, [
        node('span', { class: 'group__dot' }),
        group.name,
    ]);
}

function checkPill(item) {
    const live = state.checks.get(item.id);
    const ok = live ? live.state === 'ok' : item.last_check_ok;
    const pending = live?.state === 'pending';

    if (pending) {
        return node('span', { class: 'pill pill--warn' }, [icon('i-pulse'), node('span', { class: 'pill__text', text: 'Checking' })]);
    }
    if (ok === true) {
        return node('span', { class: 'pill pill--ok' }, [icon('i-shield-check'), node('span', { class: 'pill__text', text: 'Verified' })]);
    }
    if (ok === false) {
        return node('span', { class: 'pill pill--fail' }, [icon('i-shield-alert'), node('span', { class: 'pill__text', text: 'Failed' })]);
    }
    return node('span', { class: 'pill pill--neutral' }, [icon('i-clock'), node('span', { class: 'pill__text', text: 'Untested' })]);
}

/**
 * Expiry badge. Silent when a key has no expiry, so the common case stays
 * uncluttered; loud once it has passed.
 */
function expiryPill(item) {
    if (!item.expires_at) return null;
    const at = formatDateTime(item.expires_at);

    if (isExpired(item)) {
        return node('span', { class: 'pill pill--fail', title: at }, [
            icon('i-calendar'),
            node('span', { class: 'pill__text', text: 'Expired' }),
        ]);
    }
    if (isExpiringSoon(item)) {
        return node('span', { class: 'pill pill--warn', title: at }, [
            icon('i-calendar'),
            node('span', { class: 'pill__text', text: 'Expiring soon' }),
        ]);
    }
    return null;
}

/** The masked or revealed key, with reveal and copy affordances. */
function secretControl(item) {
    const revealed = state.revealed.has(item.id);
    const text = node('span', {
        class: `secret__text${revealed ? ' is-revealed' : ''}`,
        text: revealed ? state.revealed.get(item.id) : maskFor(item),
        title: revealed ? 'Decrypted in this browser only' : 'Encrypted at rest',
    });

    const revealButton = node('button', {
        type: 'button',
        class: 'secret__btn',
        'aria-label': revealed ? 'Hide the key' : 'Reveal the key',
        title: revealed ? 'Hide' : 'Reveal',
        onclick: () => (revealed ? hideKey(item.id) : revealKey(item.id)),
    }, [icon(revealed ? 'i-eye-off' : 'i-eye')]);

    const copyButton = node('button', {
        type: 'button',
        class: 'secret__btn',
        'aria-label': 'Copy the key to the clipboard',
        title: 'Copy',
        onclick: () => copyKey(item, copyButton),
    }, [icon('i-copy')]);

    return node('span', { class: 'secret' }, [
        text,
        node('span', { class: 'secret__actions' }, [revealButton, copyButton]),
    ]);
}

/** Persistent status line for the last validation result. */
function checkResult(item) {
    const live = state.checks.get(item.id);
    const pending = live?.state === 'pending';
    const ok = live ? live.state === 'ok' : item.last_check_ok;
    const message = live ? live.message : item.last_check_message;
    const checkedAt = live ? live.at : item.last_check_at;
    const status = live ? live.status : item.last_check_status;

    if (!pending && !message && !checkedAt) return null;

    const variant = pending ? 'pending' : (ok ? 'ok' : 'fail');
    const glyph = pending ? 'i-pulse' : (ok ? 'i-check-circle' : 'i-x-circle');

    const metaParts = [];
    if (status) metaParts.push(`HTTP ${status}`);
    if (checkedAt) metaParts.push(`Checked ${formatRelative(checkedAt)}`);
    if (item.api_base_url) metaParts.push('Base URL from your record');
    else metaParts.push(`Probe ${TEST_PROBE_PATH} against the provider default`);

    return node('div', { class: `check check--${variant}` }, [
        node('span', { class: 'check__icon' }, [icon(glyph)]),
        node('span', { class: 'check__body' }, [
            node('span', { class: 'check__message', text: message || 'Contacting the provider…' }),
            node('span', { class: 'check__meta', text: metaParts.join(' · ') }),
        ]),
    ]);
}

function actionButton({ glyph, label, onClick, danger = false, extraClass = '' }) {
    return node('button', {
        type: 'button',
        class: `action${danger ? ' action--danger' : ''}${extraClass ? ` ${extraClass}` : ''}`,
        'aria-label': label,
        title: label,
        onclick: onClick,
    }, [icon(glyph)]);
}

function keyActions(item, { withLabels = false } = {}) {
    const live = state.checks.get(item.id);
    const testState = live?.state === 'pending' ? '' : (item.last_check_ok === true ? 'ok' : (item.last_check_ok === false ? 'fail' : ''));

    const test = node('button', {
        type: 'button',
        class: `action action--test${withLabels ? ' action--labelled' : ''}`,
        dataset: { state: testState },
        'aria-label': `Validate ${item.label ?? item.provider} against its provider`,
        title: 'Validate against the provider',
        onclick: () => testKey(item),
    }, [icon('i-pulse')]);

    const edit = actionButton({
        glyph: 'i-pencil',
        label: `Edit ${item.label ?? item.provider}`,
        onClick: () => openKeyDialog(item),
    });

    const remove = actionButton({
        glyph: 'i-trash',
        label: `Delete ${item.label ?? item.provider}`,
        onClick: () => confirmDelete(item),
        danger: true,
    });

    return node('span', { class: 'rowactions' }, [test, edit, remove]);
}

/**
 * Extend an expired or soon-to-expire key in one click. Used on the
 * Overview panel, where the whole point is not having to open a dialog.
 */
function quickExtendButton(item) {
    const preset = item.expires_at ? '30d' : '90d';
    return node('button', {
        type: 'button',
        class: 'btn btn--sm',
        onclick: () => setKeyExpiry(item, preset),
    }, [icon('i-calendar'), node('span', { class: 'btn__label', text: `Extend ${preset}` })]);
}

/* ==================================================================== *
 * Rendering — table row & card
 * ==================================================================== */
function selectionToggle(item) {
    const checked = state.selected.has(item.id);
    return node('button', {
        type: 'button',
        class: `selectbox${checked ? ' is-checked' : ''}`,
        role: 'checkbox',
        'aria-checked': String(checked),
        'aria-label': `${checked ? 'Deselect' : 'Select'} ${item.label || item.provider}`,
        onclick: () => toggleSelected(item.id),
    }, [icon('i-check')]);
}

function tableRow(item) {
    const baseUrl = item.api_base_url;
    const group = groupFor(item);
    const expiry = expiryPill(item);

    return node('tr', { class: isExpired(item) ? 'row--expired' : '' }, [
        node('td', { class: 'cell-select' }, [selectionToggle(item)]),
        node('td', { class: 'cell-name' }, [
            node('span', { class: 'cell-name__title', text: item.label || `${item.provider} key` }),
            node('span', {
                class: 'cell-name__sub',
                text: item.description || (baseUrl ? baseUrl.replace(/^https?:\/\//i, '') : 'No description'),
            }),
        ]),
        node('td', { class: 'cell-provider' }, [
            node('div', { class: 'cell-stack' }, [
                providerChip(item.provider),
                group ? groupChip(group) : null,
            ]),
        ]),
        node('td', { class: 'cell-key' }, [secretControl(item)]),
        node('td', {}, [
            node('div', { class: 'cell-stack' }, [checkPill(item), expiry]),
        ]),
        node('td', { class: 'cell-time', text: formatRelative(item.updated_at), title: formatDateTime(item.updated_at) }),
        node('td', { class: 'cell-actions' }, [keyActions(item)]),
    ]);
}

function keyCard(item) {
    const baseUrl = item.api_base_url;
    const isLink = typeof baseUrl === 'string' && /^https?:\/\//i.test(baseUrl);
    const group = groupFor(item);

    const metaRows = [];

    if (group) {
        metaRows.push(node('div', { class: 'card__metarow' }, [
            node('span', { class: 'card__metalabel', text: 'Group' }),
            node('span', { class: 'card__metaval' }, [groupChip(group)]),
        ]));
    }

    if (baseUrl) {
        metaRows.push(node('div', { class: 'card__metarow' }, [
            node('span', { class: 'card__metalabel', text: 'Base URL' }),
            node('span', { class: 'card__metaval' }, [
                isLink
                    ? node('a', {
                        href: baseUrl,
                        target: '_blank',
                        rel: 'noopener noreferrer nofollow',
                        text: baseUrl,
                    })
                    : node('span', { text: baseUrl }),
            ]),
        ]));
    }

    metaRows.push(node('div', { class: 'card__metarow' }, [
        node('span', { class: 'card__metalabel', text: 'Status' }),
        node('span', { class: 'card__metaval' }, [checkPill(item)]),
    ]));

    const expiry = expiryPill(item);
    if (expiry) {
        const suffix = isExpired(item)
            ? `Expired ${formatDate(item.expires_at)}`
            : `${formatDate(item.expires_at)} · ${expiryLabel(item)}`;
        metaRows.push(node('div', { class: 'card__metarow' }, [
            node('span', { class: 'card__metalabel', text: 'Expiry' }),
            node('span', { class: 'card__metaval' }, [
                expiry,
                node('span', { class: 'card__metanote', text: ` ${suffix}` }),
            ]),
        ]));
    }

    return node('article', { class: `card${isExpired(item) ? ' card--expired' : ''}` }, [
        node('div', { class: 'card__head' }, [
            selectionToggle(item),
            node('div', { class: 'card__titles' }, [
                node('span', { class: 'card__title', text: item.label || `${item.provider} key` }),
                item.description ? node('span', { class: 'card__desc', text: item.description }) : null,
            ]),
            providerChip(item.provider),
        ]),

        node('div', { class: 'card__keys' }, [
            node('div', { class: 'card__metarow' }, [
                node('span', { class: 'card__metalabel', text: 'Key' }),
                secretControl(item),
            ]),
            ...metaRows,
        ]),

        checkResult(item),

        node('div', { class: 'card__foot' }, [
            node('span', {
                class: 'card__time',
                text: `Updated ${formatRelative(item.updated_at)}`,
                title: formatDateTime(item.updated_at),
            }),
            keyActions(item),
        ]),
    ]);
}

/* ==================================================================== *
 * Rendering — keys view
 * ==================================================================== */
function renderFilters() {
    const counts = new Map([['All', state.keys.length]]);
    for (const name of PROVIDERS) counts.set(name, 0);
    for (const item of state.keys) counts.set(item.provider, (counts.get(item.provider) ?? 0) + 1);

    // "All" always shows; a provider shows once it has keys.
    const names = ['All', ...PROVIDERS.filter((name) => name === 'Custom' || (counts.get(name) ?? 0) > 0)];

    el.providerFilters.replaceChildren(
        ...names.map((name) =>
            node('button', {
                type: 'button',
                class: `filter${state.providerFilter === name ? ' is-active' : ''}`,
                'aria-pressed': String(state.providerFilter === name),
                dataset: name === 'Custom' ? {} : { provider: name },
                onclick: () => {
                    state.providerFilter = name;
                    renderKeys();
                },
            }, [
                name === 'All' ? 'All providers' : providerChip(name),
                node('span', { class: 'filter__count', text: String(counts.get(name) ?? 0) }),
            ]),
        ),
    );
}

function renderGroupFilters() {
    if (state.groups.length === 0) {
        el.groupFilters.replaceChildren();
        el.groupFilters.hidden = true;
        if (state.groupFilter !== 'All') state.groupFilter = 'All';
        return;
    }

    el.groupFilters.hidden = false;

    const counts = new Map();
    let ungrouped = 0;
    for (const item of state.keys) {
        if (item.group_id) counts.set(item.group_id, (counts.get(item.group_id) ?? 0) + 1);
        else ungrouped += 1;
    }

    const options = [
        node('button', {
            type: 'button',
            class: `filter${state.groupFilter === 'All' ? ' is-active' : ''}`,
            'aria-pressed': String(state.groupFilter === 'All'),
            onclick: () => { state.groupFilter = 'All'; renderKeys(); },
        }, [
            node('span', { class: 'filter__label', text: 'All groups' }),
            node('span', { class: 'filter__count', text: String(state.keys.length) }),
        ]),
        ...state.groups.map((group) =>
            node('button', {
                type: 'button',
                class: `filter filter--group${state.groupFilter === group.id ? ' is-active' : ''}`,
                style: groupHueStyle(group.color),
                'aria-pressed': String(state.groupFilter === group.id),
                onclick: () => { state.groupFilter = group.id; renderKeys(); },
            }, [
                groupChip(group),
                node('span', { class: 'filter__count', text: String(counts.get(group.id) ?? 0) }),
            ]),
        ),
    ];

    if (ungrouped > 0) {
        options.push(node('button', {
            type: 'button',
            class: `filter${state.groupFilter === 'ungrouped' ? ' is-active' : ''}`,
            'aria-pressed': String(state.groupFilter === 'ungrouped'),
            onclick: () => { state.groupFilter = 'ungrouped'; renderKeys(); },
        }, [
            node('span', { class: 'filter__label', text: 'Ungrouped' }),
            node('span', { class: 'filter__count', text: String(ungrouped) }),
        ]));
    }

    el.groupFilters.replaceChildren(...options);
}

function renderKeys() {
    renderFilters();
    renderGroupFilters();
    renderBulkBar();

    const items = visibleKeys();
    keepRevealedOnly(items.map((item) => item.id));

    el.railKeyCount.textContent = String(state.keys.length);

    if (state.keys.length === 0) {
        el.keysHost.replaceChildren();
        el.keysEmpty.hidden = false;
        el.resultLine.textContent = '';
        return;
    }

    el.keysEmpty.hidden = true;

    if (items.length === 0) {
        el.keysHost.replaceChildren();
        el.resultLine.textContent = 'No keys match the current search or filter.';
        return;
    }

    const noun = state.keys.length === 1 ? 'key' : 'keys';
    el.resultLine.textContent = items.length === state.keys.length
        ? `${state.keys.length} ${noun} stored`
        : `${items.length} of ${state.keys.length} ${noun}`;

    el.keysHost.replaceChildren(
        node('div', { class: 'cards' }, items.map(keyCard)),
        node('div', { class: 'tablecard' }, [
            node('div', { class: 'tablewrap' }, [
                node('table', { class: 'table' }, [
                    node('thead', {}, [
                        node('tr', {}, [
                            node('th', { scope: 'col', class: 'cell-select' }, [
                                node('span', { class: 'sr-only', text: 'Select' }),
                            ]),
                            node('th', { scope: 'col', text: 'Name' }),
                            node('th', { scope: 'col', text: 'Provider / group' }),
                            node('th', { scope: 'col', text: 'API key' }),
                            node('th', { scope: 'col', text: 'Validation / expiry' }),
                            node('th', { scope: 'col', text: 'Updated' }),
                            node('th', { scope: 'col' }, [node('span', { class: 'sr-only', text: 'Actions' })]),
                        ]),
                    ]),
                    node('tbody', {}, items.map(tableRow)),
                ]),
            ]),
        ]),
    );
}

/* ==================================================================== *
 * Rendering — overview
 * ==================================================================== */
function computeSummary() {
    const total = state.keys.length;
    const verified = state.keys.filter((item) => item.last_check_ok === true).length;
    const failed = state.keys.filter((item) => item.last_check_ok === false).length;
    const untested = total - verified - failed;
    const expired = state.keys.filter(isExpired).length;
    const expiringSoon = state.keys.filter(isExpiringSoon).length;
    const groups = state.groups.length;
    return { total, verified, failed, untested, expired, expiringSoon, groups };
}

function statCard({ glyph, tone, label, value, note }) {
    return node('div', { class: 'stat' }, [
        node('div', { class: 'stat__top' }, [
            node('span', { class: `stat__icon${tone ? ` stat__icon--${tone}` : ''}` }, [icon(glyph)]),
            node('span', { class: 'stat__label', text: label }),
        ]),
        node('span', { class: 'stat__value', text: String(value) }),
        node('span', { class: 'stat__note', text: note }),
    ]);
}

function renderOverview() {
    const summary = computeSummary();

    el.stats.replaceChildren(
        statCard({
            glyph: 'i-key',
            tone: 'brand',
            label: 'Keys stored',
            value: summary.total,
            note: summary.total === 1 ? 'One credential in the vault' : 'All encrypted at rest',
        }),
        statCard({
            glyph: 'i-shield-check',
            tone: 'ok',
            label: 'Verified',
            value: summary.verified,
            note: 'Passed a live provider check',
        }),
        statCard({
            glyph: summary.expired > 0 ? 'i-calendar' : 'i-layers',
            tone: summary.expired > 0 ? 'warn' : undefined,
            label: 'Expired',
            value: summary.expired,
            note: summary.expired === 0
                ? `${summary.groups} group${summary.groups === 1 ? '' : 's'} in use`
                : 'No longer usable through the proxy',
        }),
        statCard({
            glyph: 'i-clock',
            tone: summary.expiringSoon > 0 ? 'warn' : undefined,
            label: 'Expiring soon',
            value: summary.expiringSoon,
            note: summary.expiringSoon === 0 ? 'Nothing flagged' : `Within ${EXPIRY_WARNING_DAYS} days`,
        }),
    );

    /* -- Provider breakdown -- */
    if (summary.total === 0) {
        el.providerBreakdown.replaceChildren(
            node('p', { class: 'breakdown__empty', text: 'Add a key to see how they are distributed.' }),
        );
    } else {
        const tally = new Map();
        for (const item of state.keys) tally.set(item.provider, (tally.get(item.provider) ?? 0) + 1);

        const ordered = [...tally.entries()].sort((a, b) => b[1] - a[1]);
        el.providerBreakdown.replaceChildren(
            node('div', { class: 'breakdown' }, ordered.map(([name, count]) => {
                const percent = Math.round((count / summary.total) * 100);
                return node('div', { class: 'breakdown__row', dataset: { provider: name } }, [
                    node('div', { class: 'breakdown__head' }, [
                        providerChip(name),
                        node('span', {
                            class: 'breakdown__count',
                            text: `${count} · ${percent}%`,
                        }),
                    ]),
                    node('div', {
                        class: 'meter',
                        role: 'img',
                        'aria-label': `${name}: ${count} of ${summary.total} keys`,
                    }, [
                        node('span', { class: 'meter__fill', style: `inline-size:${percent}%` }),
                    ]),
                ]);
            })),
        );
    }

    /* -- Recent validation -- */
    const checked = state.keys
        .filter((item) => item.last_check_at)
        .sort((a, b) => new Date(b.last_check_at) - new Date(a.last_check_at))
        .slice(0, 5);

    if (checked.length === 0) {
        el.activity.replaceChildren(
            node('p', { class: 'activity__empty', text: 'No validations yet. Use the validate action on any key.' }),
        );
        return;
    }

    el.activity.replaceChildren(
        node('div', { class: 'activity' }, checked.map((item) => {
            const ok = item.last_check_ok === true;
            return node('div', { class: 'activity__row' }, [
                node('span', { class: `activity__glyph${ok ? ' activity__glyph--ok' : ' activity__glyph--fail'}` }, [
                    icon(ok ? 'i-check-circle' : 'i-x-circle'),
                ]),
                node('span', { class: 'activity__main' }, [
                    node('span', { class: 'activity__name', text: item.label || `${item.provider} key` }),
                    node('span', {
                        class: 'activity__meta',
                        text: item.last_check_message || (ok ? 'Validated successfully.' : 'Validation failed.'),
                    }),
                ]),
                node('span', { class: 'activity__tail' }, [
                    item.last_check_status
                        ? node('span', { class: 'pill pill--neutral' }, [node('span', { class: 'pill__text', text: `HTTP ${item.last_check_status}` })])
                        : null,
                    node('span', { class: 'activity__time', text: formatRelative(item.last_check_at) }),
                ]),
            ]);
        })),
    );
}

/* ==================================================================== *
 * Master render
 * ==================================================================== */
function renderAll() {
    renderKeys();
    renderOverview();
    renderGroups();
    renderExpiring();
    renderTokens();
    renderUsage();
}

/* ==================================================================== *
 * Reveal / hide
 * ==================================================================== */
function clearRevealTimer(id) {
    const timer = state.revealTimers.get(id);
    if (timer) {
        clearTimeout(timer);
        state.revealTimers.delete(id);
    }
}

function keepRevealedOnly(ids) {
    const keep = new Set(ids);
    for (const id of [...state.revealed.keys()]) {
        if (!keep.has(id)) {
            state.revealed.delete(id);
            clearRevealTimer(id);
        }
    }
}

function clearRevealed() {
    for (const timer of state.revealTimers.values()) clearTimeout(timer);
    state.revealed.clear();
    state.revealTimers.clear();
}

function hideKey(id) {
    state.revealed.delete(id);
    clearRevealTimer(id);
    renderAll();
}

async function revealKey(id) {
    if (state.revealed.has(id)) {
        hideKey(id);
        return;
    }

    // Single-row decrypt, ownership re-checked inside Postgres.
    const { data, error } = await supabase.rpc('get_api_key_secret', { p_id: id });
    if (error) {
        toast(friendlyError(error), 'error');
        return;
    }
    if (typeof data !== 'string' || !data) {
        toast('That key could not be retrieved.', 'error');
        return;
    }

    state.revealed.set(id, data);
    renderAll();

    // Auto-hide so plaintext never lingers on screen.
    clearRevealTimer(id);
    state.revealTimers.set(id, setTimeout(() => {
        if (state.revealed.has(id)) {
            state.revealed.delete(id);
            state.revealTimers.delete(id);
            renderAll();
        }
    }, REVEAL_TIMEOUT_MS));
}

async function copyKey(item, button) {
    let value = state.revealed.get(item.id);

    if (!value) {
        const { data, error } = await supabase.rpc('get_api_key_secret', { p_id: item.id });
        if (error) {
            toast(friendlyError(error), 'error');
            return;
        }
        value = data;
    }
    if (!value) {
        toast('That key could not be retrieved.', 'error');
        return;
    }

    if (!(await copyText(value))) {
        toast('Copying is blocked here. Reveal the key and copy it manually.', 'error');
        return;
    }

    button.dataset.copied = 'true';
    button.replaceChildren(icon('i-check'));
    setTimeout(() => {
        button.dataset.copied = 'false';
        button.replaceChildren(icon('i-copy'));
    }, 1400);

    toast('Key copied to the clipboard.', 'ok');
}

/* ==================================================================== *
 * Live provider validation
 * ==================================================================== */
async function testKey(item) {
    if (state.checks.get(item.id)?.state === 'pending') return;

    state.checks.set(item.id, { state: 'pending', message: 'Contacting the provider…' });
    renderAll();

    try {
        // Only the id crosses the boundary. The key is decrypted server-side.
        const { data, error } = await supabase.functions.invoke(TEST_FUNCTION_NAME, {
            body: { key_id: item.id, path: TEST_PROBE_PATH },
        });

        if (error) {
            let detail = 'The validation could not be completed.';
            try {
                const payload = await error.context?.json?.();
                if (payload?.error) detail = payload.error;
                if (payload?.hint) detail = `${detail} ${payload.hint}`;
            } catch { /* keep the generic message */ }

            if (error.context?.status === 401) detail = 'Your session expired. Log in again.';
            throw new Error(detail);
        }

        const ok = Boolean(data?.ok);
        state.checks.set(item.id, {
            state: ok ? 'ok' : 'fail',
            message: data?.message || (ok ? 'The key is valid.' : 'The key did not validate.'),
            status: data?.status ?? null,
            at: data?.checked_at || new Date().toISOString(),
        });

        toast(ok ? 'Key validated against its provider.' : 'The key did not validate.', ok ? 'ok' : 'error');
    } catch (error) {
        state.checks.set(item.id, {
            state: 'fail',
            message: friendlyError(error),
            status: null,
            at: new Date().toISOString(),
        });
        toast('Validation failed.', 'error');
    }

    renderAll();
    await loadKeys();
}

/* ==================================================================== *
 * Add / edit dialog
 * ==================================================================== */
function applyProviderUrl(provider, { force = false } = {}) {
    // Never clobber a URL the person has typed or one being edited.
    if (!force && el.fBaseUrl.value.trim()) return;

    const resolved = resolveProviderUrl(provider);
    el.fBaseUrl.value = resolved.value;

    const hint = el.fBaseUrl.getAttribute('aria-describedby');
    const hintNode = hint ? document.getElementById(hint) : null;
    if (!hintNode) return;

    if (resolved.source === 'placeholder') {
        hintNode.textContent =
            'Pre-filled from a default that is not yet verified. Check it against the provider\'s docs — your value is remembered for next time.';
    } else if (resolved.source === 'learned') {
        hintNode.textContent = 'Remembered from a key you saved earlier. Used to validate the key.';
    } else {
        hintNode.textContent = 'Used to validate the key. Required for custom providers.';
    }
}

function openKeyDialog(item = null) {
    state.editingId = item?.id ?? null;
    const isEdit = Boolean(item);

    el.keyDialogTitle.textContent = isEdit ? 'Edit API key' : 'Add an API key';
    el.keyDialogSub.textContent = isEdit
        ? 'Metadata changes apply immediately. Leave the key blank to keep it.'
        : 'Encrypted on submit, before it reaches the database.';
    el.dialogSave.querySelector('.btn__label').textContent = isEdit ? 'Save changes' : 'Save key';

    el.keyOptional.hidden = !isEdit;
    el.fApiKey.required = !isEdit;
    el.fApiKey.value = '';
    el.fApiKey.type = 'password';
    el.fApiKey.placeholder = isEdit ? 'Unchanged' : 'sk-...';
    el.fApiKey.setAttribute('aria-invalid', 'false');
    el.fProvider.value = item?.provider ?? PROVIDERS[0];
    el.fLabel.value = item?.label ?? '';
    el.fDescription.value = item?.description ?? '';
    el.fBaseUrl.value = item?.api_base_url ?? '';

    // Group + expiry controls reset to the record being edited.
    groupsSelectOptions(el.fGroup, {
        includeBlank: true,
        blankLabel: 'No group',
        selected: item?.group_id ?? null,
    });

    const chosenPreset = presetForExpiry(item?.expires_at ?? null);
    el.fExpiry.replaceChildren(
        ...EXPIRY_PRESETS.map((preset) => node('option', { value: preset.value, text: preset.label })),
    );
    el.fExpiry.value = chosenPreset;
    el.fExpiryCustom.value = chosenPreset === 'custom' ? toLocalInputValue(item?.expires_at) : '';
    el.fExpiryCustomWrap.hidden = chosenPreset !== 'custom';

    clearFormError(el.keyError);

    // Pre-fill the base URL for a new key, so the same host is never typed
    // twice. An existing key keeps whatever it already has.
    if (!isEdit) applyProviderUrl(el.fProvider.value, { force: true });

    el.keyDialog.showModal();
    (isEdit ? el.fLabel : el.fApiKey).focus();
}

function closeKeyDialog() {
    if (el.keyDialog.open) el.keyDialog.close();
    state.editingId = null;
    el.fApiKey.value = '';
}

/* ==================================================================== *
 * Proxy tokens
 * ==================================================================== */
function renderTokens() {
    if (state.tokens.length === 0) {
        el.tokenList.replaceChildren(
            node('p', {
                class: 'activity__empty',
                text: 'No proxy tokens yet. Create one to route a client through the vault.',
            }),
        );
        return;
    }

    const keyNames = new Map(state.keys.map((item) => [item.id, item.label || item.provider]));

    el.tokenList.replaceChildren(
        node('div', { class: 'tokenlist' }, state.tokens.map((token) => {
            const revoked = Boolean(token.revoked_at);
            const keyName = keyNames.get(token.key_id) ?? 'Deleted key';

            const meta = [
                `kv_····${token.token_hint}`,
                keyName,
                revoked
                    ? `revoked ${formatRelative(token.revoked_at)}`
                    : (token.last_used_at ? `used ${formatRelative(token.last_used_at)}` : 'never used'),
            ];

            return node('div', { class: 'tokenrow' }, [
                node('span', { class: `tokenrow__glyph${revoked ? ' tokenrow__glyph--revoked' : ''}` }, [
                    icon(revoked ? 'i-shield-alert' : 'i-key'),
                ]),
                node('span', { class: 'tokenrow__main' }, [
                    node('span', { class: 'tokenrow__name', text: token.name || 'Unnamed token' }),
                    node('span', { class: 'tokenrow__meta', text: meta.join('  ·  ') }),
                ]),
                revoked
                    ? node('span', { class: 'pill pill--neutral' }, [node('span', { class: 'pill__text', text: 'Revoked' })])
                    : actionButton({
                        glyph: 'i-trash',
                        label: `Revoke ${token.name || 'token'}`,
                        onClick: () => revokeToken(token),
                        danger: true,
                    }),
            ]);
        })),
    );
}

function openTokenDialog() {
    if (state.keys.length === 0) {
        toast('Add a key first — a token has to be bound to one.', 'error');
        return;
    }

    el.tokenForm.reset();
    el.tokenError.hidden = true;
    el.tokenReveal.hidden = true;
    state.newTokenValue = null;

    el.tokenKey.replaceChildren(
        ...state.keys.map((item) =>
            node('option', { value: item.id, text: `${item.label || item.provider} — ${item.provider}` })),
    );

    el.tokenDialog.showModal();
    el.tokenKey.focus();
}

function closeTokenDialog() {
    if (el.tokenDialog.open) el.tokenDialog.close();
    state.newTokenValue = null;
    el.tokenReveal.hidden = true;
    el.tokenValue.textContent = '';
}

async function createToken() {
    const keyId = el.tokenKey.value;
    const name = el.tokenName.value.trim();
    if (!keyId) {
        showFormError(el.tokenError, 'Choose the key this token may reach.');
        return;
    }

    el.tokenCreate.disabled = true;
    el.tokenCreate.dataset.busy = 'true';

    // The plaintext token is returned exactly once, by the database.
    const { data, error } = await supabase.rpc('create_proxy_token', {
        p_key_id: keyId,
        p_name: name || null,
    });

    el.tokenCreate.disabled = false;
    delete el.tokenCreate.dataset.busy;

    if (error) {
        showFormError(el.tokenError, friendlyError(error));
        return;
    }

    state.newTokenValue = data?.token ?? null;
    el.tokenValue.textContent = state.newTokenValue ?? '';
    el.tokenReveal.hidden = false;
    el.tokenCreate.disabled = true;
    toast('Token created. Copy it now — it is not shown again.', 'ok', 6000);

    await loadTokens();
}

async function revokeToken(token) {
    const { error } = await supabase.rpc('revoke_proxy_token', { p_id: token.id });
    if (error) {
        toast(friendlyError(error), 'error');
        return;
    }
    toast('Token revoked. Requests using it will now be rejected.', 'ok');
    await loadTokens();
}

/* ==================================================================== *
 * Groups
 * ==================================================================== */
function groupsSelectOptions(select, { includeBlank = true, blankLabel = 'No group', selected = null } = {}) {
    const options = [];
    if (includeBlank) options.push(node('option', { value: '', text: blankLabel }));
    for (const group of state.groups) {
        options.push(node('option', { value: group.id, text: group.name }));
    }
    select.replaceChildren(...options);
    select.value = selected ?? '';
}

function expirySelectOptions(select, { includeBlank = false, blankLabel = 'Set expiry…' } = {}) {
    const options = [];
    if (includeBlank) options.push(node('option', { value: '', text: blankLabel }));
    for (const preset of EXPIRY_PRESETS) {
        options.push(node('option', { value: preset.value, text: preset.label }));
    }
    select.replaceChildren(...options);
    select.value = '';
}

function renderGroups() {
    if (state.groups.length === 0) {
        el.groupList.replaceChildren(
            node('p', {
                class: 'activity__empty',
                text: 'No groups yet. Create one to bucket related keys — by project, team or environment.',
            }),
        );
        return;
    }

    const counts = new Map();
    for (const item of state.keys) {
        if (item.group_id) counts.set(item.group_id, (counts.get(item.group_id) ?? 0) + 1);
    }

    el.groupList.replaceChildren(
        node('div', { class: 'grouplist' }, state.groups.map((group) => {
            const count = counts.get(group.id) ?? 0;
            return node('div', { class: 'grouprow', style: groupHueStyle(group.color) }, [
                node('span', { class: 'grouprow__glyph' }, [icon('i-layers')]),
                node('span', { class: 'grouprow__main' }, [
                    node('span', { class: 'grouprow__name' }, [groupChip(group)]),
                    node('span', {
                        class: 'grouprow__meta',
                        text: `${count} key${count === 1 ? '' : 's'}`,
                    }),
                ]),
                actionButton({
                    glyph: 'i-pencil',
                    label: `Edit ${group.name}`,
                    onClick: () => openGroupDialog(group),
                }),
                actionButton({
                    glyph: 'i-trash',
                    label: `Delete ${group.name}`,
                    onClick: () => confirmDeleteGroup(group),
                    danger: true,
                }),
            ]);
        })),
    );
}

function renderGroupColorSwatches() {
    el.groupColors.replaceChildren(...GROUP_COLORS.map((color) =>
        node('button', {
            type: 'button',
            class: `swatch${state.groupColor === color ? ' is-active' : ''}`,
            style: groupHueStyle(color),
            role: 'radio',
            'aria-checked': String(state.groupColor === color),
            'aria-label': GROUP_COLOR_LABELS[color],
            title: GROUP_COLOR_LABELS[color],
            onclick: () => {
                state.groupColor = color;
                renderGroupColorSwatches();
            },
        }, [icon('i-check')]),
    ));
}

function openGroupDialog(group = null) {
    state.editingGroupId = group?.id ?? null;
    state.groupColor = group?.color ?? GROUP_COLORS[0];

    el.groupDialogTitle.textContent = group ? 'Edit group' : 'New group';
    el.groupSave.querySelector('.btn__label').textContent = group ? 'Save changes' : 'Create group';
    el.groupName.value = group?.name ?? '';
    clearFormError(el.groupError);
    renderGroupColorSwatches();

    el.groupDialog.showModal();
    el.groupName.focus();
}

function closeGroupDialog() {
    if (el.groupDialog.open) el.groupDialog.close();
    state.editingGroupId = null;
}

async function saveGroup() {
    const name = el.groupName.value.trim();
    if (!name) {
        showFormError(el.groupError, 'Give the group a name.');
        el.groupName.focus();
        return;
    }

    el.groupSave.disabled = true;
    el.groupSave.dataset.busy = 'true';

    const isEdit = Boolean(state.editingGroupId);
    const { error } = isEdit
        ? await supabase.rpc('update_key_group', {
            p_id: state.editingGroupId,
            p_name: name,
            p_color: state.groupColor,
        })
        : await supabase.rpc('create_key_group', {
            p_name: name,
            p_color: state.groupColor,
        });

    el.groupSave.disabled = false;
    delete el.groupSave.dataset.busy;

    if (error) {
        showFormError(el.groupError, friendlyError(error));
        return;
    }

    closeGroupDialog();
    toast(isEdit ? 'Group updated.' : 'Group created.', 'ok');
    await loadGroups();
}

function confirmDeleteGroup(group) {
    state.pendingAction = { kind: 'delete-group', ids: [group.id] };
    el.confirmTitle.textContent = 'Delete this group?';
    el.confirmText.textContent = `“${group.name}” will be deleted.`;
    el.confirmNote.hidden = false;
    el.confirmNote.textContent = 'The keys in it are kept — they simply become ungrouped.';
    el.confirmOkLabel.textContent = 'Delete group';
    el.confirmDialog.showModal();
}

/** One-click expiry extension for a key that has lapsed or is about to. */
async function setKeyExpiry(item, presetValue) {
    const expiresAt = expiresAtFromPreset(presetValue, null);
    const { error } = await supabase.rpc('set_api_key_expiry', {
        p_id: item.id,
        p_expires_at: expiresAt,
    });
    if (error) {
        toast(friendlyError(error), 'error');
        return;
    }
    toast('Expiry updated.', 'ok');
    await loadKeys();
}

/* ==================================================================== *
 * Selection & bulk actions
 * ==================================================================== */
function selectedItems() {
    return state.keys.filter((item) => state.selected.has(item.id));
}

function toggleSelected(id) {
    if (state.selected.has(id)) state.selected.delete(id);
    else state.selected.add(id);
    renderAll();
}

function clearSelection() {
    state.selected.clear();
    renderAll();
}

function renderBulkBar() {
    // Selection can outlive a key; drop ids that no longer exist.
    if (state.selected.size > 0) {
        const live = new Set(state.keys.map((item) => item.id));
        for (const id of [...state.selected]) {
            if (!live.has(id)) state.selected.delete(id);
        }
    }

    const count = state.selected.size;
    el.bulkBar.hidden = count === 0;
    el.bulkCount.textContent = `${count} selected`;

    if (count === 0) return;

    // Only rebuild the dropdowns when their option set is out of date.
    // Rebuilding on every render would silently reset a choice the person
    // had already made but not yet applied.
    const wantedGroups = state.groups.length + 1;   // + the blank option
    if (el.bulkGroup.options.length !== wantedGroups) {
        groupsSelectOptions(el.bulkGroup, { includeBlank: true, blankLabel: 'Move to…' });
    }
    if (el.bulkExpiry.options.length !== EXPIRY_PRESETS.length + 1) {
        expirySelectOptions(el.bulkExpiry, { includeBlank: true, blankLabel: 'Set expiry…' });
    }
}

async function bulkAssignGroup() {
    const groupId = el.bulkGroup.value;
    if (!groupId) {
        toast('Choose a group to move the keys into.', 'error');
        return;
    }

    const items = selectedItems();
    if (items.length === 0) return;

    for (const item of items) {
        const { error } = await supabase.rpc('set_api_key_group', {
            p_id: item.id,
            p_group_id: groupId,
        });
        if (error) {
            toast(friendlyError(error), 'error');
            return;
        }
    }

    const name = state.groups.find((group) => group.id === groupId)?.name ?? 'the group';
    toast(`${items.length} key${items.length === 1 ? '' : 's'} moved to ${name}.`, 'ok');
    state.selected.clear();
    await loadKeys();
}

async function bulkSetExpiry() {
    const preset = el.bulkExpiry.value;
    if (!preset) {
        toast('Choose an expiry to apply.', 'error');
        return;
    }

    const expiresAt = expiresAtFromPreset(preset, null);
    const items = selectedItems();
    if (items.length === 0) return;

    for (const item of items) {
        const { error } = await supabase.rpc('set_api_key_expiry', {
            p_id: item.id,
            p_expires_at: expiresAt,
        });
        if (error) {
            toast(friendlyError(error), 'error');
            return;
        }
    }

    toast(`Expiry set on ${items.length} key${items.length === 1 ? '' : 's'}.`, 'ok');
    state.selected.clear();
    await loadKeys();
}

async function bulkValidate() {
    const items = selectedItems();
    if (items.length === 0) return;

    toast(`Validating ${items.length} key${items.length === 1 ? '' : 's'}…`, 'info');

    // Sequential, so providers are not stampeded and every verdict is stored.
    for (const item of items) {
        await testKey(item);
    }

    toast('Bulk validation finished.', 'ok');
}

/* ==================================================================== *
 * Export — metadata only, never a secret
 * ==================================================================== */
function exportPayload(items) {
    return {
        exported_at: new Date().toISOString(),
        count: items.length,
        // Stated explicitly so the file can never be mistaken for a backup
        // of the credentials themselves.
        secrets_included: false,
        keys: items.map((item) => {
            const group = groupFor(item);
            return {
                label: item.label,
                provider: item.provider,
                description: item.description,
                api_base_url: item.api_base_url,
                group: group ? group.name : null,
                key_last4: item.key_last4,
                key_fingerprint: item.key_fingerprint,
                expires_at: item.expires_at,
                expired: isExpired(item),
                last_check_at: item.last_check_at,
                last_check_ok: item.last_check_ok,
                created_at: item.created_at,
                updated_at: item.updated_at,
            };
        }),
    };
}

function exportKeys(items, suffix) {
    if (items.length === 0) {
        toast('Nothing to export.', 'error');
        return;
    }
    const stamp = new Date().toISOString().slice(0, 10);
    downloadJson(`${EXPORT_FILENAME_PREFIX}-${suffix}-${stamp}.json`, exportPayload(items));
    toast(
        `Exported ${items.length} key${items.length === 1 ? '' : 's'} — metadata only, no secrets.`,
        'ok',
        5200,
    );
}

/* ==================================================================== *
 * Overview — keys needing attention
 * ==================================================================== */
function renderExpiring() {
    const flagged = state.keys
        .filter((item) => isExpired(item) || isExpiringSoon(item))
        .sort((a, b) => new Date(a.expires_at) - new Date(b.expires_at));

    if (flagged.length === 0) {
        el.expiringPanel.hidden = true;
        el.expiring.replaceChildren();
        return;
    }

    el.expiringPanel.hidden = false;

    el.expiring.replaceChildren(
        node('div', { class: 'activity' }, flagged.map((item) => {
            const expired = isExpired(item);
            return node('div', { class: 'activity__row' }, [
                node('span', {
                    class: `activity__glyph${expired ? ' activity__glyph--fail' : ' activity__glyph--warn'}`,
                }, [icon('i-calendar')]),
                node('span', { class: 'activity__main' }, [
                    node('span', { class: 'activity__name', text: item.label || `${item.provider} key` }),
                    node('span', {
                        class: 'activity__meta',
                        text: `${expiryLabel(item)} · ${formatDateTime(item.expires_at)}`,
                    }),
                ]),
                node('span', { class: 'activity__tail' }, [quickExtendButton(item)]),
            ]);
        })),
    );
}

/* ==================================================================== *
 * Usage
 * ==================================================================== */
function formatTokens(value) {
    if (value === null || value === undefined) return '—';
    return new Intl.NumberFormat().format(value);
}

function formatCost(value) {
    const amount = Number(value);
    if (!Number.isFinite(amount)) return '—';
    if (amount === 0) return '$0.00';
    if (amount < 0.01) return `$${amount.toFixed(4)}`;
    return `$${amount.toFixed(2)}`;
}

function renderUsage() {
    const rows = state.usage;
    const succeeded = rows.filter((row) => row.ok);
    const totalTokens = succeeded.reduce((sum, row) => sum + (row.total_tokens ?? 0), 0);
    const totalCost = succeeded.reduce((sum, row) => sum + (Number(row.cost_usd) || 0), 0);
    const failures = rows.filter((row) => !row.ok).length;
    const priced = succeeded.filter((row) => row.cost_usd !== null && row.cost_usd !== undefined).length;

    const estimated = priced < succeeded.length;

    el.usageStats.replaceChildren(
        statCard({
            glyph: 'i-pulse',
            tone: 'brand',
            label: 'Requests',
            value: rows.length,
            note: `Last ${rows.length ? USAGE_PAGE_SIZE : 0} shown`,
        }),
        statCard({
            glyph: 'i-key',
            label: 'Tokens',
            value: formatTokens(totalTokens),
            note: 'Prompt plus completion',
        }),
        statCard({
            glyph: 'i-gauge',
            label: 'Estimated spend',
            value: formatCost(totalCost),
            note: estimated ? 'Some rows unpriced' : 'Based on the pricing table',
        }),
        statCard({
            glyph: failures > 0 ? 'i-shield-alert' : 'i-shield-check',
            tone: failures > 0 ? 'warn' : 'ok',
            label: 'Errors',
            value: failures,
            note: failures === 0 ? 'All requests succeeded' : 'Check the status column',
        }),
    );

    /* -- Spend grouped by key -- */
    const byKey = new Map();
    for (const row of succeeded) {
        const entry = byKey.get(row.key_id) ?? { tokens: 0, cost: 0, count: 0 };
        entry.tokens += row.total_tokens ?? 0;
        entry.cost += Number(row.cost_usd) || 0;
        entry.count += 1;
        byKey.set(row.key_id, entry);
    }

    const keyNames = new Map(state.keys.map((item) => [item.id, item.label || item.provider]));

    if (byKey.size === 0) {
        el.usageByKey.replaceChildren(
            node('p', { class: 'breakdown__empty', text: 'No usage recorded yet.' }),
        );
    } else {
        const rowsByKey = [...byKey.entries()].sort((a, b) => b[1].cost - a[1].cost);
        const topCost = rowsByKey[0][1].cost || 1;

        el.usageByKey.replaceChildren(
            node('div', { class: 'breakdown' }, rowsByKey.map(([keyId, entry]) => {
                const percent = Math.round((entry.cost / topCost) * 100);
                return node('div', { class: 'breakdown__row' }, [
                    node('div', { class: 'breakdown__head' }, [
                        node('span', { class: 'breakdown__value', text: keyNames.get(keyId) ?? 'Deleted key' }),
                        node('span', { class: 'breakdown__cost', text: formatCost(entry.cost) }),
                    ]),
                    node('div', {
                        class: 'meter',
                        role: 'img',
                        'aria-label': `${keyNames.get(keyId) ?? 'Deleted key'}: ${formatCost(entry.cost)} across ${entry.count} requests`,
                    }, [node('span', { class: 'meter__fill', style: `inline-size:${Math.max(percent, 2)}%` })]),
                    node('span', {
                        class: 'estimate-tag',
                        text: `${entry.count} request${entry.count === 1 ? '' : 's'} · ${formatTokens(entry.tokens)} tokens`,
                    }),
                ]);
            })),
        );
    }

    /* -- Spend grouped by model -- */
    const byModel = new Map();
    for (const row of succeeded) {
        const name = row.model || 'Unknown model';
        const entry = byModel.get(name) ?? { tokens: 0, cost: 0, count: 0 };
        entry.tokens += row.total_tokens ?? 0;
        entry.cost += Number(row.cost_usd) || 0;
        entry.count += 1;
        byModel.set(name, entry);
    }

    if (byModel.size === 0) {
        el.usageByModel.replaceChildren(
            node('p', { class: 'breakdown__empty', text: 'No usage recorded yet.' }),
        );
    } else {
        const rowsByModel = [...byModel.entries()].sort((a, b) => b[1].cost - a[1].cost);
        const topCost = rowsByModel[0][1].cost || 1;

        el.usageByModel.replaceChildren(
            node('div', { class: 'breakdown' }, rowsByModel.map(([name, entry]) => {
                const percent = Math.round((entry.cost / topCost) * 100);
                return node('div', { class: 'breakdown__row' }, [
                    node('div', { class: 'breakdown__head' }, [
                        node('span', { class: 'breakdown__value' }, [
                            node('code', { class: 'usage-model', text: name }),
                        ]),
                        node('span', { class: 'breakdown__cost', text: formatCost(entry.cost) }),
                    ]),
                    node('div', {
                        class: 'meter',
                        role: 'img',
                        'aria-label': `${name}: ${formatCost(entry.cost)} across ${entry.count} requests`,
                    }, [node('span', { class: 'meter__fill', style: `inline-size:${Math.max(percent, 2)}%` })]),
                    node('span', {
                        class: 'estimate-tag',
                        text: `${entry.count} request${entry.count === 1 ? '' : 's'} · ${formatTokens(entry.tokens)} tokens`,
                    }),
                ]);
            })),
        );
    }

    /* -- Recent requests -- */
    if (rows.length === 0) {
        el.usageTable.hidden = true;
        el.usageEmpty.hidden = false;
        return;
    }

    el.usageEmpty.hidden = true;
    el.usageTable.hidden = false;

    el.usageTableBody.replaceChildren(...rows.map((row) => {
        const ok = row.ok;
        return node('tr', {}, [
            node('td', {
                class: 'cell-time',
                text: formatRelative(row.created_at),
                title: formatDateTime(row.created_at),
            }),
            node('td', { class: 'cell-name__sub', text: keyNames.get(row.key_id) ?? 'Deleted key' }),
            node('td', {}, [node('code', { class: 'usage-model', text: row.model || '—' })]),
            node('td', {}, [
                ok
                    ? node('span', { class: 'pill pill--ok' }, [
                        icon('i-check'),
                        node('span', { class: 'pill__text', text: String(row.status_code ?? 'OK') }),
                    ])
                    : node('span', { class: 'pill pill--fail' }, [
                        icon('i-alert'),
                        node('span', { class: 'pill__text', text: String(row.status_code || 'Error') }),
                    ]),
            ]),
            node('td', { class: 'num muted-cell', text: formatTokens(row.total_tokens) }),
            node('td', { class: 'num cost', text: formatCost(row.cost_usd) }),
            node('td', { class: 'num muted-cell', text: row.latency_ms ? `${row.latency_ms} ms` : '—' }),
        ]);
    }));
}

function renderProxyEndpoint() {
    el.proxyEndpoint.textContent = `${SUPABASE_URL}/functions/v1/${PROXY_FUNCTION_NAME}/v1/chat/completions`;
}

async function copyEndpoint(button) {
    const value = el.proxyEndpoint.textContent;
    if (!value || !(await copyText(value))) {
        toast('Copying is blocked here. Select the URL and copy it manually.', 'error');
        return;
    }

    const label = button.querySelector('.btn__label');
    if (label) {
        label.textContent = 'Copied';
        setTimeout(() => { label.textContent = 'Copy'; }, 1400);
    }
    toast('Proxy URL copied.', 'ok');
}

async function copyNewToken(button) {
    // Taken from memory, never from the DOM, and cleared on dialog close.
    const value = state.newTokenValue;
    if (!value) return;

    if (!(await copyText(value))) {
        toast('Copying is blocked here. Select the token and copy it manually.', 'error');
        return;
    }

    const label = button.querySelector('.btn__label');
    if (label) {
        label.textContent = 'Copied';
        setTimeout(() => { label.textContent = 'Copy'; }, 1400);
    }
    toast('Proxy token copied. Store it somewhere safe.', 'ok');
}

function initKeyDialog() {
    el.keyForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        clearFormError(el.keyError);

        const provider = el.fProvider.value;
        const apiKey = el.fApiKey.value.trim();
        const label = el.fLabel.value.trim();
        const description = el.fDescription.value.trim();
        const baseUrl = el.fBaseUrl.value.trim();
        const groupId = el.fGroup.value || null;
        const isEdit = Boolean(state.editingId);

        if (el.fExpiry.value === 'custom' && !el.fExpiryCustom.value) {
            el.fExpiryCustom.setAttribute('aria-invalid', 'true');
            el.fExpiryCustom.focus();
            showFormError(el.keyError, 'Choose the date and time the key should expire.');
            return;
        }
        const expiresAt = expiresAtFromPreset(el.fExpiry.value, el.fExpiryCustom.value);

        if (!isEdit && !apiKey) {
            el.fApiKey.setAttribute('aria-invalid', 'true');
            el.fApiKey.focus();
            showFormError(el.keyError, 'Enter the API key you want to store.');
            return;
        }

        if (baseUrl && !/^https?:\/\//i.test(baseUrl)) {
            el.fBaseUrl.setAttribute('aria-invalid', 'true');
            el.fBaseUrl.focus();
            showFormError(el.keyError, 'The base URL must begin with http:// or https://');
            return;
        }

        el.dialogSave.disabled = true;
        el.dialogSave.dataset.busy = 'true';

        // Mutations go through SECURITY DEFINER RPCs — never direct table writes.
        const { error } = isEdit
            ? await supabase.rpc('update_api_key', {
                p_id: state.editingId,
                p_provider: provider,
                p_label: label || null,
                p_description: description || null,
                p_api_base_url: baseUrl || null,
                p_api_key: apiKey || null,   // null preserves the stored ciphertext
                p_expires_at: expiresAt,
                p_group_id: groupId,
            })
            : await supabase.rpc('create_api_key', {
                p_provider: provider,
                p_api_key: apiKey,
                p_label: label || null,
                p_description: description || null,
                p_api_base_url: baseUrl || null,
                p_expires_at: expiresAt,
                p_group_id: groupId,
            });

        el.dialogSave.disabled = false;
        delete el.dialogSave.dataset.busy;

        if (error) {
            showFormError(el.keyError, friendlyError(error));
            return;
        }

        el.fApiKey.value = '';   // never leave plaintext in the DOM
        closeKeyDialog();
        toast(isEdit ? 'Key updated.' : 'Key added and encrypted.', 'ok');
        await loadKeys();
    });
}

/* ==================================================================== *
 * Delete
 * ==================================================================== */
function confirmDelete(item) {
    state.pendingAction = { kind: 'delete-key', ids: [item.id] };
    el.confirmTitle.textContent = 'Delete this key?';
    el.confirmText.textContent = `“${item.label || item.provider}” will be removed from your vault.`;
    el.confirmNote.hidden = false;
    el.confirmNote.textContent = 'This removes the encrypted record permanently. A copy held elsewhere is unaffected.';
    el.confirmOkLabel.textContent = 'Delete key';
    el.confirmDialog.showModal();
}

function confirmBulkDelete() {
    const items = selectedItems();
    if (items.length === 0) return;

    state.pendingAction = { kind: 'delete-keys', ids: items.map((item) => item.id) };
    el.confirmTitle.textContent = `Delete ${items.length} key${items.length === 1 ? '' : 's'}?`;
    el.confirmText.textContent = 'The selected keys will be removed from your vault.';
    el.confirmNote.hidden = false;
    el.confirmNote.textContent = 'This removes the encrypted records permanently. Copies held elsewhere are unaffected.';
    el.confirmOkLabel.textContent = `Delete ${items.length === 1 ? 'key' : 'keys'}`;
    el.confirmDialog.showModal();
}

/** Carry out whichever destructive action the confirm dialog is showing. */
async function runPendingAction() {
    const action = state.pendingAction;
    if (!action) return;

    el.confirmOk.disabled = true;
    el.confirmOk.dataset.busy = 'true';

    let error = null;

    if (action.kind === 'delete-key' || action.kind === 'delete-keys') {
        for (const id of action.ids) {
            const result = await supabase.rpc('delete_api_key', { p_id: id });
            if (result.error) { error = result.error; break; }
        }
    } else if (action.kind === 'delete-group') {
        const result = await supabase.rpc('delete_key_group', { p_id: action.ids[0] });
        error = result.error;
    }

    el.confirmOk.disabled = false;
    delete el.confirmOk.dataset.busy;
    el.confirmDialog.close();

    if (error) {
        toast(friendlyError(error), 'error');
        return;
    }

    if (action.kind === 'delete-group') {
        toast('Group deleted. Its keys are now ungrouped.', 'ok');
        await Promise.all([loadGroups(), loadKeys()]);
    } else {
        for (const id of action.ids) {
            state.selected.delete(id);
            hideKey(id);
        }
        toast(
            action.ids.length === 1 ? 'Key deleted.' : `${action.ids.length} keys deleted.`,
            'ok',
        );
        await loadKeys();
    }

    state.pendingAction = null;
}

function initConfirmDialog() {
    el.confirmOk.addEventListener('click', runPendingAction);
}

/* ==================================================================== *
 * Toolbar wiring
 * ==================================================================== */
let searchTimer = null;

function initToolbar() {
    el.search.addEventListener('input', () => {
        const value = el.search.value;
        el.searchClear.hidden = value.length === 0;
        el.searchKbd.toggleAttribute('hidden', value.length > 0);
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => {
            state.query = value;
            renderKeys();
        }, SEARCH_DEBOUNCE_MS);
    });

    el.searchClear.addEventListener('click', () => {
        el.search.value = '';
        el.searchClear.hidden = true;
        el.searchKbd.hidden = false;
        state.query = '';
        renderKeys();
        el.search.focus();
    });

    el.sort.addEventListener('change', () => {
        state.sort = el.sort.value;
        renderKeys();
    });

    // Ctrl/Cmd+K focuses search from anywhere.
    document.addEventListener('keydown', (event) => {
        if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
            event.preventDefault();
            if (window.location.hash !== '#keys') {
                window.location.hash = '#keys';
                setTimeout(() => el.search.focus(), 30);
            } else {
                el.search.focus();
                el.search.select();
            }
        }
    });

    // Match the shortcut hint to the platform.
    if (/Mac|iPhone|iPad/i.test(navigator.platform || navigator.userAgent)) {
        el.searchKbd.textContent = '⌘K';
    }

    // Hide plaintext the moment the tab loses visibility.
    document.addEventListener('visibilitychange', () => {
        if (document.hidden && state.revealed.size > 0) {
            clearRevealed();
            renderAll();
        }
    });
}

/* ==================================================================== *
 * Global click delegation for data-action buttons
 * ==================================================================== */
function initActions() {
    document.addEventListener('click', (event) => {
        const trigger = event.target.closest('[data-action]');
        if (!trigger) return;

        switch (trigger.dataset.action) {
            case 'add':
                openKeyDialog();
                break;
            case 'logout':
                signOut();
                break;
            case 'dialog-close':
                closeKeyDialog();
                break;
            case 'confirm-cancel':
                el.confirmDialog.close();
                state.pendingAction = null;
                break;
            case 'toggle-secret': {
                const revealed = el.fApiKey.type === 'text';
                el.fApiKey.type = revealed ? 'password' : 'text';
                trigger.replaceChildren(icon(revealed ? 'i-eye' : 'i-eye-off'));
                trigger.setAttribute('aria-label', revealed ? 'Show the key as you type' : 'Hide the key');
                el.fApiKey.focus();
                break;
            }
            case 'new-token':
                openTokenDialog();
                break;
            case 'token-close':
                closeTokenDialog();
                break;
            case 'refresh-usage':
                loadUsage();
                toast('Usage refreshed.', 'info');
                break;
            case 'copy-endpoint':
                copyEndpoint(trigger);
                break;
            case 'copy-token':
                copyNewToken(trigger);
                break;
            case 'new-group':
                openGroupDialog();
                break;
            case 'group-close':
                closeGroupDialog();
                break;
            case 'export-keys':
                exportKeys(visibleKeys(), 'filtered');
                break;
            case 'bulk-group':
                bulkAssignGroup();
                break;
            case 'bulk-expiry':
                bulkSetExpiry();
                break;
            case 'bulk-validate':
                bulkValidate();
                break;
            case 'bulk-export':
                exportKeys(selectedItems(), 'selected');
                break;
            case 'bulk-delete':
                confirmBulkDelete();
                break;
            case 'bulk-clear':
                clearSelection();
                break;
            default:
                break;
        }
    });

    // Auto-fill the base URL whenever the provider changes.
    el.fProvider.addEventListener('change', () => {
        applyProviderUrl(el.fProvider.value, { force: true });
    });

    // Reveal the date picker only for the "custom" expiry option.
    el.fExpiry.addEventListener('change', () => {
        el.fExpiryCustomWrap.hidden = el.fExpiry.value !== 'custom';
        if (el.fExpiry.value === 'custom') el.fExpiryCustom.focus();
    });

    el.groupForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        await saveGroup();
    });

    el.groupDialog.addEventListener('close', () => {
        state.editingGroupId = null;
    });

    el.tokenForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        await createToken();
    });

    el.tokenDialog.addEventListener('close', () => {
        state.newTokenValue = null;
        el.tokenReveal.hidden = true;
        el.tokenValue.textContent = '';
    });

    // Clicking the backdrop dismisses a dialog.
    for (const dialog of [el.keyDialog, el.confirmDialog, el.tokenDialog, el.groupDialog]) {
        dialog.addEventListener('click', (event) => {
            if (event.target === dialog) dialog.close();
        });
    }

    el.keyDialog.addEventListener('close', () => {
        state.editingId = null;
    });

    el.confirmDialog.addEventListener('close', () => {
        state.pendingAction = null;
    });

    // Clear the invalid flag as soon as the person corrects the field.
    for (const input of [el.fApiKey, el.fBaseUrl, el.fExpiryCustom]) {
        input.addEventListener('input', () => input.setAttribute('aria-invalid', 'false'));
    }
}

/* ==================================================================== *
 * Bootstrap
 * ==================================================================== */
async function main() {
    const syncFromHash = initRouter();

    initTheme();
    initAuth();
    initToolbar();
    initKeyDialog();
    initConfirmDialog();
    initActions();

    el.fProvider.replaceChildren(...PROVIDERS.map((name) => node('option', { value: name, text: name })));

    // Expiry presets are static, so they can be built once at boot. Groups
    // are per-user and are populated each time a dialog opens.
    el.fExpiry.replaceChildren(
        ...EXPIRY_PRESETS.map((preset) => node('option', { value: preset.value, text: preset.label })),
    );

    // Keep relative expiry labels ("in 3 days") honest without a reload.
    // Only re-renders when at least one key actually carries an expiry.
    setInterval(() => {
        if (el.app.hidden) return;
        if (state.keys.some((item) => item.expires_at)) renderAll();
    }, 60_000);

    const { data, error } = await supabase.auth.getSession();
    if (error || !data?.session?.user) {
        enterAuthScreen();
        syncFromHash();
        return;
    }

    await enterApp(data.session.user);
    syncFromHash();
}

main();