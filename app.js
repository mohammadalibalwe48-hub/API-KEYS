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
} from './config.js';

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
    'created_at', 'updated_at',
].join(', ');

const VIEWS = {
    overview: { title: 'Overview', subtitle: 'A summary of every key you hold.' },
    keys: { title: 'API keys', subtitle: 'Stored, encrypted and validated on demand.' },
    account: { title: 'Account', subtitle: 'Your identity and workspace preferences.' },
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
    viewAccount: $('view-account'),
    stats: $('stats'),
    providerBreakdown: $('provider-breakdown'),
    activity: $('activity'),

    // Keys
    search: $('search'),
    searchKbd: $('search-kbd'),
    searchClear: $('search-clear'),
    sort: $('sort'),
    providerFilters: $('provider-filters'),
    resultLine: $('result-line'),
    keysHost: $('keys-host'),
    keysEmpty: $('keys-empty'),

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
    keyOptional: $('key-optional'),

    confirmDialog: $('confirm-dialog'),
    confirmText: $('confirm-text'),
    confirmOk: $('confirm-ok'),

    toasts: $('toasts'),
};

/* ==================================================================== *
 * In-memory state. Nothing here is ever persisted.
 * ==================================================================== */
const state = {
    user: null,
    keys: [],
    checks: new Map(),      // id -> { state, message, status, at }
    revealed: new Map(),    // id -> plaintext, only while revealed
    revealTimers: new Map(),
    query: '',
    providerFilter: 'All',
    sort: 'updated',
    view: 'overview',
    editingId: null,
    pendingDeleteId: null,
    busyIds: new Set(),
    channel: null,
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
    clearRevealed();
    state.keys = [];
    state.checks.clear();
    state.user = null;
    state.busyIds.clear();

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
    el.sort.value = 'updated';
    state.sort = 'updated';

    renderSkeleton();
    await loadKeys();
    subscribeRealtime();
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

/* ==================================================================== *
 * Selection: filter + sort
 * ==================================================================== */
function visibleKeys() {
    const query = state.query.trim().toLowerCase();

    const filtered = state.keys.filter((item) => {
        if (state.providerFilter !== 'All' && item.provider !== state.providerFilter) return false;
        if (!query) return true;
        return [item.provider, item.label, item.description, item.api_base_url, item.key_last4]
            .filter(Boolean)
            .some((value) => String(value).toLowerCase().includes(query));
    });

    const sorters = {
        updated: (a, b) => new Date(b.updated_at) - new Date(a.updated_at),
        created: (a, b) => new Date(b.created_at) - new Date(a.created_at),
        provider: (a, b) => a.provider.localeCompare(b.provider) || (a.label ?? '').localeCompare(b.label ?? ''),
        name: (a, b) => (a.label ?? a.provider).localeCompare(b.label ?? b.provider),
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

/* ==================================================================== *
 * Rendering — table row & card
 * ==================================================================== */
function tableRow(item) {
    const baseUrl = item.api_base_url;

    return node('tr', {}, [
        node('td', { class: 'cell-name' }, [
            node('span', { class: 'cell-name__title', text: item.label || `${item.provider} key` }),
            node('span', {
                class: 'cell-name__sub',
                text: item.description || (baseUrl ? baseUrl.replace(/^https?:\/\//i, '') : 'No description'),
            }),
        ]),
        node('td', { class: 'cell-provider' }, [providerChip(item.provider)]),
        node('td', { class: 'cell-key' }, [secretControl(item)]),
        node('td', {}, [checkPill(item)]),
        node('td', { class: 'cell-time', text: formatRelative(item.updated_at), title: formatDateTime(item.updated_at) }),
        node('td', { class: 'cell-actions' }, [keyActions(item)]),
    ]);
}

function keyCard(item) {
    const baseUrl = item.api_base_url;
    const isLink = typeof baseUrl === 'string' && /^https?:\/\//i.test(baseUrl);

    const metaRows = [];

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

    return node('article', { class: 'card' }, [
        node('div', { class: 'card__head' }, [
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

function renderKeys() {
    renderFilters();

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
                            node('th', { scope: 'col', text: 'Name' }),
                            node('th', { scope: 'col', text: 'Provider' }),
                            node('th', { scope: 'col', text: 'API key' }),
                            node('th', { scope: 'col', text: 'Validation' }),
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
    return { total, verified, failed, untested };
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
            glyph: 'i-shield-alert',
            tone: summary.failed > 0 ? 'warn' : undefined,
            label: 'Needs attention',
            value: summary.failed,
            note: summary.failed === 0 ? 'Nothing flagged' : 'Review the validation messages',
        }),
        statCard({
            glyph: 'i-clock',
            label: 'Untested',
            value: summary.untested,
            note: 'Run a check to confirm these',
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
    clearFormError(el.keyError);

    el.keyDialog.showModal();
    (isEdit ? el.fLabel : el.fApiKey).focus();
}

function closeKeyDialog() {
    if (el.keyDialog.open) el.keyDialog.close();
    state.editingId = null;
    el.fApiKey.value = '';
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
        const isEdit = Boolean(state.editingId);

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
            })
            : await supabase.rpc('create_api_key', {
                p_provider: provider,
                p_api_key: apiKey,
                p_label: label || null,
                p_description: description || null,
                p_api_base_url: baseUrl || null,
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
    state.pendingDeleteId = item.id;
    el.confirmText.textContent =
        `“${item.label || item.provider}” will be removed from your vault.`;
    el.confirmDialog.showModal();
}

function initConfirmDialog() {
    el.confirmOk.addEventListener('click', async () => {
        const id = state.pendingDeleteId;
        if (!id) return;

        el.confirmOk.disabled = true;
        el.confirmOk.dataset.busy = 'true';

        const { error } = await supabase.rpc('delete_api_key', { p_id: id });

        el.confirmOk.disabled = false;
        delete el.confirmOk.dataset.busy;
        el.confirmDialog.close();
        state.pendingDeleteId = null;

        if (error) {
            toast(friendlyError(error), 'error');
            return;
        }

        hideKey(id);
        toast('Key deleted.', 'ok');
        await loadKeys();
    });
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
                state.pendingDeleteId = null;
                break;
            case 'toggle-secret': {
                const revealed = el.fApiKey.type === 'text';
                el.fApiKey.type = revealed ? 'password' : 'text';
                trigger.replaceChildren(icon(revealed ? 'i-eye' : 'i-eye-off'));
                trigger.setAttribute('aria-label', revealed ? 'Show the key as you type' : 'Hide the key');
                el.fApiKey.focus();
                break;
            }
            default:
                break;
        }
    });

    // Clicking the backdrop dismisses a dialog.
    for (const dialog of [el.keyDialog, el.confirmDialog]) {
        dialog.addEventListener('click', (event) => {
            if (event.target === dialog) dialog.close();
        });
    }

    el.keyDialog.addEventListener('close', () => {
        state.editingId = null;
    });

    el.confirmDialog.addEventListener('close', () => {
        state.pendingDeleteId = null;
    });

    // Clear the invalid flag as soon as the person corrects the field.
    for (const input of [el.fApiKey, el.fBaseUrl]) {
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