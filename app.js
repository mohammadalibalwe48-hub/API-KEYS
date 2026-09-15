/**
 * KeyVault — AI API key manager (frontend)
 * ---------------------------------------------------------------------
 * Security model:
 *  - Only the publishable (anon) key is used. No service-role key exists
 *    anywhere in the frontend.
 *  - The browser reads key *metadata* directly, filtered by RLS, which
 *    limits rows to the signed-in user.
 *  - Creating, updating, deleting and decrypting always go through
 *    Postgres RPCs (SECURITY DEFINER) that re-verify ownership in the
 *    database. Plaintext keys are decrypted on demand only, held in
 *    memory, auto-hidden after REVEAL_TIMEOUT_MS, and never written to
 *    storage, the URL, or the console.
 *  - All user-controlled strings are rendered with textContent — never
 *    innerHTML — so stored content cannot inject markup.
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

/* ------------------------------------------------------------------ *
 * DOM references
 * ------------------------------------------------------------------ */
const ui = {
    authView: document.getElementById('auth-view'),
    appView: document.getElementById('app-view'),

    tabLogin: document.getElementById('tab-login'),
    tabSignup: document.getElementById('tab-signup'),
    loginForm: document.getElementById('login-form'),
    signupForm: document.getElementById('signup-form'),
    loginEmail: document.getElementById('login-email'),
    loginPassword: document.getElementById('login-password'),
    signupEmail: document.getElementById('signup-email'),
    signupPassword: document.getElementById('signup-password'),

    userEmail: document.getElementById('user-email'),
    logoutBtn: document.getElementById('logout-btn'),
    syncStatus: document.getElementById('sync-status'),
    syncLabel: document.getElementById('sync-label'),

    search: document.getElementById('search'),
    addBtn: document.getElementById('add-btn'),
    emptyAddBtn: document.getElementById('empty-add-btn'),
    chips: document.getElementById('provider-chips'),
    listStatus: document.getElementById('list-status'),
    grid: document.getElementById('key-grid'),
    emptyState: document.getElementById('empty-state'),

    dialog: document.getElementById('key-dialog'),
    dialogTitle: document.getElementById('dialog-title'),
    dialogClose: document.getElementById('dialog-close'),
    dialogCancel: document.getElementById('dialog-cancel'),
    keyForm: document.getElementById('key-form'),
    fProvider: document.getElementById('f-provider'),
    fApiKey: document.getElementById('f-api-key'),
    fLabel: document.getElementById('f-label'),
    fDescription: document.getElementById('f-description'),
    fBaseUrl: document.getElementById('f-base-url'),
    keyOptional: document.getElementById('key-optional'),
    toggleKeyVisibility: document.getElementById('toggle-key-visibility'),

    confirmDialog: document.getElementById('confirm-dialog'),
    confirmText: document.getElementById('confirm-text'),
    confirmCancel: document.getElementById('confirm-cancel'),
    confirmOk: document.getElementById('confirm-ok'),

    toast: document.getElementById('toast'),
};

/* ------------------------------------------------------------------ *
 * App state (in memory only — never persisted)
 * ------------------------------------------------------------------ */
const state = {
    user: null,
    keys: [],
    query: '',
    providerFilter: 'All',
    revealed: new Map(),   // id -> plaintext (only while revealed)
    revealTimers: new Map(),
    editingId: null,
    pendingDeleteId: null,
    realtimeChannel: null,
    checks: new Map(),     // id -> { state, message, status, at } for live probes
};

const MASK = '••••••••••••••';

/* ------------------------------------------------------------------ *
 * Small utilities
 * ------------------------------------------------------------------ */
function el(tag, props = {}, children = []) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
        if (value === undefined || value === null) continue;
        if (key === 'class') node.className = value;
        else if (key === 'text') node.textContent = value;
        else if (key === 'dataset') Object.assign(node.dataset, value);
        else if (key.startsWith('on') && typeof value === 'function') {
            node.addEventListener(key.slice(2).toLowerCase(), value);
        } else if (value === true) node.setAttribute(key, '');
        else node.setAttribute(key, value);
    }
    for (const child of [].concat(children)) {
        if (child === null || child === undefined || child === false) continue;
        node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
}

/**
 * Supabase/Postgres errors carry technical text. Map the common ones to
 * something a person can act on, without leaking internals.
 */
function friendlyError(error) {
    if (!error) return 'Something went wrong.';
    const code = error.code || '';
    const msg = (error.message || '').toLowerCase();
    if (msg.includes('invalid login credentials')) return 'Email or password is incorrect.';
    if (msg.includes('email not confirmed')) return 'Please confirm your email address first.';
    if (msg.includes('user already registered')) return 'That email is already registered. Try logging in.';
    if (msg.includes('not authenticated')) return 'Your session expired. Please log in again.';
    if (msg.includes('not found')) return 'That key no longer exists.';
    if (msg.includes('cannot be empty')) return 'Please enter the API key.';
    if (code === '23505') return 'That value already exists.';
    if (msg.includes('password should be at least')) return 'Password must be at least 6 characters.';
    if (msg.includes('failed to fetch') || msg.includes('networkerror')) {
        return 'Network problem. Check your connection and try again.';
    }
    return error.message || 'Something went wrong.';
}

let toastTimer = null;
function toast(message, kind = 'info') {
    ui.toast.textContent = message;
    ui.toast.dataset.kind = kind;
    ui.toast.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { ui.toast.hidden = true; }, kind === 'error' ? 5000 : 2600);
}

async function copyText(text) {
    try {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
            return true;
        }
    } catch { /* fall through to legacy path */ }

    // Fallback for non-secure contexts (e.g. plain http on a LAN IP).
    const ta = el('textarea', { style: 'position:fixed;top:-1000px;opacity:0' });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.remove();
    return ok;
}

const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
function formatDate(iso) {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? '' : dateFmt.format(d);
}

function maskFor(item) {
    return item.key_last4 ? `${MASK}${item.key_last4}` : MASK;
}

/* ------------------------------------------------------------------ *
 * Auth screen
 * ------------------------------------------------------------------ */
function switchAuthTab(mode) {
    const isLogin = mode === 'login';
    ui.tabLogin.classList.toggle('is-active', isLogin);
    ui.tabSignup.classList.toggle('is-active', !isLogin);
    ui.tabLogin.setAttribute('aria-selected', String(isLogin));
    ui.tabSignup.setAttribute('aria-selected', String(!isLogin));
    ui.loginForm.hidden = !isLogin;
    ui.signupForm.hidden = isLogin;
    (isLogin ? ui.loginEmail : ui.signupEmail).focus();
}

ui.tabLogin.addEventListener('click', () => switchAuthTab('login'));
ui.tabSignup.addEventListener('click', () => switchAuthTab('signup'));

function setBusy(form, busy) {
    const button = form.querySelector('button[type="submit"]');
    if (!button) return;
    if (busy) {
        button.dataset.label = button.textContent;
        button.disabled = true;
        button.textContent = 'Please wait…';
    } else {
        button.disabled = false;
        if (button.dataset.label) button.textContent = button.dataset.label;
    }
}

ui.loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const email = ui.loginEmail.value.trim();
    const password = ui.loginPassword.value;
    if (!email || !password) return toast('Enter your email and password.', 'error');

    setBusy(ui.loginForm, true);
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    setBusy(ui.loginForm, false);

    if (error) return toast(friendlyError(error), 'error');
    ui.loginForm.reset();
});

ui.signupForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const email = ui.signupEmail.value.trim();
    const password = ui.signupPassword.value;
    if (!email || !password) return toast('Enter an email and password.', 'error');
    if (password.length < 6) return toast('Password must be at least 6 characters.', 'error');

    setBusy(ui.signupForm, true);
    const { data, error } = await supabase.auth.signUp({ email, password });
    setBusy(ui.signupForm, false);

    if (error) return toast(friendlyError(error), 'error');
    ui.signupForm.reset();

    if (data.session) toast('Account created. Welcome!', 'success');
    else toast('Account created. Check your email to confirm, then log in.', 'success');
});

ui.logoutBtn.addEventListener('click', async () => {
    await supabase.auth.signOut();
    toast('Logged out.');
});

/* ------------------------------------------------------------------ *
 * Session / view switching
 * ------------------------------------------------------------------ */
function showAuth() {
    teardownRealtime();
    clearRevealed();
    state.keys = [];
    state.checks.clear();
    state.user = null;
    ui.appView.hidden = true;
    ui.authView.hidden = false;
    ui.loginPassword.value = '';
    ui.signupPassword.value = '';
    switchAuthTab('login');
}

async function showApp(user) {
    state.user = user;
    ui.userEmail.textContent = user.email || '';
    ui.authView.hidden = true;
    ui.appView.hidden = false;
    ui.search.value = '';
    state.query = '';
    state.providerFilter = 'All';
    renderSkeletons();
    await loadKeys();
    subscribeRealtime();
}

supabase.auth.onAuthStateChange((event, session) => {
    // Defer so supabase-js finishes its internal lock handling first.
    setTimeout(() => {
        if (session?.user) showApp(session.user);
        else showAuth();
    }, 0);
});

/* ------------------------------------------------------------------ *
 * Loading & realtime
 * ------------------------------------------------------------------ */
const KEY_COLUMNS = 'id, provider, label, description, api_base_url, key_last4, key_fingerprint, '
    + 'last_check_at, last_check_ok, last_check_status, last_check_message, created_at, updated_at';

function renderSkeletons() {
    ui.grid.replaceChildren(...Array.from({ length: 3 }, () => el('div', { class: 'skeleton' })));
    ui.emptyState.hidden = true;
    ui.listStatus.textContent = 'Loading your keys…';
}

async function loadKeys() {
    const { data, error } = await supabase
        .from('api_keys')
        .select(KEY_COLUMNS)
        .order('created_at', { ascending: false });

    if (error) {
        ui.grid.replaceChildren();
        ui.listStatus.textContent = '';
        toast(friendlyError(error), 'error');
        return;
    }
    state.keys = data ?? [];
    render();
}

function setSyncStatus(stateName, label) {
    ui.syncStatus.dataset.state = stateName;
    ui.syncLabel.textContent = label;
}

function teardownRealtime() {
    if (state.realtimeChannel) {
        supabase.removeChannel(state.realtimeChannel);
        state.realtimeChannel = null;
    }
}

function subscribeRealtime() {
    teardownRealtime();
    if (!state.user) return;

    setSyncStatus('connecting', 'Syncing');
    state.realtimeChannel = supabase
        .channel(`api_keys:${state.user.id}`)
        .on(
            'postgres_changes',
            {
                event: '*',
                schema: 'public',
                table: 'api_keys',
                filter: `user_id=eq.${state.user.id}`,
            },
            () => { loadKeys(); },
        )
        .subscribe((status) => {
            if (status === 'SUBSCRIBED') setSyncStatus('online', 'Live');
            else if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') setSyncStatus('offline', 'Offline');
            else if (status === 'CLOSED') setSyncStatus('connecting', 'Paused');
        });
}

/* ------------------------------------------------------------------ *
 * Filtering (client-side: metadata only, never decrypted values)
 * ------------------------------------------------------------------ */
function visibleKeys() {
    const q = state.query.trim().toLowerCase();
    return state.keys.filter((item) => {
        if (state.providerFilter !== 'All' && item.provider !== state.providerFilter) return false;
        if (!q) return true;
        return [item.provider, item.label, item.description, item.api_base_url, item.key_last4]
            .filter(Boolean)
            .some((value) => String(value).toLowerCase().includes(q));
    });
}

function renderChips() {
    const counts = new Map([['All', state.keys.length]]);
    for (const name of PROVIDERS) counts.set(name, 0);
    for (const item of state.keys) {
        counts.set(item.provider, (counts.get(item.provider) ?? 0) + 1);
    }

    const names = ['All', ...PROVIDERS.filter((p) => (counts.get(p) ?? 0) > 0 || p !== 'Custom')];
    ui.chips.replaceChildren(
        ...names.map((name) =>
            el('button', {
                type: 'button',
                class: `chip${state.providerFilter === name ? ' is-active' : ''}`,
                'aria-pressed': String(state.providerFilter === name),
                onclick: () => {
                    state.providerFilter = name;
                    render();
                },
            }, [
                name === 'All' ? 'All providers' : name,
                el('span', { class: 'count', text: String(counts.get(name) ?? 0) }),
            ]),
        ),
    );
}

/* ------------------------------------------------------------------ *
 * Rendering
 * ------------------------------------------------------------------ */
function render() {
    renderChips();

    const items = visibleKeys();
    clearRevealedExcept(items.map((i) => i.id));

    ui.grid.replaceChildren();

    if (state.keys.length === 0) {
        ui.emptyState.hidden = false;
        ui.listStatus.textContent = '';
        return;
    }
    ui.emptyState.hidden = true;

    if (items.length === 0) {
        ui.listStatus.textContent = 'No keys match your search.';
        return;
    }

    ui.listStatus.textContent =
        `${items.length} of ${state.keys.length} key${state.keys.length === 1 ? '' : 's'}`;
    ui.grid.replaceChildren(...items.map(renderCard));
}

function renderCard(item) {
    const isRevealed = state.revealed.has(item.id);
    const valueText = isRevealed ? state.revealed.get(item.id) : maskFor(item);

    const keyValue = el('code', {
        class: `key-value${isRevealed ? ' is-revealed' : ''}`,
        text: valueText,
        title: isRevealed ? 'Decrypted value — visible in this browser only' : 'Encrypted · hidden',
    });

    const revealBtn = el('button', {
        type: 'button',
        class: 'btn btn-ghost btn-icon',
        'aria-label': isRevealed ? 'Hide key' : 'Reveal key',
        title: isRevealed ? 'Hide' : 'Reveal',
        onclick: () => (isRevealed ? hideKey(item.id) : revealKey(item.id)),
    }, [isRevealed ? '🙈' : '👁']);

    const copyBtn = el('button', {
        type: 'button',
        class: 'btn btn-ghost btn-icon',
        'aria-label': 'Copy key',
        title: 'Copy',
        onclick: () => copyKey(item, copyBtn),
    }, ['⧉']);

    const card = el('article', { class: 'card' }, [
        el('div', { class: 'card-head' }, [
            el('div', { class: 'card-titles' }, [
                el('h3', { class: 'card-title', text: item.label || `${item.provider} key` }),
                item.description ? el('p', { class: 'card-sub', text: item.description }) : null,
            ]),
            el('span', {
                class: `badge${item.provider === 'Custom' ? ' badge--custom' : ''}`,
                text: item.provider,
            }),
        ]),

        el('div', { class: 'key-row' }, [
            keyValue,
            el('div', { class: 'key-actions' }, [revealBtn, copyBtn]),
        ]),

        item.api_base_url
            ? el('div', { class: 'meta' }, [
                el('div', { class: 'meta-row' }, [
                    el('span', { class: 'meta-label', text: 'Base URL' }),
                    el('span', { class: 'meta-val' }, [
                        // Only render a real link for http(s); anything else
                        // (e.g. a hand-crafted javascript: URL) stays inert text.
                        /^https?:\/\//i.test(item.api_base_url)
                            ? el('a', {
                                href: item.api_base_url,
                                target: '_blank',
                                rel: 'noopener noreferrer nofollow',
                                text: item.api_base_url,
                            })
                            : el('span', { text: item.api_base_url }),
                    ]),
                ]),
            ])
            : null,

        renderCheckResult(item),

        el('div', { class: 'card-foot' }, [
            el('span', { class: 'timestamp', text: `Updated ${formatDate(item.updated_at)}` }),
            el('div', { class: 'card-buttons' }, [
                el('button', {
                    type: 'button',
                    class: `btn btn-sm btn-test${item.last_check_ok === true ? ' is-ok' : ''}`,
                    dataset: { state: item.last_check_ok === true ? 'ok' : (item.last_check_ok === false ? 'fail' : '') },
                    onclick: () => testKey(item),
                }, ['Test']),
                el('button', {
                    type: 'button',
                    class: 'btn btn-sm',
                    onclick: () => openKeyDialog(item),
                }, ['Edit']),
                el('button', {
                    type: 'button',
                    class: 'btn btn-sm',
                    onclick: () => confirmDelete(item),
                }, ['Delete']),
            ]),
        ]),
    ]);

    return card;
}

/**
 * Status line for the most recent connectivity check.
 *
 * A live result kept in memory (this session) takes priority over the
 * persisted one, so pressing Test updates the card immediately without
 * waiting for the Realtime round-trip.
 */
function renderCheckResult(item) {
    const live = state.checks.get(item.id);
    const ok = live ? live.state === 'ok' : item.last_check_ok;
    const pending = live?.state === 'pending';
    const message = live ? live.message : item.last_check_message;
    const checkedAt = live ? live.at : item.last_check_at;
    const status = live ? live.status : item.last_check_status;

    if (!pending && !checkedAt && !message) return null;

    const variant = pending ? 'check-result--pending' : (ok ? 'check-result--ok' : 'check-result--fail');
    const icon = pending ? '⟳' : (ok ? '✓' : '✕');

    const metaParts = [];
    if (status) metaParts.push(`HTTP ${status}`);
    if (checkedAt) metaParts.push(`checked ${formatDate(checkedAt)}`);
    if (item.api_base_url) metaParts.push('probe endpoint varies by provider');
    else metaParts.push(`probe ${TEST_PROBE_PATH} on the provider default`);

    return el('div', { class: `check-result ${variant}` }, [
        el('span', { class: 'check-icon', text: icon, 'aria-hidden': 'true' }),
        el('span', {}, [
            el('span', { text: message || 'Checking…' }),
            el('span', {
                class: `check-meta${pending ? '' : (ok ? ' check-meta--ok' : ' check-meta--fail')}`,
                text: metaParts.join(' · '),
            }),
        ]),
    ]);
}

/* ------------------------------------------------------------------ *
 * Connectivity check (Test button)
 * ------------------------------------------------------------------ */
/**
 * Ask the server-side proxy to verify the key against its provider.
 *
 * Only the key's id is sent. The function decrypts the key inside the
 * database, checks ownership through RLS, and makes the provider call
 * server-side — so the plaintext key never travels to a provider from the
 * browser, never appears in a URL, and is never logged.
 */
async function testKey(item) {
    if (state.checks.get(item.id)?.state === 'pending') return;

    state.checks.set(item.id, { state: 'pending', message: 'Contacting the provider…' });
    render();

    try {
        const { data, error } = await supabase.functions.invoke(TEST_FUNCTION_NAME, {
            body: { key_id: item.id, path: TEST_PROBE_PATH },
        });

        if (error) {
            // Non-2xx responses carry the function's JSON payload.
            let detail = 'Could not run the check.';
            try {
                const payload = await error.context?.json?.();
                if (payload?.error) detail = payload.error;
                if (payload?.hint) detail += ` ${payload.hint}`;
            } catch { /* keep the generic message */ }

            if (error.context?.status === 401) {
                detail = 'Your session expired. Please log in again.';
            }
            throw new Error(detail);
        }

        const ok = Boolean(data?.ok);
        state.checks.set(item.id, {
            state: ok ? 'ok' : 'fail',
            message: data?.message || (ok ? 'Key is valid.' : 'The check failed.'),
            status: data?.status ?? null,
            at: data?.checked_at || new Date().toISOString(),
        });

        toast(ok ? 'Key is working.' : 'The key did not validate.', ok ? 'success' : 'error');
    } catch (error) {
        state.checks.set(item.id, {
            state: 'fail',
            message: friendlyError(error),
            status: null,
            at: new Date().toISOString(),
        });
        toast('Check failed.', 'error');
    }

    render();
    await loadKeys();
}

/* ------------------------------------------------------------------ *
 * Reveal / hide
 * ------------------------------------------------------------------ */
function clearRevealTimers(id) {
    const timer = state.revealTimers.get(id);
    if (timer) {
        clearTimeout(timer);
        state.revealTimers.delete(id);
    }
}

function clearRevealedExcept(keepIds) {
    const keep = new Set(keepIds);
    for (const id of [...state.revealed.keys()]) {
        if (!keep.has(id)) {
            state.revealed.delete(id);
            clearRevealTimers(id);
        }
    }
}

function clearRevealed() {
    for (const id of state.revealTimers.keys()) clearTimeout(state.revealTimers.get(id));
    state.revealed.clear();
    state.revealTimers.clear();
}

function hideKey(id) {
    state.revealed.delete(id);
    clearRevealTimers(id);
    render();
}

async function revealKey(id) {
    if (state.revealed.has(id)) return hideKey(id);

    // Decrypt one row, server-side, with ownership re-checked in Postgres.
    const { data, error } = await supabase.rpc('get_api_key_secret', { p_id: id });
    if (error) return toast(friendlyError(error), 'error');
    if (typeof data !== 'string' || !data) return toast('Could not retrieve that key.', 'error');

    state.revealed.set(id, data);
    render();

    // Auto-hide so a decrypted key never lingers on screen.
    clearRevealTimers(id);
    state.revealTimers.set(id, setTimeout(() => {
        if (state.revealed.has(id)) {
            state.revealed.delete(id);
            state.revealTimers.delete(id);
            render();
        }
    }, REVEAL_TIMEOUT_MS));
}

async function copyKey(item, button) {
    const plaintext = state.revealed.get(item.id);
    let value = plaintext;

    if (!value) {
        const { data, error } = await supabase.rpc('get_api_key_secret', { p_id: item.id });
        if (error) return toast(friendlyError(error), 'error');
        value = data;
    }
    if (!value) return toast('Could not retrieve that key.', 'error');

    const ok = await copyText(value);
    if (!ok) return toast('Copy failed — use Reveal to select it manually.', 'error');

    const original = button.textContent;
    button.textContent = '✓';
    setTimeout(() => { button.textContent = original; }, 1200);
    toast('Key copied to clipboard.', 'success');
}

/* ------------------------------------------------------------------ *
 * Add / edit dialog
 * ------------------------------------------------------------------ */
function openKeyDialog(item = null) {
    state.editingId = item?.id ?? null;
    ui.dialogTitle.textContent = item ? 'Edit API key' : 'Add API key';
    ui.keyOptional.hidden = !item;
    ui.fApiKey.required = !item;
    ui.fApiKey.value = '';
    ui.fApiKey.type = 'password';
    ui.fApiKey.placeholder = item ? 'Unchanged' : 'sk-…';
    ui.fApiKey.setAttribute('aria-invalid', 'false');
    ui.fProvider.value = item?.provider ?? PROVIDERS[0];
    ui.fLabel.value = item?.label ?? '';
    ui.fDescription.value = item?.description ?? '';
    ui.fBaseUrl.value = item?.api_base_url ?? '';
    ui.dialog.showModal();
    (item ? ui.fLabel : ui.fApiKey).focus();
}

function closeKeyDialog() {
    ui.dialog.close();
    state.editingId = null;
}

ui.addBtn.addEventListener('click', () => openKeyDialog());
ui.emptyAddBtn.addEventListener('click', () => openKeyDialog());
ui.dialogClose.addEventListener('click', closeKeyDialog);
ui.dialogCancel.addEventListener('click', closeKeyDialog);
ui.dialog.addEventListener('close', () => { state.editingId = null; });

ui.toggleKeyVisibility.addEventListener('click', () => {
    const hidden = ui.fApiKey.type === 'password';
    ui.fApiKey.type = hidden ? 'text' : 'password';
    ui.toggleKeyVisibility.setAttribute('aria-label', hidden ? 'Hide typed key' : 'Show typed key');
    ui.fApiKey.focus();
});

ui.keyForm.addEventListener('submit', async (event) => {
    event.preventDefault();

    const provider = ui.fProvider.value;
    const rawKey = ui.fApiKey.value.trim();
    const label = ui.fLabel.value.trim();
    const description = ui.fDescription.value.trim();
    const baseUrl = ui.fBaseUrl.value.trim();
    const isEdit = Boolean(state.editingId);

    if (!isEdit && !rawKey) {
        ui.fApiKey.setAttribute('aria-invalid', 'true');
        return toast('Please enter the API key.', 'error');
    }
    if (baseUrl && !/^https?:\/\//i.test(baseUrl)) {
        return toast('Base URL must start with http:// or https://', 'error');
    }

    const saveBtn = document.getElementById('dialog-save');
    saveBtn.disabled = true;

    // Mutations go through SECURITY DEFINER RPCs, never direct table writes.
    const { error } = isEdit
        ? await supabase.rpc('update_api_key', {
            p_id: state.editingId,
            p_provider: provider,
            p_label: label || null,
            p_description: description || null,
            p_api_base_url: baseUrl || null,
            p_api_key: rawKey || null,   // null keeps the existing encrypted value
        })
        : await supabase.rpc('create_api_key', {
            p_provider: provider,
            p_api_key: rawKey,
            p_label: label || null,
            p_description: description || null,
            p_api_base_url: baseUrl || null,
        });

    saveBtn.disabled = false;

    if (error) return toast(friendlyError(error), 'error');

    ui.fApiKey.value = '';           // never keep plaintext in the DOM
    const wasEdit = isEdit;
    closeKeyDialog();
    toast(wasEdit ? 'Key updated.' : 'Key added and encrypted.', 'success');
    await loadKeys();
});

/* ------------------------------------------------------------------ *
 * Delete
 * ------------------------------------------------------------------ */
function confirmDelete(item) {
    state.pendingDeleteId = item.id;
    ui.confirmText.textContent =
        `“${item.label || item.provider}” will be permanently removed from your account.`;
    ui.confirmDialog.showModal();
}

ui.confirmCancel.addEventListener('click', () => {
    state.pendingDeleteId = null;
    ui.confirmDialog.close();
});
ui.confirmDialog.addEventListener('close', () => { state.pendingDeleteId = null; });

ui.confirmOk.addEventListener('click', async () => {
    const id = state.pendingDeleteId;
    if (!id) return;
    ui.confirmOk.disabled = true;

    const { error } = await supabase.rpc('delete_api_key', { p_id: id });
    ui.confirmOk.disabled = false;
    ui.confirmDialog.close();

    if (error) return toast(friendlyError(error), 'error');
    hideKey(id);
    toast('Key deleted.', 'success');
    await loadKeys();
});

/* ------------------------------------------------------------------ *
 * Search
 * ------------------------------------------------------------------ */
let searchTimer = null;
ui.search.addEventListener('input', () => {
    const value = ui.search.value;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
        state.query = value;
        render();
    }, 120);
});

/* ------------------------------------------------------------------ *
 * Global wiring
 * ------------------------------------------------------------------ */
ui.fProvider.replaceChildren(
    ...PROVIDERS.map((name) => el('option', { value: name, text: name })),
);

// Hide decrypted values when the tab is backgrounded.
document.addEventListener('visibilitychange', () => {
    if (document.hidden && state.revealed.size > 0) {
        clearRevealed();
        render();
    }
});

// Close dialogs on backdrop click.
for (const dialog of [ui.dialog, ui.confirmDialog]) {
    dialog.addEventListener('click', (event) => {
        if (event.target === dialog) dialog.close();
    });
}

// Keep the UI in sync if the session expires or the token is refreshed.
let refreshTimer = null;
supabase.auth.onAuthStateChange((event) => {
    if (event === 'TOKEN_REFRESHED' || event === 'SIGNED_IN') {
        clearTimeout(refreshTimer);
        refreshTimer = setTimeout(() => { if (state.user) loadKeys(); }, 0);
    }
});

(async function bootstrap() {
    const { data, error } = await supabase.auth.getSession();
    if (error) {
        showAuth();
        return;
    }
    if (data?.session?.user) await showApp(data.session.user);
    else showAuth();
})();