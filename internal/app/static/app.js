'use strict';
// VartaDNS web panel. All untrusted strings (domain names, client IPs) are
// inserted with textContent only, never as HTML.

// ---- i18n -------------------------------------------------------------------
const I18N = {
  uk: {
    user: 'Користувач', password: 'Пароль', login: 'Увійти', logout: 'Вийти',
    login_failed: 'Невірний користувач або пароль', login_locked: 'Забагато невдалих спроб, зачекайте 10 хвилин',
    tab_dash: 'Огляд', tab_log: 'Журнал', tab_rules: 'Правила', tab_lists: 'Списки', tab_settings: 'Налаштування',
    s_total: 'Запитів', s_blocked: 'Заблоковано', s_cached: 'З кешу', s_qps: 'Запитів/с', s_rules: 'Правил', s_mem: "Пам'ять",
    of_all: 'від усіх', cache_hits: 'влучань у кеш', uptime: 'працює', mb: 'МБ',
    d: 'д', h: 'г', m: 'хв',
    chart_title: 'Запити за останні 60 хв', legend_all: 'усі', legend_blocked: 'заблоковані',
    top_domains: 'Топ доменів', top_blocked: 'Топ заблокованих', top_clients: 'Топ клієнтів', no_data: 'немає даних',
    upstreams: 'Upstream-сервери', col_server: 'Сервер', col_latency: 'Затримка', col_state: 'Стан', ms: 'мс', fails: 'збої',
    protect_on: 'Захист увімкнено', protect_off: 'Захист вимкнено', until: 'до',
    log_search: 'Пошук домену або IP клієнта', autorefresh: 'автооновлення',
    f_all: 'Усі', f_blocked: 'Заблоковані', f_forwarded: 'Переслані', f_cached: 'З кешу',
    f_allowed: 'Дозволені правилом', f_error: 'Помилки', f_refused: 'Відхилені',
    col_time: 'Час', col_client: 'Клієнт', col_domain: 'Домен', col_type: 'Тип', col_status: 'Статус',
    col_rule: 'Правило / upstream', col_ms: 'мс',
    st_blocked: 'заблоковано', st_forwarded: 'переслано', st_cached: 'кеш', st_allowed: 'дозволено',
    st_error: 'помилка', st_refused: 'відхилено',
    btn_allow: 'Дозволити', btn_block: 'Блокувати', btn_delete: 'Видалити',
    check_title: 'Перевірити домен', check_ph: 'наприклад ads.example.com', check_btn: 'Перевірити',
    v_pass: 'не блокується', v_blocked: 'БЛОКУЄТЬСЯ', v_allowed: 'дозволено винятком', rule: 'правило',
    custom_block: 'Власний чорний список', custom_allow: 'Білий список (винятки)',
    block_ph: 'domain.com (блокує й піддомени)', allow_ph: 'domain.com', add: 'Додати', empty: 'порожньо',
    added_block: 'Заблоковано: ', added_allow: 'Дозволено: ',
    lists_title: 'Списки блокування', lists_refresh: 'Оновити всі зараз',
    col_on: 'Увімк.', col_name: 'Назва', col_rules: 'Правил', col_updated: 'Оновлено', col_error: 'Помилка',
    list_black: 'чорний', list_white: 'білий',
    list_name_ph: 'Назва', list_url_ph: 'https://... (hosts, domains або adblock формат)',
    list_is_allow: 'білий список', list_add: 'Додати список',
    list_saved: 'Збережено, перебудовую правила…', list_confirm_del: 'Видалити список «{0}»?',
    list_refresh_started: 'Оновлення запущено, це може зайняти хвилину', list_added: 'Список додано, завантажую…',
    filtering: 'Фільтрація', enable: 'Увімкнути', disable: 'Вимкнути',
    pause5: 'Пауза 5 хв', pause30: 'Пауза 30 хв', pause60: 'Пауза 1 год',
    cache: 'Кеш', cache_flush: 'Очистити кеш', cache_flushed: 'Кеш очищено',
    pw_title: 'Змінити пароль', pw_old: 'Поточний пароль', pw_new: 'Новий пароль (мін. 8 символів)',
    save: 'Зберегти', pw_changed: 'Пароль змінено, увійдіть знову',
    us_title: 'Upstream-сервери', us_help: 'Куди VartaDNS пересилає запити, які не заблоковані. По одному в рядку: IP (1.1.1.1), IP:порт (192.168.11.1:53), tcp://IP:порт або DoH (https://…/dns-query). Bootstrap — звичайні IP-адреси, через які VartaDNS дізнається адреси DoH-серверів.',
    us_servers: 'Сервери', us_bootstrap: 'Bootstrap DNS (тільки IP)', us_use_preset: 'Підставити набір',
    us_test: 'Перевірити', us_save: 'Зберегти', us_reset: 'Скинути до заводських', us_result: 'Результат',
    us_custom: 'зараз: власні налаштування', us_factory: 'зараз: заводські налаштування', us_saved: 'Збережено й застосовано',
    us_none_ok: 'Жоден сервер не відповів — не збережено', us_choose: '— набір —', us_reset_done: 'Повернуто заводські сервери',
    preset_quad9: 'блокує шкідливі домени', preset_cloudflare: 'найшвидший, без фільтрації', preset_cf_security: 'блокує шкідливі домени',
    preset_cf_family: 'шкідливі + дорослий контент', preset_google: 'без фільтрації', preset_adguard: 'блокує рекламу і трекери',
    up_title: 'DNS-запити в інтернет', up_enc: 'Спершу шифровано (DoH)', up_fast: 'Найшвидший сервер',
    up_enc_help: 'Запити йдуть через зашифрований DNS-over-HTTPS. Звичайний DNS — лише запасний, якщо DoH не відповідає. Трохи повільніше, але провайдер не бачить і не може підмінити запити.',
    up_fast_help: 'Запити йдуть на найшвидший робочий сервер, зазвичай звичайний DNS без шифрування. Швидше, але запити видно на шляху.',
    up_saved: 'Збережено', up_primary: 'основний', up_encrypted: 'шифровано',
    tab_groups: 'Групи', col_group: 'Група', f_safesearch: 'Безпечний пошук', st_safesearch: 'безпечний пошук',
    g_new: 'Нова група', g_help: 'Членство: окремі IP, діапазони (192.168.11.50-192.168.11.69) або підмережі (192.168.11.64/27) через кому. Якщо IP входить у кілька груп, діє перша зверху. Нова група нічого не блокує, поки ви не ввімкнете правила.',
    g_name_ph: 'Назва, напр. Діти', g_members_ph: '192.168.11.50, 192.168.11.100-192.168.11.110', g_create: 'Створити',
    g_members: 'Учасники (по одному в рядку: IP, діапазон або підмережа)', g_services: 'Сервіси', g_categories: 'Категорії',
    g_rules_loaded: 'правил', g_not_loaded: 'завантажиться після збереження', g_safesearch: 'Безпечний пошук (Google, Bing, DuckDuckGo, YouTube «Обмежений»)',
    g_internet: 'Інтернет', g_off_1h: 'Вимкнути на 1 год', g_off_3h: 'на 3 год', g_off_forever: 'Вимкнути до ввімкнення', g_on: 'Увімкнути',
    g_off_now: 'Інтернет вимкнено', g_off_until: 'до',
    g_schedule: 'Розклад', g_sched_enable: 'Обмеження діють лише за розкладом', g_sched_blockall: 'У цей час повністю вимкнути інтернет',
    g_sched_help: 'Без розкладу обмеження групи діють завжди. З розкладом — лише у вказані дні та години (наприклад 22:00–07:00 через північ).',
    g_add_window: 'Додати проміжок', g_from: 'з', g_to: 'до', g_remove: 'Прибрати',
    g_block: 'Блокувати додатково (домени, по одному в рядку)', g_allow: 'Завжди дозволено (домени, по одному в рядку)',
    g_save: 'Зберегти групу', g_saved: 'Групу збережено', g_delete: 'Видалити групу', g_confirm_del: 'Видалити групу «{0}»?',
    g_up: '↑', g_down: '↓', g_active_now: 'обмеження діють зараз', g_inactive_now: 'поза розкладом — без обмежень',
    g_none: 'Груп ще немає', btn_block_group: 'Блок. для групи', btn_allow_group: 'Дозв. для групи',
    days: ['Нд', 'Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб'],
    minecraft_note: 'Вхід через Microsoft/Xbox не блокується', facebook_note: 'Може зламати «Увійти через Facebook» на інших сайтах',
    telegram_note: 'Застосунок частково працює напряму за IP — DNS блокує не повністю',
    cat_adult: 'Дорослий контент', cat_gambling: 'Азартні ігри',
  },
  en: {
    user: 'User', password: 'Password', login: 'Sign in', logout: 'Sign out',
    login_failed: 'Wrong user or password', login_locked: 'Too many failed attempts, wait 10 minutes',
    tab_dash: 'Dashboard', tab_log: 'Query log', tab_rules: 'Rules', tab_lists: 'Lists', tab_settings: 'Settings',
    s_total: 'Queries', s_blocked: 'Blocked', s_cached: 'From cache', s_qps: 'Queries/s', s_rules: 'Rules', s_mem: 'Memory',
    of_all: 'of all', cache_hits: 'cache hit rate', uptime: 'uptime', mb: 'MB',
    d: 'd', h: 'h', m: 'm',
    chart_title: 'Queries over the last 60 min', legend_all: 'all', legend_blocked: 'blocked',
    top_domains: 'Top domains', top_blocked: 'Top blocked', top_clients: 'Top clients', no_data: 'no data',
    upstreams: 'Upstream servers', col_server: 'Server', col_latency: 'Latency', col_state: 'State', ms: 'ms', fails: 'failures',
    protect_on: 'Protection on', protect_off: 'Protection off', until: 'until',
    log_search: 'Search domain or client IP', autorefresh: 'auto-refresh',
    f_all: 'All', f_blocked: 'Blocked', f_forwarded: 'Forwarded', f_cached: 'Cached',
    f_allowed: 'Allowed by rule', f_error: 'Errors', f_refused: 'Refused',
    col_time: 'Time', col_client: 'Client', col_domain: 'Domain', col_type: 'Type', col_status: 'Status',
    col_rule: 'Rule / upstream', col_ms: 'ms',
    st_blocked: 'blocked', st_forwarded: 'forwarded', st_cached: 'cached', st_allowed: 'allowed',
    st_error: 'error', st_refused: 'refused',
    btn_allow: 'Allow', btn_block: 'Block', btn_delete: 'Delete',
    check_title: 'Check a domain', check_ph: 'e.g. ads.example.com', check_btn: 'Check',
    v_pass: 'not blocked', v_blocked: 'BLOCKED', v_allowed: 'allowed by exception', rule: 'rule',
    custom_block: 'Custom blocklist', custom_allow: 'Allowlist (exceptions)',
    block_ph: 'domain.com (also blocks subdomains)', allow_ph: 'domain.com', add: 'Add', empty: 'empty',
    added_block: 'Blocked: ', added_allow: 'Allowed: ',
    lists_title: 'Blocklists', lists_refresh: 'Update all now',
    col_on: 'On', col_name: 'Name', col_rules: 'Rules', col_updated: 'Updated', col_error: 'Error',
    list_black: 'block', list_white: 'allow',
    list_name_ph: 'Name', list_url_ph: 'https://... (hosts, domains or adblock format)',
    list_is_allow: 'allowlist', list_add: 'Add list',
    list_saved: 'Saved, rebuilding rules…', list_confirm_del: 'Delete list “{0}”?',
    list_refresh_started: 'Update started, this may take a minute', list_added: 'List added, downloading…',
    filtering: 'Filtering', enable: 'Enable', disable: 'Disable',
    pause5: 'Pause 5 min', pause30: 'Pause 30 min', pause60: 'Pause 1 hour',
    cache: 'Cache', cache_flush: 'Flush cache', cache_flushed: 'Cache flushed',
    pw_title: 'Change password', pw_old: 'Current password', pw_new: 'New password (min. 8 characters)',
    save: 'Save', pw_changed: 'Password changed, please sign in again',
    us_title: 'Upstream servers', us_help: 'Where VartaDNS forwards queries that are not blocked. One per line: IP (1.1.1.1), IP:port (192.168.11.1:53), tcp://IP:port or DoH (https://…/dns-query). Bootstrap: plain IP addresses used to look up DoH server names.',
    us_servers: 'Servers', us_bootstrap: 'Bootstrap DNS (IP only)', us_use_preset: 'Use preset',
    us_test: 'Test', us_save: 'Save', us_reset: 'Reset to defaults', us_result: 'Result',
    us_custom: 'now: custom settings', us_factory: 'now: factory defaults', us_saved: 'Saved and applied',
    us_none_ok: 'No server answered - not saved', us_choose: '- preset -', us_reset_done: 'Factory servers restored',
    preset_quad9: 'blocks malicious domains', preset_cloudflare: 'fastest, no filtering', preset_cf_security: 'blocks malicious domains',
    preset_cf_family: 'malicious + adult content', preset_google: 'no filtering', preset_adguard: 'blocks ads and trackers',
    up_title: 'Upstream DNS', up_enc: 'Encrypted first (DoH)', up_fast: 'Fastest server',
    up_enc_help: 'Queries go over encrypted DNS-over-HTTPS. Plain DNS is only a fallback when DoH does not answer. Slightly slower, but nobody on the path can see or tamper with queries.',
    up_fast_help: 'Queries go to the fastest healthy server, usually plain unencrypted DNS. Faster, but queries are visible on the path.',
    up_saved: 'Saved', up_primary: 'primary', up_encrypted: 'encrypted',
    tab_groups: 'Groups', col_group: 'Group', f_safesearch: 'SafeSearch', st_safesearch: 'safesearch',
    g_new: 'New group', g_help: 'Members: single IPs, ranges (192.168.11.50-192.168.11.69) or subnets (192.168.11.64/27), comma-separated. If an IP is in several groups, the first one from the top wins. A new group blocks nothing until you enable rules.',
    g_name_ph: 'Name, e.g. Kids', g_members_ph: '192.168.11.50, 192.168.11.100-192.168.11.110', g_create: 'Create',
    g_members: 'Members (one per line: IP, range or subnet)', g_services: 'Services', g_categories: 'Categories',
    g_rules_loaded: 'rules', g_not_loaded: 'loads after saving', g_safesearch: 'SafeSearch (Google, Bing, DuckDuckGo, YouTube Restricted)',
    g_internet: 'Internet', g_off_1h: 'Turn off for 1 h', g_off_3h: 'for 3 h', g_off_forever: 'Turn off until enabled', g_on: 'Turn on',
    g_off_now: 'Internet is off', g_off_until: 'until',
    g_schedule: 'Schedule', g_sched_enable: 'Restrictions apply only on schedule', g_sched_blockall: 'Turn internet off completely during these times',
    g_sched_help: 'Without a schedule the group restrictions always apply. With a schedule only on the given days and hours (e.g. 22:00-07:00 across midnight).',
    g_add_window: 'Add time window', g_from: 'from', g_to: 'to', g_remove: 'Remove',
    g_block: 'Also block (domains, one per line)', g_allow: 'Always allowed (domains, one per line)',
    g_save: 'Save group', g_saved: 'Group saved', g_delete: 'Delete group', g_confirm_del: 'Delete group “{0}”?',
    g_up: '↑', g_down: '↓', g_active_now: 'restrictions active now', g_inactive_now: 'outside schedule - no restrictions',
    g_none: 'No groups yet', btn_block_group: 'Block for group', btn_allow_group: 'Allow for group',
    days: ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'],
    minecraft_note: 'Microsoft/Xbox sign-in is not blocked', facebook_note: 'May break “Log in with Facebook” on other sites',
    telegram_note: 'The app partly connects by IP - DNS blocking is incomplete',
    cat_adult: 'Adult content', cat_gambling: 'Gambling',
  },
};

function loadLang() {
  try {
    const saved = localStorage.getItem('varta_lang');
    if (saved && I18N[saved]) return saved;
  } catch (_) { /* storage may be unavailable */ }
  return (navigator.language || '').toLowerCase().startsWith('uk') ? 'uk' : 'en';
}
let lang = loadLang();
const locale = () => (lang === 'uk' ? 'uk-UA' : 'en-GB');

function t(key, ...args) {
  let s = (I18N[lang] && I18N[lang][key]) || I18N.en[key] || key;
  args.forEach((a, i) => { s = s.replace('{' + i + '}', a); });
  return s;
}

function applyI18n() {
  document.documentElement.lang = lang;
  document.querySelectorAll('[data-i18n]').forEach((e) => { e.textContent = t(e.dataset.i18n); });
  document.querySelectorAll('[data-i18n-ph]').forEach((e) => { e.placeholder = t(e.dataset.i18nPh); });
  document.querySelectorAll('.lang-select').forEach((s) => { s.value = lang; });
}

function setLang(l) {
  lang = l;
  try { localStorage.setItem('varta_lang', l); } catch (_) { /* ignore */ }
  applyI18n();
  if (!document.getElementById('main').classList.contains('hidden')) refreshCurrent();
}

// ---- helpers -----------------------------------------------------------------
const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

function el(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'text') e.textContent = v;
    else if (v !== null && v !== undefined) e.setAttribute(k, v);
  }
  for (const k of kids) e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return e;
}

async function api(method, path, body) {
  const opt = { method, headers: { 'X-Varta': '1' }, credentials: 'same-origin' };
  if (body !== undefined) {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body);
  }
  const r = await fetch(path, opt);
  if (r.status === 401 && path !== '/api/login') { showLogin(); throw new Error('unauthorized'); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
  return data;
}

function toast(msg) {
  const tt = $('#toast');
  tt.textContent = msg;
  tt.classList.remove('hidden');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => tt.classList.add('hidden'), 3000);
}

const fmt = (n) => Number(n || 0).toLocaleString(locale());
const pct = (a, b) => (b ? (100 * a / b).toFixed(1) + '%' : '0%');
function dur(sec) {
  const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
  return (d ? d + t('d') + ' ' : '') + h + t('h') + ' ' + m + t('m');
}
const time = (iso) => new Date(iso).toLocaleTimeString(locale());
const isZeroTime = (iso) => !iso || iso.startsWith('0001');

// ---- login ---------------------------------------------------------------------
let timers = [];
function showLogin() {
  timers.forEach(clearInterval); timers = [];
  $('#main').classList.add('hidden');
  $('#login').classList.remove('hidden');
}
function showMain() {
  $('#login').classList.add('hidden');
  $('#main').classList.remove('hidden');
  refreshDash();
  timers.push(setInterval(() => { if (current === 'dash') refreshDash(); }, 5000));
  timers.push(setInterval(() => { if (current === 'log' && $('#log-auto').checked) refreshLog(); }, 3000));
}
$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#login-err').textContent = '';
  try {
    await api('POST', '/api/login', { user: $('#login-user').value, password: $('#login-pass').value });
    $('#login-pass').value = '';
    showMain();
  } catch (err) {
    const known = { 'wrong user or password': 'login_failed', 'too many failed logins, wait 10 minutes': 'login_locked' };
    $('#login-err').textContent = known[err.message] ? t(known[err.message]) : err.message;
  }
});
$('#logout').addEventListener('click', async () => { await api('POST', '/api/logout').catch(() => {}); showLogin(); });

// ---- tabs -----------------------------------------------------------------------
let current = 'dash';
function refreshCurrent() {
  ({ dash: refreshDash, log: refreshLog, rules: refreshRules, groups: refreshGroups, lists: refreshLists,
    settings: () => { refreshStatus(); refreshUpstreams(); } })[current]();
}
$$('nav button').forEach((b) => b.addEventListener('click', () => {
  $$('nav button').forEach((x) => x.classList.toggle('active', x === b));
  current = b.dataset.tab;
  $$('.tab').forEach((tab) => tab.classList.toggle('hidden', tab.id !== 'tab-' + current));
  refreshCurrent();
}));

// ---- dashboard ---------------------------------------------------------------------
async function refreshStatus() {
  const s = await api('GET', '/api/status');
  $('#ver').textContent = 'v' + s.version;
  const st = $('#blocking-state');
  st.className = 'pill ' + (s.blocking ? 'on' : 'off');
  $$('input[name=up-strategy]').forEach((r) => { r.checked = r.value === s.upstream_strategy; });
  st.textContent = s.blocking ? t('protect_on') :
    (t('protect_off') + (isZeroTime(s.disabled_until) ? '' : ' ' + t('until') + ' ' + time(s.disabled_until)));
  return s;
}

async function refreshDash() {
  try {
    const [s, series, top] = await Promise.all([
      refreshStatus(), api('GET', '/api/series?minutes=60'), api('GET', '/api/top?n=10'),
    ]);
    $('#s-total').textContent = fmt(s.total);
    $('#s-blocked').textContent = fmt(s.blocked);
    $('#s-blocked-pct').textContent = pct(s.blocked, s.total) + ' ' + t('of_all');
    $('#s-cached').textContent = fmt(s.cached);
    $('#s-hit').textContent = t('cache_hits') + ' ' + pct(s.cache_hits, s.cache_hits + s.cache_misses);
    $('#s-qps').textContent = s.qps.toFixed(1);
    $('#s-rules').textContent = fmt(s.rules_block + s.custom_block);
    $('#s-mem').textContent = s.mem_alloc_mb.toFixed(0) + ' ' + t('mb');
    $('#s-uptime').textContent = t('uptime') + ' ' + dur(s.uptime_sec);
    drawChart(series);
    fillTop('#top-domains', top.domains);
    fillTop('#top-blocked', top.blocked);
    fillTop('#top-clients', top.clients);
    const ub = $('#upstreams'); ub.replaceChildren();
    for (const u of s.upstreams) {
      const tags = [u.encrypted ? '🔒 ' + t('up_encrypted') : '', u.primary ? '★ ' + t('up_primary') : ''].filter(Boolean).join(' · ');
      ub.append(el('tr', {}, el('td', {}, el('div', { text: u.name }), el('div', { class: 'muted', text: tags })),
        el('td', { text: u.latency_ms.toFixed(1) + ' ' + t('ms') }),
        el('td', { class: u.healthy ? 'st-cached' : 'st-blocked', text: u.healthy ? 'OK' : t('fails') + ': ' + u.fails })));
    }
  } catch (e) { if (e.message !== 'unauthorized') console.error(e); }
}

function fillTop(sel, items) {
  const ol = $(sel); ol.replaceChildren();
  if (!items.length) ol.append(el('li', { class: 'muted', text: t('no_data') }));
  for (const it of items) ol.append(el('li', {}, el('span', { text: it.key }), el('span', { text: fmt(it.count) })));
}

function drawChart(points) {
  const c = $('#chart');
  const dpr = window.devicePixelRatio || 1;
  const w = c.clientWidth, h = 180;
  c.width = w * dpr; c.height = h * dpr;
  const g = c.getContext('2d');
  g.scale(dpr, dpr);
  g.clearRect(0, 0, w, h);
  const max = Math.max(1, ...points.map((p) => p.total));
  const pad = 28, bw = (w - pad) / points.length;
  g.fillStyle = '#8b98a9'; g.font = '11px system-ui';
  g.fillText(fmt(max), 0, 12); g.fillText('0', 0, h - 4);
  g.strokeStyle = '#263142'; g.beginPath(); g.moveTo(pad, h - 0.5); g.lineTo(w, h - 0.5); g.stroke();
  points.forEach((p, i) => {
    const x = pad + i * bw;
    const th = (p.total / max) * (h - 16), bh = (p.blocked / max) * (h - 16);
    g.fillStyle = '#4c8dff'; g.fillRect(x + 1, h - th, Math.max(1, bw - 2), th);
    g.fillStyle = '#ff5c6c'; g.fillRect(x + 1, h - bh, Math.max(1, bw - 2), bh);
  });
}

// ---- query log -------------------------------------------------------------------------
async function refreshLog() {
  const q = encodeURIComponent($('#log-q').value.trim());
  const st = $('#log-status').value;
  const rows = await api('GET', `/api/querylog?limit=300&q=${q}&status=${st}`);
  const tb = $('#log-body'); tb.replaceChildren();
  for (const r of rows) {
    const info = r.rule ? (r.rule + (r.source ? ' · ' + r.source : '')) : (r.upstream || '');
    const action = el('td', {});
    if (r.name) {
      const target = r.rule && !r.rule.endsWith('(CNAME)') ? r.rule : r.name;
      const byGroup = (r.source || '').startsWith('group:');
      if (r.status === 'blocked') {
        if (!byGroup) action.append(el('button', { class: 'small ghost', text: t('btn_allow'), onclick: () => addRule('allow', target) }));
        const killSwitch = /\/(internet-off|schedule)$/.test(r.source || '');
        if (r.group && !killSwitch) action.append(el('button', { class: 'small ghost', text: t('btn_allow_group'), onclick: () => groupRule(r.group, 'allow', target) }));
      } else {
        action.append(el('button', { class: 'small ghost', text: t('btn_block'), onclick: () => addRule('block', r.name) }));
        if (r.group) action.append(el('button', { class: 'small ghost', text: t('btn_block_group'), onclick: () => groupRule(r.group, 'block', r.name) }));
      }
    }
    tb.append(el('tr', {},
      el('td', { text: time(r.time) }), el('td', { text: r.client }), el('td', { text: r.group || '' }), el('td', { text: r.name || '.' }),
      el('td', { text: r.type || '' }),
      el('td', { class: 'st-' + r.status, text: t('st_' + r.status) }),
      el('td', { text: info }), el('td', { text: (r.us / 1000).toFixed(1) }), action));
  }
}
$('#log-q').addEventListener('input', () => { clearTimeout(refreshLog.t); refreshLog.t = setTimeout(refreshLog, 300); });
$('#log-status').addEventListener('change', refreshLog);

// ---- rules ---------------------------------------------------------------------------------
async function refreshRules() {
  const r = await api('GET', '/api/rules');
  for (const kind of ['block', 'allow']) {
    const ul = $('#rules-' + kind); ul.replaceChildren();
    if (!r[kind].length) ul.append(el('li', { class: 'muted', text: t('empty') }));
    for (const d of r[kind]) {
      ul.append(el('li', {}, el('span', { text: d }),
        el('button', { class: 'small ghost', text: t('btn_delete'), onclick: () => delRule(kind, d) })));
    }
  }
}
async function addRule(kind, domain) {
  try {
    await api('POST', '/api/rules', { kind, domain });
    toast(t(kind === 'block' ? 'added_block' : 'added_allow') + domain);
    refreshRules();
  } catch (e) { toast(e.message); }
}
async function delRule(kind, domain) {
  try { await api('DELETE', '/api/rules', { kind, domain }); refreshRules(); } catch (e) { toast(e.message); }
}
$$('.rule-form').forEach((f) => f.addEventListener('submit', (e) => {
  e.preventDefault();
  const inp = f.querySelector('input');
  if (inp.value.trim()) addRule(f.dataset.kind, inp.value.trim());
  inp.value = '';
}));
$('#check-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const out = $('#check-result');
  try {
    const r = await api('GET', '/api/check?domain=' + encodeURIComponent($('#check-domain').value.trim()));
    out.className = r.verdict === 'blocked' ? 'st-blocked' : (r.verdict === 'allowed' ? 'st-allowed' : 'st-cached');
    out.textContent = r.domain + ': ' + t('v_' + r.verdict) + (r.rule ? ` (${t('rule')} ${r.rule}, ${r.source})` : '');
  } catch (err) { out.className = 'st-error'; out.textContent = err.message; }
});

// ---- lists ---------------------------------------------------------------------------------
async function refreshLists() {
  const lists = await api('GET', '/api/lists');
  const tb = $('#lists-body'); tb.replaceChildren();
  for (const l of lists) {
    const cb = el('input', { type: 'checkbox' });
    cb.checked = l.enabled;
    cb.addEventListener('change', async () => {
      try { await api('PUT', '/api/lists', { url: l.url, enabled: cb.checked }); toast(t('list_saved')); setTimeout(refreshLists, 1500); }
      catch (e) { toast(e.message); }
    });
    const upd = isZeroTime(l.updated) ? '—' : new Date(l.updated).toLocaleString(locale());
    tb.append(el('tr', {},
      el('td', {}, cb),
      el('td', {}, el('div', { text: l.name }), el('div', { class: 'muted', text: l.url })),
      el('td', { text: l.allow ? t('list_white') : t('list_black') }),
      el('td', { text: fmt(l.rules) }), el('td', { text: upd }),
      el('td', { class: 'st-blocked', text: l.error || '' }),
      el('td', {}, el('button', { class: 'small ghost', text: t('btn_delete'), onclick: async () => {
        if (!confirm(t('list_confirm_del', l.name))) return;
        await api('DELETE', '/api/lists', { url: l.url }).catch((e) => toast(e.message));
        setTimeout(refreshLists, 1000);
      } }))));
  }
}
$('#lists-refresh').addEventListener('click', async () => {
  await api('POST', '/api/lists/refresh').catch((e) => toast(e.message));
  toast(t('list_refresh_started'));
  setTimeout(refreshLists, 8000);
});
$('#list-add').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('POST', '/api/lists', { name: $('#list-name').value.trim(), url: $('#list-url').value.trim(), allow: $('#list-allow').checked });
    $('#list-name').value = ''; $('#list-url').value = '';
    toast(t('list_added'));
    setTimeout(refreshLists, 5000);
  } catch (err) { toast(err.message); }
});

// ---- upstream servers ----
let usData = null;
async function refreshUpstreams() {
  try { usData = await api('GET', '/api/upstreams'); } catch (e) { return; }
  $('#us-servers').value = usData.upstreams.join('\n');
  $('#us-bootstrap').value = usData.bootstrap.join('\n');
  $('#us-state').textContent = t(usData.custom ? 'us_custom' : 'us_factory');
  const sel = $('#us-preset');
  const cur = sel.value;
  sel.replaceChildren(el('option', { value: '', text: t('us_choose') }),
    ...usData.presets.map((p) => el('option', { value: p.id, text: p.name })));
  sel.value = cur;
}
function usBody() {
  return { upstreams: splitList($('#us-servers').value), bootstrap: splitList($('#us-bootstrap').value) };
}
function showResults(results) {
  const tbl = $('#us-results');
  tbl.classList.remove('hidden');
  const tb = tbl.querySelector('tbody');
  tb.replaceChildren();
  for (const r of results || []) {
    tb.append(el('tr', {}, el('td', { text: r.server }),
      el('td', { class: r.ok ? 'st-cached' : 'st-blocked', text: r.ok ? 'OK' : (r.error || 'error') }),
      el('td', { text: r.ok ? r.ms.toFixed(1) + ' ' + t('ms') : '' })));
  }
}
$('#us-preset').addEventListener('change', () => {
  const p = (usData?.presets || []).find((x) => x.id === $('#us-preset').value);
  $('#us-preset-note').textContent = p ? t(p.note) : '';
});
$('#us-apply-preset').addEventListener('click', () => {
  const p = (usData?.presets || []).find((x) => x.id === $('#us-preset').value);
  if (!p) return;
  $('#us-servers').value = p.upstreams.join('\n');
  $('#us-bootstrap').value = p.bootstrap.join('\n');
});
$('#us-test').addEventListener('click', async () => {
  try { showResults((await api('POST', '/api/upstreams/test', usBody())).results); }
  catch (e) { toast(e.message); }
});
$('#us-save').addEventListener('click', async () => {
  const opt = { method: 'PUT', headers: { 'X-Varta': '1', 'Content-Type': 'application/json' }, body: JSON.stringify(usBody()) };
  const r = await fetch('/api/upstreams', opt);
  const data = await r.json().catch(() => ({}));
  if (data.results) showResults(data.results);
  if (r.status === 422) { toast(t('us_none_ok')); return; }
  if (!r.ok) { toast(data.error || ('HTTP ' + r.status)); return; }
  toast(t('us_saved'));
  refreshUpstreams();
});
$('#us-reset').addEventListener('click', async () => {
  try { await api('POST', '/api/upstreams/reset'); toast(t('us_reset_done')); $('#us-results').classList.add('hidden'); refreshUpstreams(); }
  catch (e) { toast(e.message); }
});

// ---- settings ----------------------------------------------------------------------------------
async function setBlocking(enabled, minutes = 0) {
  try {
    await api('POST', '/api/blocking', { enabled, minutes });
    refreshStatus();
    toast(enabled ? t('protect_on') : t('protect_off'));
  } catch (e) { toast(e.message); }
}
$('#block-on').addEventListener('click', () => setBlocking(true));
$('#block-off').addEventListener('click', () => setBlocking(false));
$$('[data-pause]').forEach((b) => b.addEventListener('click', () => setBlocking(false, +b.dataset.pause)));
$$('input[name=up-strategy]').forEach((r) => r.addEventListener('change', async () => {
  try { await api('POST', '/api/upstream/strategy', { strategy: r.value }); toast(t('up_saved')); }
  catch (e) { toast(e.message); refreshStatus(); }
}));
$('#cache-flush').addEventListener('click', async () => { await api('POST', '/api/cache/flush').catch(() => {}); toast(t('cache_flushed')); });
$('#pw-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('POST', '/api/password', { old: $('#pw-old').value, new: $('#pw-new').value });
    toast(t('pw_changed'));
    showLogin();
  } catch (err) { $('#pw-msg').textContent = err.message; }
});

// ---- groups ------------------------------------------------------------------------------------
let groupsCache = null;
const splitList = (txt) => txt.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean);

async function groupRule(groupName, kind, domain) {
  try {
    const data = groupsCache || await api('GET', '/api/groups');
    const g = data.groups.find((x) => x.name === groupName);
    if (!g) throw new Error('group not found');
    groupsCache = await api('POST', '/api/groups/rule', { id: g.id, kind, domain });
    toast(t(kind === 'block' ? 'added_block' : 'added_allow') + domain + ' (' + groupName + ')');
  } catch (e) { toast(e.message); }
}

async function refreshGroups() {
  try { groupsCache = await api('GET', '/api/groups'); } catch (e) { toast(e.message); return; }
  renderGroups(groupsCache);
}

function checkbox(checked, label, extraClass) {
  const cb = el('input', { type: 'checkbox' });
  cb.checked = !!checked;
  const lab = el('label', { class: 'inline ' + (extraClass || '') }, cb, el('span', { text: label }));
  return { cb, lab };
}

function windowRow(w) {
  const row = el('div', { class: 'win-row' });
  const dayBoxes = [];
  const order = [1, 2, 3, 4, 5, 6, 0]; // Monday first
  const days = t('days');
  for (const d of order) {
    const c = checkbox((w.days || []).includes(d), days[d], 'day');
    c.cb.dataset.day = d;
    dayBoxes.push(c.cb);
    row.append(c.lab);
  }
  const from = el('input', { type: 'time', value: w.from || '22:00' });
  const to = el('input', { type: 'time', value: w.to || '07:00' });
  row.append(el('span', { class: 'muted', text: t('g_from') }), from, el('span', { class: 'muted', text: t('g_to') }), to,
    el('button', { type: 'button', class: 'small ghost', text: t('g_remove'), onclick: () => row.remove() }));
  row.read = () => ({ days: dayBoxes.filter((b) => b.checked).map((b) => +b.dataset.day), from: from.value, to: to.value });
  return row;
}

function renderGroups(data) {
  const box = $('#groups-list');
  box.replaceChildren();
  if (!data.groups.length) box.append(el('div', { class: 'card muted', text: t('g_none') }));
  data.groups.forEach((g, idx) => {
    const card = el('div', { class: 'card group-card' });

    // Header: name, state, order, delete.
    const name = el('input', { value: g.name, class: 'group-title' });
    const state = el('span', { class: 'pill ' + (g.off_active ? 'off' : 'on') });
    if (g.off_active) {
      state.textContent = t('g_off_now') + (isZeroTime(g.off_until) ? '' : ' ' + t('g_off_until') + ' ' + time(g.off_until));
    } else if (g.schedule.enabled) {
      state.textContent = g.restrictions_active ? t('g_active_now') : t('g_inactive_now');
    } else {
      state.className = 'hidden';
    }
    card.append(el('div', { class: 'card-head' },
      el('div', { class: 'toolbar nomargin' }, name, state),
      el('div', { class: 'toolbar nomargin' },
        el('button', { class: 'small ghost', text: t('g_up'), disabled: idx === 0 ? 'disabled' : null, onclick: () => moveGroup(g.id, -1) }),
        el('button', { class: 'small ghost', text: t('g_down'), onclick: () => moveGroup(g.id, 1) }),
        el('button', { class: 'small danger', text: t('g_delete'), onclick: () => delGroup(g) }))));

    // Internet kill switch.
    card.append(el('h3', { text: t('g_internet') }), el('div', { class: 'toolbar' },
      el('button', { class: 'small danger', text: t('g_off_1h'), onclick: () => setInternet(g.id, true, 60) }),
      el('button', { class: 'small ghost', text: t('g_off_3h'), onclick: () => setInternet(g.id, true, 180) }),
      el('button', { class: 'small ghost', text: t('g_off_forever'), onclick: () => setInternet(g.id, true, 0) }),
      el('button', { class: 'small', text: t('g_on'), onclick: () => setInternet(g.id, false, 0) })));

    const grid = el('div', { class: 'grid2' });
    // Left column: members, services, categories, safesearch.
    const left = el('div');
    const members = el('textarea', { rows: '3' });
    members.value = g.members.join('\n');
    left.append(el('h3', { text: t('g_members') }), members);

    left.append(el('h3', { text: t('g_services') }));
    const svcBox = el('div', { class: 'checks' });
    const svcs = data.services.map((sv) => {
      const c = checkbox(g.services.includes(sv.id), sv.name);
      if (sv.note) c.lab.title = t(sv.note);
      if (sv.note) c.lab.append(el('span', { class: 'muted', text: ' ⓘ' }));
      svcBox.append(c.lab);
      return { id: sv.id, cb: c.cb };
    });
    left.append(svcBox);

    left.append(el('h3', { text: t('g_categories') }));
    const catBox = el('div', { class: 'checks' });
    const cats = data.categories.map((ct) => {
      const loaded = ct.load && ct.load.rules ? fmt(ct.load.rules) + ' ' + t('g_rules_loaded') : t('g_not_loaded');
      const c = checkbox(g.categories.includes(ct.id), t('cat_' + ct.id));
      c.lab.append(el('span', { class: 'muted', text: ' (' + loaded + ')' }));
      catBox.append(c.lab);
      return { id: ct.id, cb: c.cb };
    });
    left.append(catBox);
    const safe = checkbox(g.safe_search, t('g_safesearch'));
    left.append(el('div', { class: 'spaced' }, safe.lab));

    // Right column: schedule, custom block/allow.
    const right = el('div');
    right.append(el('h3', { text: t('g_schedule') }), el('p', { class: 'muted', text: t('g_sched_help') }));
    const schedOn = checkbox(g.schedule.enabled, t('g_sched_enable'));
    const blockAll = checkbox(g.schedule.block_all, t('g_sched_blockall'));
    const wins = el('div', { class: 'wins' });
    (g.schedule.windows.length ? g.schedule.windows : []).forEach((w) => wins.append(windowRow(w)));
    right.append(el('div', {}, schedOn.lab), el('div', {}, blockAll.lab), wins,
      el('button', { type: 'button', class: 'small ghost', text: t('g_add_window'),
        onclick: () => wins.append(windowRow({ days: [1, 2, 3, 4, 5], from: '22:00', to: '07:00' })) }));
    const block = el('textarea', { rows: '4' });
    block.value = g.block.join('\n');
    const allow = el('textarea', { rows: '3' });
    allow.value = g.allow.join('\n');
    right.append(el('h3', { text: t('g_block') }), block, el('h3', { text: t('g_allow') }), allow);

    grid.append(left, right);
    card.append(grid);

    card.append(el('div', { class: 'toolbar' }, el('button', { text: t('g_save'), onclick: async () => {
      const body = {
        id: g.id, name: name.value.trim(), members: splitList(members.value),
        services: svcs.filter((x) => x.cb.checked).map((x) => x.id),
        categories: cats.filter((x) => x.cb.checked).map((x) => x.id),
        block: splitList(block.value), allow: splitList(allow.value),
        safe_search: safe.cb.checked,
        schedule: { enabled: schedOn.cb.checked, block_all: blockAll.cb.checked,
          windows: [...wins.children].map((r) => r.read()) },
      };
      try {
        groupsCache = await api('PUT', '/api/groups', body);
        toast(t('g_saved'));
        renderGroups(groupsCache);
        setTimeout(refreshGroups, 4000); // category lists may still be loading
      } catch (e) { toast(e.message); }
    } })));
    box.append(card);
  });
}

async function setInternet(id, off, minutes) {
  try { renderGroups(groupsCache = await api('POST', '/api/groups/internet', { id, off, minutes })); }
  catch (e) { toast(e.message); }
}
async function moveGroup(id, dir) {
  try { renderGroups(groupsCache = await api('POST', '/api/groups/move', { id, dir })); }
  catch (e) { toast(e.message); }
}
async function delGroup(g) {
  if (!confirm(t('g_confirm_del', g.name))) return;
  try { renderGroups(groupsCache = await api('DELETE', '/api/groups', { id: g.id })); }
  catch (e) { toast(e.message); }
}
$('#group-add').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    groupsCache = await api('POST', '/api/groups', { name: $('#group-name').value.trim(), members: splitList($('#group-members').value) });
    $('#group-name').value = ''; $('#group-members').value = '';
    renderGroups(groupsCache);
  } catch (err) { toast(err.message); }
});

// ---- start ------------------------------------------------------------------------------------------
$$('.lang-select').forEach((s) => {
  s.append(el('option', { value: 'uk', text: 'UK' }), el('option', { value: 'en', text: 'EN' }));
  s.addEventListener('change', () => setLang(s.value));
});
applyI18n();
api('GET', '/api/status').then(showMain).catch(showLogin);
