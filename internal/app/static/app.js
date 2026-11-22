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
    tab_devices: 'Пристрої',
    log_live: 'Останні запити (пам\'ять)', log_disk: 'Архів на флешці',
    arch_title: 'Архів журналу', arch_from: 'з', arch_to: 'по',
    arch_clients_ph: 'IP через кому (порожньо = усі)', arch_q_ph: 'домен або ім\'я пристрою',
    arch_show: 'Показати', arch_download: 'Завантажити', arch_more: 'Ще',
    arch_info: 'На флешці: {0} дн. ({1}), з {2}. Вільно: {3}.', arch_empty: 'Архів порожній',
    arch_none: 'Нічого не знайдено',
    fmt_csv: 'CSV для Excel (;)', fmt_csv_comma: 'CSV (,)',
    f_threats: 'Загрози (віруси, фішинг)',
    k_any: 'Будь-який тип', k_malware: 'Віруси', k_phishing: 'Фішинг', k_ads: 'Реклама/трекери',
    k_parental: 'Батьківський контроль', k_custom: 'Власні правила', k_other: 'Інше',
    col_date: 'Дата і час', col_kind: 'Категорія', k_auto: 'Категорія: автоматично',
    dev_title: 'Пристрої в мережі',
    dev_help: 'Імена показуються в журналі й Telegram поруч з IP. Власне ім\'я має пріоритет над ім\'ям від роутера.',
    dev_server: 'Сервер імен (роутер)', dev_server_ph: '172.17.53.1',
    dev_mac_note: 'Телефони з випадковою MAC-адресою можуть отримати новий IP. Для дитячих пристроїв вимкніть «приватну адресу» для домашньої Wi-Fi і зробіть статичну оренду DHCP на роутері.',
    dev_ip_ph: 'IP, наприклад 192.168.11.45', dev_name_ph: 'Ім\'я, наприклад Телефон Максима', dev_set_name: 'Задати ім\'я',
    dev_col_name: 'Власне ім\'я', dev_col_auto: 'Від роутера', dev_col_first: 'Вперше', dev_col_last: 'Востаннє',
    dev_rename: 'Ім\'я', dev_forget: 'Забути', dev_prompt: 'Ім\'я для {0} (порожньо = прибрати):', dev_saved: 'Збережено',
    col_kind_short: 'Тип',
    profile: 'Профіль',
    ql_title: 'Журнал на флешці', ql_mode: 'Що записувати',
    ql_off: 'Нічого', ql_threats: 'Тільки загрози', ql_blocked: 'Усі заблоковані', ql_all: 'Усі запити',
    ql_days: 'Зберігати днів', ql_max: 'Ліміт розміру журналів, МБ', ql_free: 'Мінімум вільного місця, МБ (0 = не стежити)',
    ql_help: 'Видаляються тільки старі файли журналу. Якщо видаляти нічого, запис зупиняється, а DNS працює далі.',
    ql_state: 'Зайнято: {0}, днів: {1}, вільно на флешці: {2}. Записано: {3}, пропущено: {4}.',
    ql_paused: '⚠ Запис зупинено: на флешці мало місця.', ql_saved: 'Налаштування журналу збережено',
    tg_title: 'Telegram-сповіщення', tg_howto: 'Як налаштувати (2 хвилини)',
    tg_steps: ['У Telegram відкрийте @BotFather → /newbot → задайте ім\'я. Скопіюйте токен.',
      'Вставте токен нижче.', 'Напишіть своєму боту /start.', 'Натисніть «Знайти chat ID» і виберіть себе.', 'Збережіть і натисніть «Надіслати тест».'],
    tg_token: 'Токен бота', tg_change: 'Змінити', tg_clear: 'Видалити токен', tg_token_set: 'збережено: {0}',
    tg_chat: 'Chat ID', tg_detect: 'Знайти chat ID', tg_no_chats: 'Немає повідомлень. Напишіть боту /start і спробуйте ще раз.',
    tg_events: 'Про що повідомляти', tg_threshold: 'Поріг «можливо заражений»: різних шкідливих доменів за годину',
    tg_lang: 'Мова повідомлень', tg_test: 'Надіслати тест', tg_test_ok: 'Тестове повідомлення надіслано',
    tg_saved: 'Налаштування Telegram збережено', tg_confirm_clear: 'Видалити токен бота? Сповіщення зупиняться.',
    tg_state: 'Надіслано: {0}, останнє: {1}.', tg_err: 'Помилка: {0}', tg_off: 'Не налаштовано',
    ev_malware: '🦠 Віруси', ev_phishing: '🎣 Фішинг', ev_parental: '👨‍👧 Батьківський контроль', ev_custom: '✋ Власні правила',
    ev_ads: '📢 Реклама/трекери (багато повідомлень)', ev_infected: '🚨 Пристрій, можливо, заражений', ev_new_device: '📱 Новий пристрій у мережі',
    ev_disk_full: '💾 Флешка заповнена', ev_log_cleanup: '🗑 Видалення журналів (ліміт / мало місця)',
    ev_log_retention: '🗑 Видалення журналів за терміном (щодня)', ev_upstreams_down: '⚠️ Усі upstream недоступні',
    bk_title: 'Резервна копія налаштувань',
    bk_help: 'Списки, правила, групи, upstream, журнал, Telegram, імена пристроїв. Відновлення замінює всі поточні налаштування.',
    bk_secrets: 'Включити пароль панелі й токен Telegram (зберігайте файл у безпечному місці)',
    bk_download: 'Завантажити копію', bk_restore: 'Відновити з файлу:', bk_confirm: 'Замінити ВСІ налаштування вмістом файлу {0}?',
    bk_done: 'Налаштування відновлено',
    ev_update: '🆕 Нова версія VartaDNS',
    tg_cmd_title: 'Керування і звіти', tg_commands: 'Приймати команди з Telegram',
    tg_commands_help: 'Тільки з вашого chat ID: /status, /pause 15, /resume, /top, /threats, /groups, /internet Діти off 60. Повідомлення від інших ігноруються.',
    tg_report: 'Звіт', tg_report_off: 'вимкнено', tg_report_daily: 'щодня', tg_report_weekly: 'щотижня (неділя)',
    tg_report_at: 'о', tg_hour: 'год', update_avail: 'Нова версія {0}',
    no_rights: 'Недостатньо прав для цієї дії',
    g_lists: 'Загальні списки для групи', g_lists_help: 'Зніміть галочку, щоб група не отримувала цю категорію загальних списків (наприклад, без блоку реклами).',
    fs_title: 'Охоплення фільтрації', fs_default: 'Загальні списки для пристроїв поза групами',
    fs_bypass: 'Не фільтрувати ці IP (IP або CIDR, по одному в рядку)',
    fs_config: 'Ще з config.json: {0}', fs_saved: 'Збережено',
    enc_title: 'Шифрований DNS для пристроїв (DoH / DoT)',
    enc_help: 'Пристрої з\'єднуються з VartaDNS зашифровано. Персональна адреса впізнає пристрій навіть після зміни MAC/IP. Android і iPhone вимагають сертифікат, якому довіряють: Let\'s Encrypt (потрібен домен або безкоштовний DuckDNS/deSEC) або власний CA VartaDNS (встановлюється на пристрій вручну).',
    enc_enable: 'Увімкнути DoH/DoT', enc_host: 'Ім\'я сервера', enc_addr: 'IP, до якого підключаються пристрої (VartaDNS відповідатиме ним на це ім\'я)',
    enc_cert: 'Сертифікат', enc_src_ca: 'Власний CA VartaDNS (без домену; CA встановлюється на кожен пристрій)',
    enc_src_acme: 'Let\'s Encrypt через DNS (Cloudflare / DuckDNS / deSEC)', enc_src_custom: 'Свій сертифікат',
    enc_provider: 'DNS-провайдер', enc_token: 'API-токен провайдера (Cloudflare: Zone → DNS → Edit)', enc_email: 'Email для Let\'s Encrypt (необов\'язково)',
    enc_agree: 'Я приймаю угоду Let\'s Encrypt:', enc_staging: 'Тестовий сервер Let\'s Encrypt (сертифікат не довірений, для перевірки)',
    enc_issue: 'Отримати сертифікат', enc_token_set: 'збережено (введіть новий, щоб замінити)',
    enc_ca_help: 'Завантажте CA і встановіть його як довірений на кожному пристрої. Для iPhone сертифікат уже включено в профіль.',
    enc_ca_dl: 'Завантажити CA (vartadns-ca.crt)', enc_devices: 'Персональні адреси пристроїв',
    enc_devices_help: 'IP — адреса, якою пристрій «вважається» для груп і журналу (наприклад, його статичний IP у LAN). Адреса працює як пароль: не публікуйте її.',
    enc_col_doh: 'DoH (браузер, Windows, iPhone)', enc_col_dot: 'DoT (Android «Приватний DNS»)', enc_dev_ip_ph: 'IP пристрою, напр. 192.168.11.45',
    enc_dev_add: 'Створити адресу', enc_profile: 'Профіль iPhone', enc_copy: 'Копіювати', enc_copied: 'Скопійовано', enc_del_confirm: 'Видалити адресу {0}? Пристрій перестане фільтруватися через неї.',
    enc_state: 'DoH: {0}, DoT: {1}. Сертифікат: {2}, дійсний до {3}.', enc_saved: 'Збережено', enc_issue_started: 'Запит сертифіката запущено (1–5 хв)',
    enc_howto: 'Як підключити пристрої',
    enc_howto_list: ['Android 9+: Налаштування → Мережа → Приватний DNS → «Ім\'я хоста» → адреса з колонки DoT.',
      'iPhone/iPad: завантажте «Профіль iPhone», відкрийте на пристрої, встановіть у Налаштуваннях. Для власного CA: Загальні → Про пристрій → Довіра сертифікатам → увімкнути VartaDNS.',
      'Windows 11: Параметри → Мережа → Властивості → DNS → Редагувати → IP VartaDNS, шифрування «Лише зашифровано (DoH)», шаблон — адреса DoH.',
      'Chrome/Firefox: Налаштування → Безпека → Безпечний DNS → власний постачальник → адреса DoH.',
      'На MikroTik виконайте скрипт deploy/examples/mikrotik-encrypted-dns.rsc, щоб дозволити 443/853 до VartaDNS.'],
    sl_title: 'Syslog / SIEM', sl_help: 'Надсилає події у Graylog, Wazuh, rsyslog у форматі RFC 5424 з JSON. Готові правила для Wazuh і Graylog — у папці deploy/siem репозиторію.',
    sl_enable: 'Надсилати в syslog', sl_audit: 'журнал дій', sl_insecure: 'TLS без перевірки сертифіката',
    sl_test: 'Надіслати тестову подію', sl_state: 'Надіслано: {0}, втрачено: {1}.', sl_saved: 'Syslog збережено', sl_test_ok: 'Тестову подію відправлено',
    st_local: 'локально',
    https_title: 'HTTPS для панелі',
    https_help: 'HTTP-панель (порт 8080) працює завжди. HTTPS відкривається на порту 8443. Самопідписаний сертифікат браузер покаже з попередженням — перевірте відбиток нижче й прийміть його один раз.',
    https_off: 'Вимкнено', https_auto: 'Автоматичний сертифікат (самопідписаний)', https_custom: 'Свій сертифікат (наприклад, від CA підприємства)',
    https_cert: 'Сертифікат (PEM, з ланцюжком)', https_key: 'Приватний ключ (PEM)', https_redirect: 'Перенаправляти http:// на https://',
    https_state: 'Порт {0}: {1}. Відбиток SHA-256: {2}. Дійсний до {3}. Імена: {4}.', https_running: 'працює', https_stopped: 'не працює',
    https_saved: 'HTTPS збережено', https_key_saved: 'збережено (вставте нові, щоб замінити)',
    users_title: 'Користувачі панелі',
    users_help: 'Адмін — усе. Оператор — перегляд і керування групами (інтернет, правила груп). Перегляд — тільки дашборд і журнал. Після зміни ролі чи пароля користувач входить заново.',
    users_role: 'Роль', users_sessions: 'Сесій', users_name_ph: 'Ім\'я (латиницею)', users_pass_ph: 'Пароль (від 8 символів)',
    role_viewer: 'Перегляд', role_operator: 'Оператор', role_admin: 'Адмін',
    users_reset: 'Новий пароль', users_del: 'Видалити', users_pass_prompt: 'Новий пароль для {0} (від 8 символів):',
    users_del_confirm: 'Видалити користувача {0}?', users_saved: 'Збережено',
    audit_title: 'Журнал дій', audit_refresh: 'Оновити', audit_action: 'Дія',
    act: { 'login': 'Вхід', 'POST /api/blocking': 'Фільтрація вкл/пауза', 'POST /api/rules': 'Додано правило', 'DELETE /api/rules': 'Видалено правило',
      'POST /api/lists': 'Додано список', 'PUT /api/lists': 'Змінено список', 'DELETE /api/lists': 'Видалено список', 'POST /api/lists/refresh': 'Оновлення списків',
      'POST /api/groups': 'Створено групу', 'PUT /api/groups': 'Змінено групу', 'DELETE /api/groups': 'Видалено групу', 'POST /api/groups/internet': 'Інтернет групи',
      'POST /api/groups/rule': 'Правило групи', 'PUT /api/upstreams': 'Змінено upstream', 'PUT /api/telegram': 'Змінено Telegram', 'PUT /api/qlog': 'Змінено журнал',
      'POST /api/restore': 'Відновлення з копії', 'PUT /api/users': 'Змінено користувача', 'DELETE /api/users': 'Видалено користувача', 'PUT /api/tls': 'Змінено HTTPS',
      'POST /api/password': 'Зміна пароля', 'PUT /api/devices/name': 'Ім\'я пристрою' },
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
    tab_devices: 'Devices',
    log_live: 'Recent queries (memory)', log_disk: 'Archive on flash drive',
    arch_title: 'Log archive', arch_from: 'from', arch_to: 'to',
    arch_clients_ph: 'IPs, comma separated (empty = all)', arch_q_ph: 'domain or device name',
    arch_show: 'Show', arch_download: 'Download', arch_more: 'More',
    arch_info: 'On the flash drive: {0} days ({1}), since {2}. Free: {3}.', arch_empty: 'Archive is empty',
    arch_none: 'Nothing found',
    fmt_csv: 'CSV for Excel (;)', fmt_csv_comma: 'CSV (,)',
    f_threats: 'Threats (malware, phishing)',
    k_any: 'Any kind', k_malware: 'Malware', k_phishing: 'Phishing', k_ads: 'Ads/trackers',
    k_parental: 'Parental control', k_custom: 'Custom rules', k_other: 'Other',
    col_date: 'Date and time', col_kind: 'Category', k_auto: 'Category: automatic',
    dev_title: 'Devices on the network',
    dev_help: 'Names are shown next to the IP in the log and in Telegram. A name set here wins over the router\'s name.',
    dev_server: 'Names server (router)', dev_server_ph: '172.17.53.1',
    dev_mac_note: 'Phones with a random MAC address may get a new IP. For children\'s devices turn off the "private address" for the home Wi-Fi and add a static DHCP lease on the router.',
    dev_ip_ph: 'IP, e.g. 192.168.11.45', dev_name_ph: 'Name, e.g. Max\'s phone', dev_set_name: 'Set name',
    dev_col_name: 'Own name', dev_col_auto: 'From router', dev_col_first: 'First seen', dev_col_last: 'Last seen',
    dev_rename: 'Name', dev_forget: 'Forget', dev_prompt: 'Name for {0} (empty = remove):', dev_saved: 'Saved',
    col_kind_short: 'Kind',
    profile: 'Profile',
    ql_title: 'Log on flash drive', ql_mode: 'What to record',
    ql_off: 'Nothing', ql_threats: 'Threats only', ql_blocked: 'All blocked', ql_all: 'All queries',
    ql_days: 'Keep days', ql_max: 'Log size limit, MB', ql_free: 'Minimum free space, MB (0 = do not watch)',
    ql_help: 'Only old log files are deleted. If nothing can be deleted, logging stops and DNS keeps working.',
    ql_state: 'Used: {0}, days: {1}, free on flash: {2}. Written: {3}, skipped: {4}.',
    ql_paused: '⚠ Logging stopped: low space on the flash drive.', ql_saved: 'Log settings saved',
    tg_title: 'Telegram notifications', tg_howto: 'How to set up (2 minutes)',
    tg_steps: ['In Telegram open @BotFather → /newbot → choose a name. Copy the token.',
      'Paste the token below.', 'Send /start to your bot.', 'Press "Find chat ID" and pick yourself.', 'Save and press "Send test".'],
    tg_token: 'Bot token', tg_change: 'Change', tg_clear: 'Remove token', tg_token_set: 'saved: {0}',
    tg_chat: 'Chat ID', tg_detect: 'Find chat ID', tg_no_chats: 'No messages yet. Send /start to the bot and try again.',
    tg_events: 'Notify about', tg_threshold: '"May be infected" threshold: different malicious domains per hour',
    tg_lang: 'Message language', tg_test: 'Send test', tg_test_ok: 'Test message sent',
    tg_saved: 'Telegram settings saved', tg_confirm_clear: 'Remove the bot token? Notifications will stop.',
    tg_state: 'Sent: {0}, last: {1}.', tg_err: 'Error: {0}', tg_off: 'Not configured',
    ev_malware: '🦠 Malware', ev_phishing: '🎣 Phishing', ev_parental: '👨‍👧 Parental control', ev_custom: '✋ Custom rules',
    ev_ads: '📢 Ads/trackers (many messages)', ev_infected: '🚨 Device may be infected', ev_new_device: '📱 New device on the network',
    ev_disk_full: '💾 Flash drive full', ev_log_cleanup: '🗑 Logs deleted (limit / low space)',
    ev_log_retention: '🗑 Logs deleted by retention (daily)', ev_upstreams_down: '⚠️ All upstreams down',
    bk_title: 'Settings backup',
    bk_help: 'Lists, rules, groups, upstreams, log, Telegram, device names. Restoring replaces all current settings.',
    bk_secrets: 'Include the panel password and the Telegram token (keep the file safe)',
    bk_download: 'Download backup', bk_restore: 'Restore from file:', bk_confirm: 'Replace ALL settings with the contents of {0}?',
    bk_done: 'Settings restored',
    ev_update: '🆕 New VartaDNS version',
    tg_cmd_title: 'Control and reports', tg_commands: 'Accept commands from Telegram',
    tg_commands_help: 'Only from your chat ID: /status, /pause 15, /resume, /top, /threats, /groups, /internet Kids off 60. Messages from others are ignored.',
    tg_report: 'Report', tg_report_off: 'off', tg_report_daily: 'daily', tg_report_weekly: 'weekly (Sunday)',
    tg_report_at: 'at', tg_hour: 'h', update_avail: 'New version {0}',
    no_rights: 'Your role does not allow this',
    g_lists: 'General lists for the group', g_lists_help: 'Untick to exclude a category of the general lists for this group (e.g. no ad blocking).',
    fs_title: 'Filtering scope', fs_default: 'General lists for devices outside groups',
    fs_bypass: 'Do not filter these IPs (IP or CIDR, one per line)',
    fs_config: 'Also from config.json: {0}', fs_saved: 'Saved',
    enc_title: 'Encrypted DNS for devices (DoH / DoT)',
    enc_help: 'Devices connect to VartaDNS encrypted. A personal address identifies a device even after its MAC/IP changes. Android and iPhone need a trusted certificate: Let\'s Encrypt (needs a domain or a free DuckDNS/deSEC name) or VartaDNS\'s own CA (installed on each device by hand).',
    enc_enable: 'Enable DoH/DoT', enc_host: 'Server name', enc_addr: 'IP devices connect to (VartaDNS answers this name with it)',
    enc_cert: 'Certificate', enc_src_ca: 'VartaDNS own CA (no domain; install the CA on each device)',
    enc_src_acme: 'Let\'s Encrypt via DNS (Cloudflare / DuckDNS / deSEC)', enc_src_custom: 'Own certificate',
    enc_provider: 'DNS provider', enc_token: 'Provider API token (Cloudflare: Zone → DNS → Edit)', enc_email: 'Email for Let\'s Encrypt (optional)',
    enc_agree: 'I accept the Let\'s Encrypt agreement:', enc_staging: 'Let\'s Encrypt staging (untrusted test certificate)',
    enc_issue: 'Get certificate', enc_token_set: 'saved (enter a new one to replace)',
    enc_ca_help: 'Download the CA and install it as trusted on every device. For iPhone it is already inside the profile.',
    enc_ca_dl: 'Download CA (vartadns-ca.crt)', enc_devices: 'Personal device addresses',
    enc_devices_help: 'IP — the address the device counts as for groups and the log (e.g. its static LAN IP). The address works like a password: keep it private.',
    enc_col_doh: 'DoH (browser, Windows, iPhone)', enc_col_dot: 'DoT (Android "Private DNS")', enc_dev_ip_ph: 'Device IP, e.g. 192.168.11.45',
    enc_dev_add: 'Create address', enc_profile: 'iPhone profile', enc_copy: 'Copy', enc_copied: 'Copied', enc_del_confirm: 'Delete the address of {0}? The device stops being filtered through it.',
    enc_state: 'DoH: {0}, DoT: {1}. Certificate: {2}, valid until {3}.', enc_saved: 'Saved', enc_issue_started: 'Certificate request started (1-5 min)',
    enc_howto: 'How to connect devices',
    enc_howto_list: ['Android 9+: Settings → Network → Private DNS → "hostname" → the address from the DoT column.',
      'iPhone/iPad: download the "iPhone profile", open it on the device, install it in Settings. With the own CA: General → About → Certificate Trust Settings → enable VartaDNS.',
      'Windows 11: Settings → Network → Properties → DNS → Edit → VartaDNS IP, encryption "Encrypted only (DoH)", template = the DoH address.',
      'Chrome/Firefox: Settings → Security → Secure DNS → custom provider → the DoH address.',
      'On MikroTik run deploy/examples/mikrotik-encrypted-dns.rsc to allow 443/853 to VartaDNS.'],
    sl_title: 'Syslog / SIEM', sl_help: 'Sends events to Graylog, Wazuh, rsyslog as RFC 5424 with JSON. Ready rules for Wazuh and Graylog are in deploy/siem in the repository.',
    sl_enable: 'Send to syslog', sl_audit: 'audit log', sl_insecure: 'TLS without certificate check',
    sl_test: 'Send test event', sl_state: 'Sent: {0}, lost: {1}.', sl_saved: 'Syslog saved', sl_test_ok: 'Test event sent',
    st_local: 'local',
    https_title: 'HTTPS for the panel',
    https_help: 'The HTTP panel (port 8080) always keeps working. HTTPS opens on port 8443. The browser warns about a self-signed certificate — check the fingerprint below and accept it once.',
    https_off: 'Off', https_auto: 'Automatic certificate (self-signed)', https_custom: 'Own certificate (e.g. from a company CA)',
    https_cert: 'Certificate (PEM, with chain)', https_key: 'Private key (PEM)', https_redirect: 'Redirect http:// to https://',
    https_state: 'Port {0}: {1}. SHA-256 fingerprint: {2}. Valid until {3}. Names: {4}.', https_running: 'running', https_stopped: 'not running',
    https_saved: 'HTTPS saved', https_key_saved: 'saved (paste new ones to replace)',
    users_title: 'Panel users',
    users_help: 'Admin — everything. Operator — view and control groups (internet, group rules). Viewer — dashboard and log only. After a role or password change the user signs in again.',
    users_role: 'Role', users_sessions: 'Sessions', users_name_ph: 'Name (latin letters)', users_pass_ph: 'Password (8+ characters)',
    role_viewer: 'Viewer', role_operator: 'Operator', role_admin: 'Admin',
    users_reset: 'New password', users_del: 'Delete', users_pass_prompt: 'New password for {0} (8+ characters):',
    users_del_confirm: 'Delete user {0}?', users_saved: 'Saved',
    audit_title: 'Audit log', audit_refresh: 'Refresh', audit_action: 'Action',
    act: { 'login': 'Sign in', 'POST /api/blocking': 'Filtering on/pause', 'POST /api/rules': 'Rule added', 'DELETE /api/rules': 'Rule removed',
      'POST /api/lists': 'List added', 'PUT /api/lists': 'List changed', 'DELETE /api/lists': 'List removed', 'POST /api/lists/refresh': 'Lists refresh',
      'POST /api/groups': 'Group created', 'PUT /api/groups': 'Group changed', 'DELETE /api/groups': 'Group deleted', 'POST /api/groups/internet': 'Group internet',
      'POST /api/groups/rule': 'Group rule', 'PUT /api/upstreams': 'Upstreams changed', 'PUT /api/telegram': 'Telegram changed', 'PUT /api/qlog': 'Log settings changed',
      'POST /api/restore': 'Restore from backup', 'PUT /api/users': 'User changed', 'DELETE /api/users': 'User deleted', 'PUT /api/tls': 'HTTPS changed',
      'POST /api/password': 'Password change', 'PUT /api/devices/name': 'Device name' },
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
  if (!r.ok) throw new Error(data.error === 'your role does not allow this' ? t('no_rights') : (data.error || ('HTTP ' + r.status)));
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
  timers.push(setInterval(() => { if (current === 'log' && logSource() === 'live' && $('#log-auto').checked) refreshLog(); }, 3000));
  loadNames();
  timers.push(setInterval(loadNames, 60000));
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
  ({ dash: refreshDash, rules: refreshRules, groups: refreshGroups, lists: refreshLists,
    devices: refreshDevices,
    log: () => (logSource() === 'disk' ? refreshArchiveInfo() : refreshLog()),
    settings: async () => {
      const st = await refreshStatus();
      if (st.role === 'admin') { refreshUpstreams(); refreshQLog(); refreshTelegram(); refreshTLS(); refreshUsers(); refreshAudit(); refreshEnc(); refreshSyslog(); refreshScope(); }
    } })[current]();
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
  $('#profile-name').textContent = s.profile || '';
  document.body.className = 'role-' + (s.role || 'viewer');
  $('#me').textContent = s.user ? s.user + ' (' + t('role_' + s.role) + ')' : '';
  if (s.role !== 'admin' && document.querySelector('nav button.active.admin-only')) $('nav button[data-tab=dash]').click();
  const ul = $('#update-link');
  if (s.latest_version && s.latest_version.url) {
    ul.href = s.latest_version.url; ul.textContent = '🆕 ' + t('update_avail', s.latest_version.tag);
    ul.classList.remove('hidden');
  } else ul.classList.add('hidden');
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
  for (const it of items) ol.append(el('li', {}, el('span', { text: sel === '#top-clients' ? devLabel(it.key) : it.key }), el('span', { text: fmt(it.count) })));
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
      el('td', { text: time(r.time) }), el('td', { text: devLabel(r.client, r.device) }), el('td', { text: r.group || '' }), el('td', { text: r.name || '.' }),
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
      el('td', {}, l.allow ? '' : kindSelect(l, cb)),
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
    await api('POST', '/api/lists', { name: $('#list-name').value.trim(), url: $('#list-url').value.trim(), allow: $('#list-allow').checked, kind: $('#list-kind').value });
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
    left.append(el('h3', { text: t('g_lists') }), el('p', { class: 'muted', text: t('g_lists_help') }));
    const kindBox = el('div', { class: 'checks' });
    const skip = g.skip_kinds || [];
    const kinds = ['malware', 'phishing', 'ads', 'other'].map((k) => {
      const c = checkbox(!skip.includes(k), t('k_' + k));
      kindBox.append(c.lab);
      return { k, cb: c.cb };
    });
    left.append(kindBox);

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
        skip_kinds: kinds.filter((x) => !x.cb.checked).map((x) => x.k),
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

// ---- device names -------------------------------------------------------------------------
let devNames = {};
async function loadNames() {
  try {
    const d = await api('GET', '/api/devices');
    const m = {};
    for (const x of d.devices) { const n = x.manual || x.auto; if (n) m[x.ip] = n; }
    devNames = m;
  } catch (_) { /* ignore */ }
}
// devLabel shows "name · ip"; the IP is always visible (devices may change names).
function devLabel(ip, name) {
  const n = name || devNames[ip];
  return n ? n + ' · ' + ip : ip;
}
const dt = (iso) => (isZeroTime(iso) ? '—' : new Date(iso).toLocaleString(locale()));
const mb = (b) => (b < 0 ? '?' : (b / 1048576).toFixed(b < 10485760 ? 1 : 0) + ' ' + t('mb'));

async function refreshDevices() {
  const d = await api('GET', '/api/devices');
  $('#dev-server').value = d.names_server || '';
  const tb = $('#dev-body'); tb.replaceChildren();
  for (const x of d.devices) {
    tb.append(el('tr', {},
      el('td', { text: x.ip }), el('td', { text: x.manual || '' }), el('td', { class: 'muted', text: x.auto || '' }),
      el('td', { text: dt(x.first_seen) }), el('td', { text: dt(x.last_seen) }),
      el('td', {},
        el('button', { class: 'small ghost', text: t('dev_rename'), onclick: async () => {
          const n = prompt(t('dev_prompt', x.ip), x.manual || x.auto || '');
          if (n === null) return;
          await api('PUT', '/api/devices/name', { ip: x.ip, name: n }).then(() => { toast(t('dev_saved')); loadNames(); refreshDevices(); })
            .catch((e) => toast(e.message));
        } }),
        ' ',
        el('button', { class: 'small ghost', text: t('dev_forget'), onclick: async () => {
          await api('POST', '/api/devices/forget', { ip: x.ip }).catch((e) => toast(e.message));
          refreshDevices();
        } }))));
  }
}
$('#dev-server-save').addEventListener('click', async () => {
  try { await api('PUT', '/api/devices/server', { server: $('#dev-server').value.trim() }); toast(t('dev_saved')); refreshDevices(); }
  catch (e) { toast(e.message); }
});
$('#dev-add').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('PUT', '/api/devices/name', { ip: $('#dev-ip').value.trim(), name: $('#dev-name').value });
    $('#dev-ip').value = ''; $('#dev-name').value = '';
    toast(t('dev_saved')); loadNames(); refreshDevices();
  } catch (err) { toast(err.message); }
});

// ---- list kinds ---------------------------------------------------------------------------
function kindSelect(l, cb) {
  const s = el('select', {});
  for (const k of ['malware', 'phishing', 'ads', 'other']) s.append(el('option', { value: k, text: t('k_' + k) }));
  s.value = l.kind || 'other';
  s.addEventListener('change', async () => {
    try { await api('PUT', '/api/lists', { url: l.url, enabled: cb.checked, kind: s.value }); toast(t('list_saved')); }
    catch (e) { toast(e.message); }
  });
  return s;
}

// ---- disk log archive -----------------------------------------------------------------------
const logSource = () => (document.querySelector('input[name=log-src]:checked') || {}).value || 'live';
$$('input[name=log-src]').forEach((r) => r.addEventListener('change', () => {
  const disk = logSource() === 'disk';
  $('#log-live-card').classList.toggle('hidden', disk);
  $('#log-disk-card').classList.toggle('hidden', !disk);
  $('#arch-result').classList.toggle('hidden', !disk);
  refreshCurrent();
}));
const todayISO = () => { const d = new Date(); d.setMinutes(d.getMinutes() - d.getTimezoneOffset()); return d.toISOString().slice(0, 10); };

async function refreshArchiveInfo() {
  const st = await api('GET', '/api/qlog');
  if (!$('#arch-to').value) $('#arch-to').value = todayISO();
  if (!$('#arch-from').value) $('#arch-from').value = todayISO();
  const f = st.files;
  $('#arch-info').textContent = f.length
    ? t('arch_info', f.length, mb(st.bytes), f[0].day, mb(st.free_bytes)) + (st.paused ? ' ' + t('ql_paused') : '')
    : t('arch_empty');
}

function archParams() {
  const p = new URLSearchParams({
    from: $('#arch-from').value, to: $('#arch-to').value, clients: $('#arch-clients').value.trim(),
    status: $('#arch-status').value, kind: $('#arch-kind').value, q: $('#arch-q').value.trim(),
  });
  return p;
}
let archOffset = 0;
async function showArchive(append) {
  if (!append) archOffset = 0;
  const p = archParams(); p.set('offset', archOffset); p.set('limit', 200);
  try {
    const r = await api('GET', '/api/qlog/entries?' + p);
    const tb = $('#arch-body');
    if (!append) tb.replaceChildren();
    if (!append && !r.entries.length) tb.append(el('tr', {}, el('td', { colspan: 8, class: 'muted', text: t('arch_none') })));
    for (const e of r.entries) {
      const info = e.rule ? (e.rule + (e.source ? ' · ' + e.source : '')) : (e.upstream || '');
      tb.append(el('tr', {},
        el('td', { text: dt(e.time) }), el('td', { text: devLabel(e.client, e.device) }), el('td', { text: e.group || '' }),
        el('td', { text: e.name || '.' }), el('td', { text: e.type || '' }),
        el('td', { class: 'st-' + e.status, text: t('st_' + e.status) }),
        el('td', { text: e.kind ? t('k_' + e.kind) : '' }), el('td', { text: info })));
    }
    archOffset += r.entries.length;
    $('#arch-more').classList.toggle('hidden', !r.more);
  } catch (e) { toast(e.message); }
}
$('#arch-show').addEventListener('click', () => showArchive(false));
$('#arch-more').addEventListener('click', () => showArchive(true));
$('#arch-download').addEventListener('click', () => {
  const p = archParams(); p.set('format', $('#arch-format').value);
  const a = el('a', { href: '/api/qlog/export?' + p, download: '' });
  document.body.append(a); a.click(); a.remove();
});

// ---- disk log settings ---------------------------------------------------------------------------
async function refreshQLog() {
  const st = await api('GET', '/api/qlog');
  const s = st.settings;
  $('#ql-mode').value = s.mode; $('#ql-days').value = s.retention_days;
  $('#ql-max').value = s.max_mb; $('#ql-free').value = s.min_free_mb;
  let txt = t('ql_state', mb(st.bytes), st.files.length, mb(st.free_bytes), fmt(st.written), fmt(st.dropped));
  if (st.paused) txt = t('ql_paused') + ' ' + txt;
  if (st.error) txt += ' ' + st.error;
  $('#ql-state').textContent = txt;
}
$('#ql-save').addEventListener('click', async () => {
  try {
    await api('PUT', '/api/qlog', {
      mode: $('#ql-mode').value, retention_days: +$('#ql-days').value,
      max_mb: +$('#ql-max').value, min_free_mb: +$('#ql-free').value,
    });
    toast(t('ql_saved')); refreshQLog();
  } catch (e) { toast(e.message); }
});

// ---- Telegram -----------------------------------------------------------------------------------
let tgData = null;
function tgBody() {
  const ev = {};
  $$('#tg-events input').forEach((c) => { ev[c.value] = c.checked; });
  const tokenInput = $('#tg-token');
  return {
    token: tokenInput.disabled ? '' : tokenInput.value.trim(), chat_id: $('#tg-chat').value.trim(), events: ev,
    infect_threshold: +$('#tg-threshold').value || 0, lang: $('#tg-lang').value,
    commands: $('#tg-commands').checked, report: $('#tg-report').value, report_hour: +$('#tg-report-hour').value,
  };
}
function tgTokenLocked(locked) {
  const i = $('#tg-token');
  i.disabled = locked;
  i.value = '';
  i.placeholder = locked && tgData && tgData.token_masked ? t('tg_token_set', tgData.token_masked) : '123456789:AA...';
  $('#tg-token-change').classList.toggle('hidden', !locked);
}
async function refreshTelegram() {
  tgData = await api('GET', '/api/telegram');
  const steps = $('#tg-steps'); steps.replaceChildren();
  for (const s of (I18N[lang] || I18N.en).tg_steps) steps.append(el('li', { text: s }));
  tgTokenLocked(!!tgData.token_masked);
  $('#tg-token-clear').classList.toggle('hidden', !tgData.token_masked);
  $('#tg-chat').value = tgData.chat_id || '';
  $('#tg-threshold').value = tgData.infect_threshold;
  $('#tg-lang').value = tgData.lang;
  $('#tg-commands').checked = tgData.commands;
  $('#tg-report').value = tgData.report;
  $('#tg-report-hour').value = tgData.report_hour;
  const box = $('#tg-events'); box.replaceChildren();
  for (const k of tgData.all_events) {
    const c = el('input', { type: 'checkbox', value: k });
    c.checked = !!tgData.events[k];
    box.append(el('label', { class: 'inline' }, c, el('span', { text: t('ev_' + k) })));
  }
  $('#tg-chats').replaceChildren();
  const st = tgData.status;
  let txt = tgData.configured ? t('tg_state', st.sent, dt(st.last_ok)) : t('tg_off');
  if (st.last_error) txt += ' ' + t('tg_err', st.last_error);
  $('#tg-state').textContent = txt;
}
$('#tg-token-change').addEventListener('click', () => { tgTokenLocked(false); $('#tg-token').focus(); });
$('#tg-token-clear').addEventListener('click', async () => {
  if (!confirm(t('tg_confirm_clear'))) return;
  try { await api('PUT', '/api/telegram', { ...tgBody(), token: '', clear_token: true }); toast(t('tg_saved')); refreshTelegram(); }
  catch (e) { toast(e.message); }
});
$('#tg-save').addEventListener('click', async () => {
  try { await api('PUT', '/api/telegram', tgBody()); toast(t('tg_saved')); refreshTelegram(); }
  catch (e) { toast(e.message); }
});
$('#tg-test').addEventListener('click', async () => {
  try { await api('POST', '/api/telegram/test', tgBody()); toast(t('tg_test_ok')); }
  catch (e) { toast(t('tg_err', e.message)); }
});
$('#tg-detect').addEventListener('click', async () => {
  const box = $('#tg-chats'); box.replaceChildren();
  try {
    const chats = await api('POST', '/api/telegram/chats', tgBody());
    if (!chats.length) { box.append(el('span', { class: 'muted', text: t('tg_no_chats') })); return; }
    for (const c of chats) {
      box.append(el('button', { class: 'small ghost', text: (c.title || c.type) + ' (' + c.id + ')',
        onclick: () => { $('#tg-chat').value = String(c.id); box.replaceChildren(); } }));
    }
  } catch (e) { toast(t('tg_err', e.message)); }
});

// ---- backup / restore -----------------------------------------------------------------------------
$('#bk-download').addEventListener('click', () => {
  const a = el('a', { href: '/api/backup?secrets=' + ($('#bk-secrets').checked ? '1' : '0'), download: '' });
  document.body.append(a); a.click(); a.remove();
});
$('#bk-file').addEventListener('change', async () => {
  const f = $('#bk-file').files[0];
  if (!f) return;
  try {
    if (!confirm(t('bk_confirm', f.name))) return;
    const r = await fetch('/api/restore', { method: 'POST', headers: { 'X-Varta': '1', 'Content-Type': 'application/json' },
      credentials: 'same-origin', body: await f.text() });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
    toast(t('bk_done')); refreshCurrent();
  } catch (e) { toast(e.message); }
  finally { $('#bk-file').value = ''; }
});

// ---- HTTPS -------------------------------------------------------------------------------------
const tlsMode = () => (document.querySelector('input[name=tls-mode]:checked') || {}).value || 'off';
async function refreshTLS() {
  const v = await api('GET', '/api/tls');
  $$('input[name=tls-mode]').forEach((r) => { r.checked = r.value === v.mode; });
  $('#tls-redirect').checked = v.redirect;
  $('#tls-custom').classList.toggle('hidden', v.mode !== 'custom');
  $('#tls-cert').value = ''; $('#tls-key').value = '';
  $('#tls-key').placeholder = v.has_custom ? t('https_key_saved') : '-----BEGIN PRIVATE KEY-----';
  const port = (v.listen || '').split(':').pop();
  let txt = v.mode === 'off' ? '' : t('https_state', port, v.running ? t('https_running') : t('https_stopped'),
    v.fingerprint || '—', v.not_after ? dt(v.not_after) : '—', (v.names || []).join(', '));
  if (v.error) txt += ' ⚠ ' + v.error;
  $('#tls-state').textContent = txt;
}
$$('input[name=tls-mode]').forEach((r) => r.addEventListener('change', () => $('#tls-custom').classList.toggle('hidden', tlsMode() !== 'custom')));
$('#tls-save').addEventListener('click', async () => {
  try {
    await api('PUT', '/api/tls', { mode: tlsMode(), redirect: $('#tls-redirect').checked, cert_pem: $('#tls-cert').value, key_pem: $('#tls-key').value });
    toast(t('https_saved')); refreshTLS();
  } catch (e) { toast(e.message); }
});

// ---- users & audit ----------------------------------------------------------------------------------
function roleSelect(value, onchange) {
  const s = el('select', {});
  for (const r of ['viewer', 'operator', 'admin']) s.append(el('option', { value: r, text: t('role_' + r) }));
  s.value = value;
  s.addEventListener('change', () => onchange(s.value));
  return s;
}
async function refreshUsers() {
  const us = await api('GET', '/api/users');
  const tb = $('#users-body'); tb.replaceChildren();
  for (const u of us) {
    tb.append(el('tr', {},
      el('td', { text: u.name }),
      el('td', {}, roleSelect(u.role, async (role) => {
        try { await api('PUT', '/api/users', { name: u.name, role }); toast(t('users_saved')); } catch (e) { toast(e.message); }
        refreshUsers();
      })),
      el('td', { text: String(u.sessions) }),
      el('td', {},
        el('button', { class: 'small ghost', text: t('users_reset'), onclick: async () => {
          const pw = prompt(t('users_pass_prompt', u.name));
          if (!pw) return;
          try { await api('PUT', '/api/users', { name: u.name, role: u.role, password: pw }); toast(t('users_saved')); } catch (e) { toast(e.message); }
          refreshUsers();
        } }), ' ',
        el('button', { class: 'small ghost', text: t('users_del'), onclick: async () => {
          if (!confirm(t('users_del_confirm', u.name))) return;
          try { await api('DELETE', '/api/users', { name: u.name }); } catch (e) { toast(e.message); }
          refreshUsers();
        } }))));
  }
}
$('#user-add').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('PUT', '/api/users', { name: $('#user-name').value.trim(), role: $('#user-role').value, password: $('#user-pass').value });
    $('#user-name').value = ''; $('#user-pass').value = '';
    toast(t('users_saved')); refreshUsers();
  } catch (err) { toast(err.message); }
});
async function refreshAudit() {
  const list = await api('GET', '/api/audit');
  const acts = (I18N[lang] || I18N.en).act;
  const tb = $('#audit-body'); tb.replaceChildren();
  for (const e of list) {
    tb.append(el('tr', {}, el('td', { text: dt(e.time) }), el('td', { text: e.user }), el('td', { text: e.ip }),
      el('td', { text: acts[e.action] || e.action }),
      el('td', { class: e.status < 300 ? 'st-cached' : 'st-blocked', text: String(e.status) })));
  }
}
$('#audit-refresh').addEventListener('click', refreshAudit);

// ---- encrypted DNS ------------------------------------------------------------------------------
const encSrc = () => (document.querySelector('input[name=enc-src]:checked') || {}).value || 'ca';
function encToggle() {
  const s = encSrc();
  $('#enc-acme').classList.toggle('hidden', s !== 'acme');
  $('#enc-custom').classList.toggle('hidden', s !== 'custom');
  $('#enc-ca').classList.toggle('hidden', s !== 'ca');
}
$$('input[name=enc-src]').forEach((r) => r.addEventListener('change', encToggle));
function copyText(txt) {
  navigator.clipboard.writeText(txt).then(() => toast(t('enc_copied'))).catch(() => prompt('', txt));
}
function download(url) { const a = el('a', { href: url, download: '' }); document.body.append(a); a.click(); a.remove(); }
async function refreshEnc() {
  const v = await api('GET', '/api/encdns');
  $('#enc-enabled').checked = v.enabled; $('#enc-host').value = v.hostname || '';
  $('#enc-addr').value = v.address || ''; $('#enc-addr').placeholder = v.suggested_address || '';
  $('#enc-doh').checked = v.doh; $('#enc-dot').checked = v.dot;
  $$('input[name=enc-src]').forEach((r) => { r.checked = r.value === (v.cert_source || 'ca'); });
  $('#enc-provider').value = v.acme_provider || 'cloudflare';
  $('#enc-token').value = ''; $('#enc-token').placeholder = v.acme_token_set ? t('enc_token_set') : '';
  $('#enc-email').value = v.acme_email || ''; $('#enc-agree').checked = v.acme_agree; $('#enc-staging').checked = v.acme_staging;
  $('#enc-cert').value = ''; $('#enc-key').value = '';
  encToggle();
  const on = (x) => (x ? '✅' : '—');
  let txt = v.enabled ? t('enc_state', on(v.doh_running), on(v.dot_running), v.cert_issuer || '—', v.cert_not_after ? dt(v.cert_not_after) : '—') : '';
  if (v.error) txt += ' ⚠ ' + v.error;
  $('#enc-state').textContent = txt;
  $('#enc-acme-state').textContent = (v.issuing ? '⏳ ' : '') + (v.acme_status || '');
  const tb = $('#enc-dev-body'); tb.replaceChildren();
  for (const d of v.devices) {
    tb.append(el('tr', {}, el('td', { text: d.name }), el('td', { text: d.ip }),
      el('td', {}, el('code', { text: d.doh || '—' }), ' ', d.doh ? el('button', { class: 'small ghost', text: t('enc_copy'), onclick: () => copyText(d.doh) }) : ''),
      el('td', {}, el('code', { text: d.dot || '—' }), ' ', d.dot ? el('button', { class: 'small ghost', text: t('enc_copy'), onclick: () => copyText(d.dot) }) : ''),
      el('td', {},
        el('button', { class: 'small ghost', text: t('enc_profile'), onclick: () => download('/api/encdns/mobileconfig?token=' + encodeURIComponent(d.token)) }), ' ',
        el('button', { class: 'small ghost', text: t('btn_delete'), onclick: async () => {
          if (!confirm(t('enc_del_confirm', d.name))) return;
          await api('DELETE', '/api/encdns/devices', { token: d.token }).catch((e) => toast(e.message));
          refreshEnc();
        } }))));
  }
  const hl = $('#enc-howto'); hl.replaceChildren();
  for (const s of (I18N[lang] || I18N.en).enc_howto_list) hl.append(el('li', { text: s }));
}
$('#enc-save').addEventListener('click', async () => {
  try {
    await api('PUT', '/api/encdns', {
      enabled: $('#enc-enabled').checked, hostname: $('#enc-host').value.trim(), address: $('#enc-addr').value.trim(),
      doh: $('#enc-doh').checked, dot: $('#enc-dot').checked, cert_source: encSrc(),
      acme_provider: $('#enc-provider').value, acme_token: $('#enc-token').value.trim(), acme_email: $('#enc-email').value.trim(),
      acme_agree: $('#enc-agree').checked, acme_staging: $('#enc-staging').checked,
      cert_pem: $('#enc-cert').value, key_pem: $('#enc-key').value,
    });
    toast(t('enc_saved')); refreshEnc();
  } catch (e) { toast(e.message); }
});
$('#enc-issue').addEventListener('click', async () => {
  try { await api('POST', '/api/encdns/issue'); toast(t('enc_issue_started')); setTimeout(refreshEnc, 3000); }
  catch (e) { toast(e.message); }
});
$('#enc-ca-dl').addEventListener('click', () => download('/api/encdns/ca.crt'));
$('#enc-dev-add').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('POST', '/api/encdns/devices', { name: $('#enc-dev-name').value, ip: $('#enc-dev-ip').value.trim() });
    $('#enc-dev-name').value = ''; $('#enc-dev-ip').value = '';
    refreshEnc();
  } catch (err) { toast(err.message); }
});

// ---- syslog ----------------------------------------------------------------------------------------
async function refreshSyslog() {
  const v = await api('GET', '/api/syslog');
  const s = v.settings;
  $('#sl-enabled').checked = s.enabled; $('#sl-addr').value = s.address || '';
  $('#sl-proto').value = s.protocol || 'udp'; $('#sl-mode').value = s.mode || 'threats';
  $('#sl-audit').checked = s.audit; $('#sl-insecure').checked = s.insecure;
  $('#sl-state').textContent = t('sl_state', fmt(v.status.sent), fmt(v.status.dropped)) + (v.status.error ? ' ⚠ ' + v.status.error : '');
}
$('#sl-save').addEventListener('click', async () => {
  try {
    await api('PUT', '/api/syslog', { enabled: $('#sl-enabled').checked, address: $('#sl-addr').value.trim(),
      protocol: $('#sl-proto').value, mode: $('#sl-mode').value, audit: $('#sl-audit').checked, insecure: $('#sl-insecure').checked });
    toast(t('sl_saved')); refreshSyslog();
  } catch (e) { toast(e.message); }
});
$('#sl-test').addEventListener('click', async () => {
  try { await api('POST', '/api/syslog/test'); toast(t('sl_test_ok')); setTimeout(refreshSyslog, 2000); } catch (e) { toast(e.message); }
});

// ---- filtering scope ------------------------------------------------------------------------------
async function refreshScope() {
  const v = await api('GET', '/api/filtering');
  const box = $('#fs-kinds'); box.replaceChildren();
  for (const k of v.kinds) {
    const c = checkbox(!v.default_skip_kinds.includes(k), t('k_' + k));
    c.cb.value = k;
    box.append(c.lab);
  }
  $('#fs-bypass').value = v.bypass_clients.join('\n');
  $('#fs-config').textContent = v.config_bypass.length ? t('fs_config', v.config_bypass.join(', ')) : '';
}
$('#fs-save').addEventListener('click', async () => {
  try {
    await api('PUT', '/api/filtering', {
      default_skip_kinds: [...$$('#fs-kinds input')].filter((c) => !c.checked).map((c) => c.value),
      bypass_clients: $('#fs-bypass').value.split(/[\s,;]+/).filter(Boolean),
    });
    toast(t('fs_saved')); refreshScope();
  } catch (e) { toast(e.message); }
});

// ---- start ------------------------------------------------------------------------------------------
$$('.lang-select').forEach((s) => {
  s.append(el('option', { value: 'uk', text: 'UK' }), el('option', { value: 'en', text: 'EN' }));
  s.addEventListener('change', () => setLang(s.value));
});
applyI18n();
api('GET', '/api/status').then(showMain).catch(showLogin);
