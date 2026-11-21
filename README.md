# VartaDNS

[![CI](https://github.com/takobas/VartaDNS/actions/workflows/ci.yml/badge.svg)](https://github.com/takobas/VartaDNS/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/takobas/VartaDNS)](https://github.com/takobas/VartaDNS/releases)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
![Go](https://img.shields.io/badge/Go-stdlib%20only-00ADD8)

**English summary.** VartaDNS is a self-hosted filtering DNS server with a built-in web panel (Ukrainian / English). It blocks ads, trackers, phishing and malware domains for the whole network and adds per-device parental control: blocked services (TikTok, Roblox, …), categories, SafeSearch, an internet kill switch and schedules. Written in pure Go with zero dependencies, it ships as a ~7 MB static binary and runs as a container on MikroTik RouterOS v7 (arm64 / armv7 / x86) — even on a 128 MB hAP ac² — or on any Linux host. The documentation below is in Ukrainian.

---

Фільтрувальний DNS-сервер із вебпанеллю (українською та англійською). Блокує рекламу, трекери, фішинг і шкідливі домени для всієї мережі, а для окремих пристроїв дає батьківський контроль. Написаний на Go без жодних сторонніх бібліотек: один статичний бінарник ~7 МБ, працює в контейнері на MikroTik (arm64 / armv7 / x86), на Proxmox або будь-якому Linux.

**Готові образи** для MikroTik і Docker — у [Releases](https://github.com/takobas/VartaDNS/releases): `vartadns-<версія>-arm64.tar`, `-armv7.tar`, `-amd64.tar` і `SHA256SUMS`.

## Можливості

- **Фільтрація за суфіксом.** Правило `example.com` блокує й `ads.example.com`. Підтримує формати hosts, списки доменів і Adblock (`||domain^`, винятки `@@||domain^`).
- **Перевірка CNAME.** Блокує трекери, замасковані під піддомен сайту (CNAME cloaking).
- **Власні чорний і білий списки** з панелі. Білий список має найвищий пріоритет.
- **Компактні правила.** 1 млн правил займає ~10 МБ RAM (64-бітні хеші), перевірка одного домену ~0,2 мкс.
- **Кеш** з урахуванням TTL і старінням TTL, захист від дублювання запитів (singleflight).
- **Upstream** через DNS-over-HTTPS (Quad9 за замовчуванням), UDP і TCP, з автоматичним перемиканням на здоровий сервер. Умовне пересилання для локальних зон (`lan`, зворотні зони).
- **Захист:**
  - обмеження частоти запитів на клієнта;
  - ACL (відповідає лише локальним мережам, тому не стане відкритим резолвером для DDoS-підсилення);
  - відмова на `ANY`;
  - випадковий ID запиту до upstream і перевірка питання у відповіді (захист від підміни);
  - автовимкнення DoH у Firefox (`use-application-dns.net`).
- **Вебпанель:**
  - статистика, графік, топ доменів і клієнтів;
  - журнал запитів з кнопками «Блокувати» / «Дозволити»;
  - керування списками, пауза захисту, зміна пароля.

  Вхід через сесію (PBKDF2-SHA256, захист від підбору пароля, SameSite=Strict, захист від CSRF).
- **Метрики Prometheus** на `/metrics`.

## Групи клієнтів (батьківський контроль), з версії 0.2

Вкладка «Групи» в панелі задає окремі правила для певних пристроїв.

- **Членство:** окремі IP, діапазони (`192.168.11.50-192.168.11.69`) або підмережі (`192.168.11.64/27`). Якщо IP входить у кілька груп, діє перша зверху; порядок змінюється стрілками.
- **Нова група нічого не блокує.** Усе нижче вимкнено, поки ви самі не ввімкнете.
- **Сервіси одним перемикачем:** TikTok, Roblox, Minecraft, Fortnite/Epic, Steam, Discord, YouTube, Instagram, Facebook/Messenger, Snapchat, Telegram, Twitch. Кожен сервіс — це набір доменів разом з CDN.
- **Категорії:** дорослий контент (HaGeZi NSFW) і азартні ігри (HaGeZi Gambling, у легкому профілі версія Medium). Список завантажується в пам'ять тільки тоді, коли категорію ввімкнено хоча б в одній групі.
- **Власні домени:** «блокувати додатково» і «завжди дозволено» для групи. Дозвіл групи перекриває і загальні списки.
- **Безпечний пошук:** Google, Bing і DuckDuckGo примусово в режимі SafeSearch, YouTube у режимі «Обмежений». Працює через DNS (CNAME на `forcesafesearch.google.com`, `strict.bing.com`, `safe.duckduckgo.com`, `restrict.youtube.com`).
- **Вимкнути інтернет групі** на 1 год, на 3 год або до ручного ввімкнення.
- **Розклад** (за замовчуванням вимкнений): дні тижня і проміжки часу, зокрема через північ (22:00–07:00). Обмеження групи діють тільки в цей час. Можна також повністю вимикати групі інтернет за розкладом. Час київський (`TZ` у контейнері).
- **Журнал:** показує групу кожного запиту. Кнопки «Блок./Дозв. для групи» додають правило тільки цій групі.
- **Пауза захисту** в налаштуваннях вимикає лише загальні списки. Обмеження груп продовжують діяти.

Чого DNS-фільтр не зупинить:
- пристрій, на якому вручну змінили IP. Закріплюйте адреси статичною орендою DHCP;
- VPN-застосунки;
- мобільний інтернет.

Telegram і деякі ігри частково з'єднуються напряму за IP, тому для них блокування через DNS неповне.

Оновлення контейнера на hAP ac² без втрати налаштувань описане в `deploy/examples/mikrotik-update-hap-ac2.rsc`.

## Продуктивність

Виміряно на 2 vCPU (Xeon 2.1 ГГц), 1 млн правил у фільтрі. Генератор навантаження і тестовий upstream працювали на тих самих 2 ядрах, що й сервер.

| Сценарій | Запитів/с | p50 | p99 |
|---|---|---|---|
| Змішаний (кеш + 20% заблокованих) | 65 000–84 000 | 0,6–0,8 мс | 4–4,5 мс |
| Усі запити повз кеш до upstream | 18 000–22 000 | 2,6–3,3 мс | 8–10 мс |

На MikroTik цифри будуть нижчими (ARM-ядра, мережа контейнера). Для дому чи офісу запас усе одно великий.

## Встановлення на MikroTik

1. Зберіть образи (`./build.sh`) або візьміть готові з `dist/`. Оберіть свою архітектуру:
   - **arm64** — CCR2004/2116/2216, RB5009, hAP ax2/ax3;
   - **armv7** — RB4011, RB3011, hAP ac3 (256 МБ RAM: лише легкі списки);
   - **amd64** — CHR/x86.
2. Встановіть пакет `container` і ввімкніть режим контейнерів. Після команди нижче потрібне фізичне підтвердження кнопкою або вимкненням живлення:
   ```
   /system/device-mode/update container=yes
   ```
3. **Підготуйте флешку або диск.** Контейнеру потрібна файлова система ext4, з FAT32 він не працює.
   - **Яку брати:** флешку відомого виробника на 16–32 ГБ або SSD у USB-боксі. Дешеві флешки швидко зношуються від щоденного запису.
   - Вставте флешку і перевірте, що роутер її бачить (слот `usb1`):
     ```
     /disk/print
     ```
   - ⚠️ Відформатуйте в ext4. Усі дані на флешці буде знищено.
     ```
     /disk/format usb1 file-system=ext4 label=varta
     ```
     На старіших RouterOS 7 команда називалась `/disk/format-drive usb1 file-system=ext4 label=varta`.
   - Перевірте, що диск змонтований (у `/disk/print` стоїть прапорець **M**) і видний у файлах:
     ```
     /file/print where name~"usb1"
     ```
   - **Якщо не спрацювало:**
     - Флешки немає в списку: спробуйте інший порт або іншу флешку, бо деякі USB 3.0 флешки споживають забагато струму.
     - Помилка `device not available`: створіть на флешці порожню папку або відформатуйте її в ext4 на комп'ютері з Linux.
   - Перед тим як витягти флешку, зупиніть контейнер і виконайте `/disk/eject usb1`.
4. **Завантажте образ** `.tar` під свою архітектуру на флешку. У Winbox це Files, перетягнути у папку `usb1`. Або через scp:
   ```
   scp vartadns-0.1.1-arm64.tar admin@192.168.88.1:/usb1/
   ```
   Перевірте: `/file/print where name~"vartadns"`.
5. Відредагуйте значення з позначкою `EDIT` у `deploy/mikrotik-install.rsc`, завантажте файл на роутер і виконайте:
   ```
   /import file-name=mikrotik-install.rsc verbose=yes
   /container/start [find name=vartadns]
   /log/print where message~"credentials"
   ```
6. Відкрийте панель `http://172.17.53.2:8080`. Логін `admin`, пароль береться з логу. Одразу змініть його в «Налаштуваннях».

Скрипт робить таке:
- створює мережу для контейнера;
- лишає DNS у клієнтів на роутері і перенаправляє весь DNS (порт 53) з LAN на VartaDNS (клієнти зберігають свої IP, тому в панелі видно статистику по кожному пристрою);
- **резервує DNS:** netwatch перевіряє контейнер кожні 10 с. Якщо VartaDNS не відповідає, перенаправлення вимикається і DNS віддає сам роутер, тож мережа не лишається без інтернету. Коли контейнер піднімається, фільтрація вмикається знову;
- перезапускає контейнер при збої (`restart-interval`) і обмежує його пам'ять (`memory-high`);
- закриває обхід через IPv6 (вимикає роздачу DNS у RA, блокує 53/853 по IPv6);
- блокує DoT, DoQ і DoH до відомих публічних резолверів;
- закриває панель від усіх, крім адмінської підмережі.

Імпортуйте скрипт один раз. Щоб видалити все або почати заново, виконайте `deploy/mikrotik-uninstall.rsc`.

### Скидання пароля панелі

```
/container/envs/add list=ENV_VARTA key=VARTA_RESET_PASSWORD value=1
/container/stop [find name=vartadns]
# wait until stopped, then:
/container/start [find name=vartadns]
/log/print where message~"credentials"
/container/envs/remove [find key=VARTA_RESET_PASSWORD]
```

Правила, списки і статистика при цьому зберігаються. Зміна envs може вимагати перестворення контейнера, залежно від версії RouterOS.

### Слабкі роутери (128–256 МБ RAM): легкий профіль

Для hAP ac², hAP ac3 і подібних увімкніть змінну `VARTA_PROFILE=light`. Тоді VartaDNS стартує з легшим набором:
- списки HaGeZi Light, TIF Mini, URLhaus і Phishing Army (~300 тис. правил);
- кеш на 20 тис. записів, журнал на 1000 запитів.

Пам'ять: ~17 МБ у звичайній роботі, ~33 МБ під час оновлення списків (виміряно на x86). Готовий приклад скрипта для hAP ac² (мережа 192.168.11.0/24) лежить у `deploy/examples/mikrotik-hap-ac2.rsc`.

Профіль задає списки тільки при першому запуску, поки ще немає `state.json`. Далі списки керуються з панелі. На роутері з 128 МБ не вмикайте великі списки (Pro, повний TIF, NRD).

**Пароль з першого запуску** пишеться в лог RouterOS тільки один раз. Цей лог живе в оперативній пам'яті і зникає після перезавантаження, тому прочитайте пароль одразу (`/log/print where message~"credentials"`).

## Запуск на Linux / Proxmox (LXC)

```sh
./build.sh
sudo install dist/vartadns-linux-amd64 /usr/local/bin/vartadns
sudo mkdir -p /etc/vartadns /var/lib/vartadns
sudo cp deploy/config.json /etc/vartadns/config.json   # set "data_dir": "/var/lib/vartadns"
sudo vartadns -config /etc/vartadns/config.json
```

Або через Docker: `docker load -i dist/vartadns-0.1.1-amd64.tar`, потім:

```sh
docker run -d --name vartadns -p 53:53/udp -p 53:53/tcp -p 8080:8080 \
  -v vartadns-data:/data vartadns:0.1.1
```

## Конфігурація

Усі параметри наведено в `deploy/config.json`, повний список виводить `vartadns -print-default-config`. Основні:

| Параметр | Опис |
|---|---|
| `upstreams` | `https://...` (DoH), `IP`, `IP:port`, `tcp://IP:port` |
| `bootstrap_dns` | Звичайні DNS для розв'язання імен DoH-серверів і завантаження списків |
| `conditional_forwarding` | `{"lan": "192.168.88.1"}`: локальні імена йдуть на роутер |
| `block_mode` | `null` (0.0.0.0 / ::) або `nxdomain` |
| `allowed_clients` | Хто може надсилати запити (ACL). **Інші клієнти отримують тишу, а не помилку.** Якщо LAN офісу на публічних адресах (наприклад, /29 від провайдера), додайте цю підмережу сюди |
| `web_hosts` | Імена, за якими відкривається панель (`["dns.lan"]`). За IP-адресою панель доступна завжди. Захист від DNS rebinding |
| `bypass_clients` | Клієнти без фільтрації |
| `rate_limit_qps` / `rate_limit_burst` | Ліміт на одного клієнта (0 = вимкнено) |
| `cache_size` | Максимум записів у кеші |
| `list_update_hours` | Як часто оновлювати списки |

Стан (власні правила, списки, хеш пароля) зберігається в `data_dir/state.json`, завантажені списки — в `data_dir/lists/`. Сервер стартує з локальних копій списків, тому працює навіть до появи інтернету.

## Розробка

```sh
go test -race ./...                       # unit + integration tests
go run ./tools/fakeupstream &             # test upstream on 127.0.0.1:5300
go run ./tools/bench -server 127.0.0.1:53 # load generator
```

## Що далі (roadmap)

- виявлення DNS-тунелювання і DGA-доменів, сповіщення в Telegram;
- блокування DoH через IPv6, прив'язка IP–MAC для груп;
- DoH і DoT для клієнтів (сервер);
- інтеграція з MikroTik address-list через API, кілька інстансів з центральною панеллю.

## Ліцензія

[GPL-3.0](LICENSE). Можна вільно використовувати, зокрема в компаніях; змінені версії, які ви поширюєте, мають лишатися відкритими під тією ж ліцензією.

Списки блокування належать їхнім авторам (HaGeZi, abuse.ch URLhaus, Phishing Army) і завантажуються безпосередньо з їхніх сайтів.
