# Changelog

Формат: [Keep a Changelog](https://keepachangelog.com/). Версии — semver из файла `VERSION`.

## [Unreleased]

## [1.4.0] — 2026-08-05

### Added
- Этап **Репозитории / обновления**: зеркала Debian/Ubuntu/Fedora/Rocky/Alma/Arch/Alpine/openSUSE/Kali (+ Yandex), Windows Update CTL / Winget / Chocolatey, Apple gdmf/mesu, Android/Chrome update, Docker/npm/PyPI/crates/Maven/NuGet/Homebrew/Flathub/Snap — секция `[updates]` в `resources.conf`.

### Changed
- GUI использует **системные шрифты** (Arial Unicode / Segoe UI / DejaVu|Noto из ОС); `DejaVuSans.ttf` убран из пакета и репозитория.

## [1.3.0] — 2026-08-05

### Changed
- **GUI-only релиз**: диагностика и пробы выполняются **внутри приложения** (in-process движок `cc_engine` / `cc_probe_*`). Отдельные `connect-check` и `probe-*` больше не входят в пакет и архивы Release.
- GUI: worker-thread + callbacks — этапы, счётчики сбоев/внимания, кнопка «Открыть отчёт»; баннер «Движок встроен» вместо пути к CLI.
- Self-update и `dist/`: раскладка только GUI + `resources.conf` + `VERSION` (+ лаунчеры).
- Документация: `docs/VERSIONING.md`, `docs/UPDATE.md`, `bin/README.md`.

### Notes
- Клиенты **&lt; 1.3.0**, ожидающие CLI в `mac|linux|win/`, не обновляются «частично» — скачайте полный пакет с Releases.

## [1.2.7] — 2026-07-31

### Changed
- HTML-отчёт: кнопка TXT — только **сбои** (fail), без «Внимание».

## [1.2.6] — 2026-07-31

### Added
- Этап **CDN / счётчики**: `yastatic.net` (HTML + asset с ya.ru, magic PNG) и `counter.yadro.ru` (GIF hit/logo) — подтверждение тела ответа, не только TCP.
- Этап **Почта**: веб (Яндекс/Mail.ru/Gmail/Outlook/iCloud/Rambler/Proton) + SMTP/IMAP/POP3 (баннер `220`/`+OK` или TLS ServerHello на :465/:993/:995).
- Этап **Значимые ресурсы (Белые списки МЦ)** (секция `[popular_ru]`): расширенный список; зарубежный контроль — этап **Зарубежные ресурсы** (`[significant]`).
- Игры Lesta/Wargaming: Мир танков (+CDN), Мир кораблей / WoWs RU, War Thunder, Escape from Tarkov.
- Roblox: TCP + rbxcdn (setup/CSS); раньше был только сайт в HTTPS.
- Канарейки ASN: Cloudflare / Hetzner / DigitalOcean / OVH / GitHub в `[infra_*]`.
- **Cloudflare 100KB canary** — детект throttle ≈16KB (ТСПУ / AS13335).
- **Steam SDR UDP** — GetSDRConfig + UDP к relay (голос/матчмейкинг).
- Этап **Гео / IX**: точки по странам + DE-CIX / AMS-IX / LINX / DATAIX / Eurasia Peering / HE LG (`[geo]`).

### Changed
- HTML-отчёт: крупно только **Сбои**; карточки **Внимание** и warning-выводы — свёрнуты; таблицы разделов без свёрток.
- HTML-отчёт: короткий дисклеймер — не авторизованное заключение; проверки могут не проходить капчи/антиботы.
- HTML-отчёт: кнопка **Скачать TXT проблемных узлов** (fail+warn) — имя, категория, IP, PORT, PROTO, SNI, URL.
- HTML-отчёт: URL в допинфо проверки — кликабельная ссылка (`target=_blank`) + кнопка «открыть».
- HTTPS-пробы сайтов: браузерные заголовки (Sec-Fetch / Accept / Chrome 138); антибот/WAF/капча → **OK** (хост жив), не FAIL.
- HTTPS-пробы сайтов: скорость **стр+CDN** — HTML + выборка JS/CSS/img; частичная недоступность ассетов при живом HTML → **Внимание** (не Сбой); critical — только если канарейки yastatic/yadro тоже легли.
- Связность/DNS: **Яндекс DNS**, кеширующие **НСДИ**, **AdGuard**; DoT — `common.dot.dns.yandex.net`, `dns.adguard-dns.com`.
- Списки ресурсов: убраны дубли; порядок этапов: CDN → значимые МЦ → зарубежные → банки → почта → …

## [1.2.5] — 2026-07-31

### Added
- Игры: Twitch, Kick, loot.farm, HoYoverse / Genshin / HoYoLAB, PSN Store.
- CDN этих сервисов: Twitch (jtvnw/usher/VOD), Kick files/images, HoYoverse webstatic/fastcdn/upload, PSN image/download, loot.farm tags/API, IVI thumbs.
- Видео: Кинопоиск (home + video path).

## [1.2.4] — 2026-07-30

### Fixed
- GUI-лог: корректная обработка CLI progress (`\r`, `\033[K`) — одна перезаписываемая строка вместо каши; ANSI вычищается.
- `resources.conf`: приоритет у файла в **корне пакета** (родитель `mac|linux|win/`), затем cwd, затем рядом с CLI — правки в корне архива снова попадают в отчёт; в лог/отчёт пишется путь загруженного conf.

### Added
- Секция банков/сервисов: **Проблемы провайдера** — Zoom, Bitrix24, Google Play.

## [1.2.3] — 2026-07-30

### Fixed
- Windows GUI: **GDI+ вместо OpenGL/GLFW** — уходит ошибка GLFW 65542 (`API_UNAVAILABLE`) на машинах без GPU ICD / в RDP.
- GUI ищет CLI в соседней `mac|linux|win/` от пути приложения (без env).
- Консольные CLI/probes: Win → `msvcrt` (системная), Mac → только `libSystem`, Linux → static musl — без сторонних runtime DLL.

## [1.2.2] — 2026-07-30

### Fixed
- GUI снова находит CLI при двойном клике по `.app` / `.exe`: ищет `mac|linux|win/` **рядом с приложением**, не в cwd и без `CONNECT_CHECK_BIN_DIR`.
- Шрифт: рядом с пакетом / внутри `.app`, иначе системный mono.

## [1.2.1] — 2026-07-30

### Fixed
- Windows: сборка через **msvcrt-os** (без `api-ms-win-crt-*`) — надёжнее старт на Win10 без VC++ Redistributable / битого UCRT.
- Windows GUI: при ошибке OpenGL/GLFW — **MessageBox** вместо тихого выхода (`-mwindows`); fallback контекста GL; DPI awareness.
- Шрифт: `DejaVuSans*.ttf` рядом, иначе системные **моноширинные** (Consolas / Courier New / DejaVuSansMono и т.п.).
- Лаунчеры в архивах: `connect-check-gui.cmd`, `ConnectCheck-mac.command`, `connect-check-gui.sh`.
- GUI: проверка обновлений после создания окна (не блокирует старт).

## [1.2.0] — 2026-07-30

### Added
- Автообновление с GitHub Releases: CLI `--check-update` / `--self-update`, в GUI баннер и кнопка «Обновить».
- Модуль `src/selfupdate.c`: semver, download ассета ОС, проверка `SHA256SUMS`, staging + helper relaunch.
- `make dist` пишет `dist/SHA256SUMS` для проверки целостности.
- Документация: [`docs/UPDATE.md`](docs/UPDATE.md).

## [1.1.1] — 2026-07-28

### Changed
- Распараллелены оставшиеся массовые пробы: **DPI** (порты/DoH/SNI/QUIC), **NTP**, gstatic×8, download-пробы скорости.
- Умный дом / IoT уже был на пуле в 1.1.0 (TCP + HTTPS).
- При сбое HTTP(S)-пробы ресурса — fallback **TCP :443 / :80** (если порт открыт → warn, не fail).

## [1.1.0] — 2026-07-28

### Added
- Параллельные пробы внутри этапов (пул воркеров, по умолчанию 32; `--jobs N` / `CONNECT_CHECK_JOBS`).
- Для недоступных (`fail`) ресурсов: **ping** и **traceroute** в спойлере SNI/IP/URL, с копированием.
- В значимых ресурсах: **Google Play** и **App Store**.

### Changed
- Массовые списки (Captive, IoT, значимые, облако, игры, AI, видео, банки) гоняются параллельно; этапы по-прежнему по порядку.

## [1.0.6] — 2026-07-22

### Fixed
- Ложные FAIL на витринах с antibot/DPI: **Steam / Epic / Ubisoft**, **Wildberries**, **2ГИС**, **Teams**, **Home Assistant / Hue / Tapo** — пробы через CDN, API, discovery/WAP или облако клиента.
- Госсайты (Кремль / Правительство / Дума): проверка по **HTTP** (:443 часто мёртв).
- **Steam CM**: если `GetCMList` недоступен — fallback TCP на `*.steamserver.net:27017`.
- Облако: HTTP **401/403** от S3/CDN без ключа = OK.

### Changed
- Этап **AI / LLM**: только **TCP :443** (без HTTPS-проб). Формат `[ai]`: `name|host|port|crit` (старые URL в conf ещё читаются).

## [1.0.5] — 2026-07-22

### Changed
- Раскладка `bin/`: **GUI только в корне** (`ConnectCheck-mac.app`, `connect-check-gui-linux`, `connect-check-gui-win.exe`); CLI — только в `bin/{mac,linux,win}/`.
- Полная пересборка всех ОС + Linux GUI; документация обновлена.

## [1.0.4] — 2026-07-22

### Fixed
- Полная пересборка и выкладка **всех** бинарников (mac/linux/win + probes + GUI); в Release — архивы пакетов, не один файл.

## [1.0.3] — 2026-07-22

### Fixed
- Ложные FAIL на **Госуслугах** и части госсайтов на macOS: системный curl/LibreSSL рвал TLS (`SSL_ERROR_SYSCALL`), браузер при этом работал. Пробы идут через `CURL_SSL_BACKEND=secure-transport`.
- Значимые ресурсы / банки: один User-Agent и таймаут 12 с вместо 5 UA × 3 с; убран принудительный `--http1.1`.

## [1.0.2] — 2026-07-22

### Added
- Секция `[infra_https]`: рабочие HTTPS-проверки **AWS** и **AWS S3** (Health/Status + S3 403 AccessDenied = живой endpoint).

### Changed
- Убраны flaky TCP к `s3.amazonaws.com` / STS (из РФ часто TLS timeout); оставлены EU S3/EC2 TCP + HTTPS S3.

## [1.0.1] — 2026-07-22

### Added
- Этап **Облако** (`[infra_tcp]`): Selectel СПб/Мск (SSH/80/443), AWS (S3/EC2/STS EU), Azure (portal/management/login/blob).
- В git и релизы выкладываются собранные бинарники в `bin/`.

### Changed
- Политика репозитория: `bin/{mac,linux,win}` и GUI-пакеты коммитятся при релизе.

## [1.0.0] — 2026-07-22

### Added
- Первый публичный релиз репозитория **connect-check** (ранее рабочее имя netscan).
- CLI `connect-check`: полная диагностика с HTML-отчётом.
- Периодические пробы: `probe-quic`, `probe-battlenet`, `probe-mqtt`, `probe-video`, `probe-captive`, `probe-url`.
- GUI (Nuklear/GLFW): `connect-check-gui` / `ConnectCheck.app`.
- `resources.conf` с группами значимых ресурсов, игр, AI, видео, банков.
- Структура `src/`, `gui/`, `bin/`, правила версий в `docs/VERSIONING.md`.

### Notes
- Бинарники `bin/{mac,linux,win}` в git не хранились — начиная с 1.0.1 хранятся.
