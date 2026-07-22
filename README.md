# connect-check

Набор утилит для разбора «интернет вроде есть, а телефон / IoT / игра / видео — нет».
CLI на macOS / Linux / Windows; опциональный GUI поверх тех же бинарников.

**Версия:** [`VERSION`](VERSION) — `./connect-check -V` / `./probe-* -V`. Правила релизов: [`docs/VERSIONING.md`](docs/VERSIONING.md).

## Структура

```
src/           — C-исходники (connect-check, probe-*)
gui/           — Nuklear/GLFW GUI
scripts/       — вспомогательные скрипты сборки
wordlists/     — списки доменов для DNS-bulk
third_party/   — Nuklear, GLFW (Win), шрифт
bin/           — собранные пакеты (в git только README)
docs/          — версионирование и процесс релизов
resources.conf — списки проверяемых ресурсов
VERSION        — semver источника правды
```

## Инструменты

| Бинарь | Назначение |
|--------|------------|
| `connect-check` | Полный прогон: captive, DNS/DoT/DoH, NTP, IoT, DPI, сайты, игры, AI, видео, банки, внешний IP, скорость. HTML-отчёт. |
| `probe-quic` | Периодический QUIC Initial |
| `probe-battlenet` | TCP/TLS к Battle.net |
| `probe-mqtt` | MQTT / MQTTS (IoT) |
| `probe-video` | Видео CDN / стриминг |
| `probe-captive` | Captive portal / «нет интернета» на клиентах |
| `probe-url` | Разовый HTTP(S) URL |
| `connect-check-gui` | Окно с вкладками diagnose / пробы / probe-url |

## Быстрый старт

```bash
make package          # CLI → bin/{mac,linux,win}
make gui              # GUI текущей ОС

./bin/mac/connect-check -y
./connect-check -V

# GUI (рядом connect-check, probe-*, resources.conf)
open bin/ConnectCheck-mac.app
```

Рядом с `connect-check` лежит **`resources.conf`**. Без файла — встроенные списки. Подробности: [`bin/README.md`](bin/README.md).

Windows: `connect-check.cmd` или `connect-check.exe` (нужен `curl.exe` в PATH).

## Сборка

```bash
make help
make cli              # отладочные бинарники в корне
make package          # пакет в bin/
make release          # проверка VERSION + package
```

Кросс-Linux с macOS: `brew install zig`. GUI: `brew install glfw` (mac), MinGW + `third_party/win` (Windows).
