# connect-check — пакет в `bin/`

Сборка: `make package` (или `make -f Makefile.package`).

В репозитории лежат **готовые сборки** последней версии:

| Каталог | Содержимое |
|---------|------------|
| [`bin/linux/`](linux/) | **Linux x86_64** (static musl): `connect-check` + все `probe-*` + `resources.conf` |
| [`bin/mac/`](mac/) | macOS arm64 CLI + GUI |
| [`bin/win/`](win/) | Windows x86_64 CLI + GUI |

Скачать пакетом: GitHub Release → `connect-check-linux-x86_64-*.tar.gz` (весь `bin/linux`).

Сборка: `make package` / `make dist` (нужен `zig` для кросс-сборки Linux с macOS).

## Содержимое после сборки

| Путь | Что |
|------|-----|
| `resources.conf` | общие списки ресурсов (копия также в каждой OS-папке) |
| `VERSION` | версия пакета (`-V` / `--version`) |
| `ConnectCheck-mac.app` | GUI macOS (двойной клик; CLI ищет в `bin/mac/`) |
| `connect-check-gui-linux` | GUI Linux |
| `connect-check-gui-win.exe` | GUI Windows |
| `mac/` `linux/` `win/` | CLI + probe-* + conf для соответствующей ОС |

## `connect-check` — полная диагностика

```bash
./connect-check
./connect-check -V
./connect-check -y
./connect-check -y --skip-dns-bulk --skip-video
./connect-check -y -o ./reports --no-open
./connect-check --resources ./my.conf -y
```

Windows: `connect-check.cmd` или `connect-check.exe`.

Списки этапов читаются из `resources.conf` (секции `[significant]`, `[games_tcp]`, `[games_https]`, `[ai]`, `[video]`, `[banks]`, `[infra_tcp]`).

Секция **`[infra_tcp]`** — TCP к облачной инфраструктуре (сейчас Selectel СПб/Москва: SSH/80/443).

## GUI

| Артефакт | ОС |
|----------|-----|
| `ConnectCheck-mac.app` | macOS |
| `connect-check-gui-linux` | Linux |
| `connect-check-gui-win.exe` | Windows |

Рядом должны лежать `connect-check`, `probe-*`, `resources.conf`. Каталог CLI можно задать через `CONNECT_CHECK_BIN_DIR`.

```bash
open bin/ConnectCheck-mac.app
CONNECT_CHECK_BIN_DIR=/path/to/bin/mac ./bin/mac/connect-check-gui
```

## Когда что запускать

| Симптом | Инструмент |
|---------|------------|
| На телефоне/TV «нет интернета», браузер на ПК жив | `connect-check` или `probe-captive` |
| Игры / Battle.net | `connect-check` + `probe-battlenet` / `probe-quic` |
| Умный дом / Tuya | `connect-check` (IoT) + `probe-mqtt` |
| Видео / CDN | `connect-check` + `probe-video` |
| Подозрение на DPI / Private DNS | `connect-check`, findings DoT/DoH |
