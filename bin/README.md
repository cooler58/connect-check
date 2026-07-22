# connect-check — пакет в `bin/`

## Раскладка

| Путь | Что |
|------|-----|
| **`bin/ConnectCheck-mac.app`** | GUI macOS |
| **`bin/connect-check-gui-linux`** | GUI Linux (+ рядом `libglfw*.so`, `DejaVuSans.ttf` при необходимости) |
| **`bin/connect-check-gui-win.exe`** | GUI Windows (+ `DejaVuSans.ttf` в корне `bin/`) |
| `bin/mac/` | CLI macOS: `connect-check`, `probe-*`, `resources.conf` |
| `bin/linux/` | CLI Linux x86_64 (static musl): то же |
| `bin/win/` | CLI Windows: `connect-check.exe`, `probe-*.exe`, `connect-check.cmd`, `resources.conf` |
| `bin/resources.conf`, `bin/VERSION` | общие файлы пакета |

GUI — **только в корне `bin/`**. Остальные бинарники — **только в папках ОС**.

Сборка: `make package` (CLI) + `make -f Makefile.gui package-all` (GUI). Архивы Release: `make dist`.

## `connect-check` — полная диагностика

```bash
./bin/mac/connect-check -V
./bin/linux/connect-check -y
./bin/win/connect-check.exe -y
```

Списки: `resources.conf` (секции `[significant]`, `[games_tcp]`, `[games_https]`, `[ai]`, `[video]`, `[banks]`, `[infra_tcp]`, `[infra_https]`).

## GUI

```bash
open bin/ConnectCheck-mac.app
CONNECT_CHECK_BIN_DIR=bin/mac open bin/ConnectCheck-mac.app

CONNECT_CHECK_BIN_DIR=bin/linux ./bin/connect-check-gui-linux
CONNECT_CHECK_BIN_DIR=bin/win ./bin/connect-check-gui-win.exe
```

Рядом с GUI задайте `CONNECT_CHECK_BIN_DIR` на папку CLI вашей ОС (`bin/mac`, `bin/linux` или `bin/win`).

## Когда что запускать

| Симптом | Инструмент |
|---------|------------|
| На телефоне/TV «нет интернета» | `connect-check` или `probe-captive` |
| Игры / Battle.net | `connect-check` + `probe-battlenet` / `probe-quic` |
| Умный дом / Tuya | `connect-check` + `probe-mqtt` |
| Видео / CDN | `connect-check` + `probe-video` |
| DPI / Private DNS | `connect-check`, findings DoT/DoH |
