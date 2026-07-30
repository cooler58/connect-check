# connect-check — пакет в `bin/`

## Раскладка

| Путь | Что |
|------|-----|
| **`bin/ConnectCheck-mac.app`** | GUI macOS |
| **`bin/connect-check-gui-linux`** | GUI Linux (+ рядом `libglfw*.so`, `DejaVuSans.ttf` при необходимости) |
| **`bin/connect-check-gui-win.exe`** | GUI Windows (+ `DejaVuSans.ttf`, лаунчер `connect-check-gui.cmd`) |
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
./bin/mac/connect-check --check-update
./bin/mac/connect-check --self-update   # см. docs/UPDATE.md
```

Списки: `resources.conf` (секции `[significant]`, `[games_tcp]`, `[games_https]`, `[ai]`, `[video]`, `[banks]`, `[infra_tcp]`, `[infra_https]`).

Формат `[ai]` (с 1.0.6): `name|host|port|crit` — только TCP connect (HTTPS у AI часто «умный» таймаут). Старый вид `name|https://…|crit` ещё принимается.

Игры / IoT: витрины store/marketing часто antibot — в conf заложены CDN/API/облака клиента (Steam CDN, Epic account/CDN, Ubisoft Services, Nabu Casa, Hue discovery, Tapo WAP и т.п.).

## GUI

GUI ищет `connect-check` / `probe-*` **в текущей рабочей папке** (`cwd` или `cwd/mac|linux|win`). Запускайте из корня распакованного архива (лаунчеры ниже делают `cd` сами).

```bash
# mac — из корня архива / bin/
./ConnectCheck-mac.command
# или: cd … && open ConnectCheck-mac.app   (cwd должен быть папкой с mac/)

# linux
./connect-check-gui.sh

# windows — двойной клик
connect-check-gui.cmd
```

Override: `CONNECT_CHECK_BIN_DIR` на каталог с CLI. Шрифт: `DejaVuSans.ttf` рядом, иначе системный mono.

## Когда что запускать

| Симптом | Инструмент |
|---------|------------|
| На телефоне/TV «нет интернета» | `connect-check` или `probe-captive` |
| Игры / Battle.net | `connect-check` + `probe-battlenet` / `probe-quic` |
| Умный дом / Tuya | `connect-check` + `probe-mqtt` |
| Видео / CDN | `connect-check` + `probe-video` |
| DPI / Private DNS | `connect-check`, findings DoT/DoH |
