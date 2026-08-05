# connect-check — пакет в `bin/`

С **1.3.0** релизный пакет — **только GUI** (движок диагностики и проб встроен). Отдельные `connect-check` / `probe-*` в архив не входят.

## Раскладка

| Путь | Что |
|------|-----|
| **`bin/ConnectCheck-mac.app`** | GUI macOS (движок in-process) |
| **`bin/connect-check-gui-linux`** | GUI Linux (+ `libglfw*.so` при необходимости) |
| **`bin/connect-check-gui-win.exe`** | GUI Windows (+ лаунчер `connect-check-gui.cmd`) |
| `bin/resources.conf`, `bin/VERSION` | списки проверок и версия |

Сборка: `make release` или `make -f Makefile.gui package-all` + `make dist`.

## GUI

Диагностика, циклические пробы и проверка URL выполняются **внутри приложения** (worker-thread). Нужен `resources.conf` рядом с пакетом (или внутри `.app/Contents/MacOS`).

```bash
open bin/ConnectCheck-mac.app
./bin/connect-check-gui-linux
# Windows: connect-check-gui-win.exe
```

Шрифт: системный (macOS Arial Unicode / Windows Segoe UI / Linux DejaVu или Noto из ОС).

## Отладочный CLI (не в релизе)

```bash
make cli   # connect-check + probe-* в корне репозитория
```

## Когда что запускать

| Симптом | В GUI |
|---------|--------|
| «Нет интернета» / captive | Диагностика или проба Captive |
| Игры / Battle.net | Диагностика + пробы Battle.net / QUIC |
| Умный дом / MQTT | Диагностика + проба MQTT |
| Видео / CDN | Диагностика + проба Видео |
| Один URL | вкладка URL |
| apt/dnf/pacman / Windows Update / Apple | Диагностика → этап «Репозитории / обновления» |
