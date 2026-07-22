# connect-check

Набор утилит для разбора «интернет вроде есть, а телефон / IoT / игра / видео — нет».
CLI на macOS / Linux / Windows; опциональный GUI поверх тех же бинарников.

**Версия:** [`VERSION`](VERSION) — `connect-check -V` / `probe-* -V`. Правила: [`docs/VERSIONING.md`](docs/VERSIONING.md).

## Структура

```
src/           — C-исходники (connect-check, probe-*)
gui/           — Nuklear/GLFW GUI
bin/           — готовые сборки (в git)
  ConnectCheck-mac.app / connect-check-gui-linux / connect-check-gui-win.exe  ← GUI
  mac/ linux/ win/   ← CLI + probe-* по ОС
scripts/ wordlists/ third_party/ docs/
resources.conf VERSION
```

Подробности раскладки: [`bin/README.md`](bin/README.md).

## Инструменты

| Бинарь | Назначение |
|--------|------------|
| `connect-check` | Полный прогон + HTML-отчёт |
| `probe-*` | QUIC, Battle.net, MQTT, video, captive, URL |
| GUI | вкладки diagnose / пробы / probe-url |

## Быстрый старт

```bash
make package                              # CLI → bin/{mac,linux,win}
make -f Makefile.gui package-all          # GUI → корень bin/

./bin/mac/connect-check -y
./bin/linux/connect-check -V

open bin/ConnectCheck-mac.app             # GUI mac (CLI из bin/mac)
CONNECT_CHECK_BIN_DIR=bin/linux ./bin/connect-check-gui-linux
```

Рядом с CLI лежит **`resources.conf`**. Без файла — встроенные списки.

## Сборка

```bash
make help
make package          # CLI всех ОС (Linux с macOS — через zig)
make -f Makefile.gui package-all
make dist             # архивы для GitHub Release
make release
```
