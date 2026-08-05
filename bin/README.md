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

```bash
# Linux
./bin/connect-check-gui-linux
# Windows
connect-check-gui-win.exe
```

### macOS — двойной клик по `ConnectCheck-mac.app`

Приложение **не нотаризовано** Apple (нет платного Developer ID). После скачивания с GitHub система один раз показывает:

> Apple не удалось подтвердить, что файл не содержит вредоносного ПО…

**Как открыть (без Terminal):**

1. **ПКМ** (или Control+клик) по `ConnectCheck-mac.app` → **Открыть** → в диалоге снова **Открыть**  
   или  
2. Двойной клик → **ОК** → **Системные настройки → Конфиденциальность и безопасность** → внизу **Всё равно открыть**

После этого обычный двойной клик работает. Terminal / `xattr` / `.command` не нужны.

Полностью убрать диалог можно только с **Apple Developer ID + notarize** (платная программа разработчика).
