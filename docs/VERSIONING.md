# Версии, сборки и релизы

## SemVer

Файл [`VERSION`](../VERSION) в корне — единственный источник правды (формат `MAJOR.MINOR.PATCH`).

| Изменение | Когда |
|-----------|--------|
| **PATCH** `x.y.Z` | фикс бага, правка списков в `resources.conf`, мелкие правки отчёта |
| **MINOR** `x.Y.0` | новый этап/проба, новый флаг CLI, совместимое расширение |
| **MAJOR** `X.0.0` | ломающее изменение CLI/формата отчёта/`resources.conf` |

Макрос сборки: `-DCONNECT_CHECK_VERSION="…"`. Заголовок: `src/version.h`.

Формат `resources.conf`: поле `connect-check-version` и `CONNECT_CHECK_RESOURCES_FORMAT` — при несовместимом формате поднимать MAJOR или формат+MINOR.

## Процесс релиза

1. Обновить `VERSION`.
2. Запись в [`CHANGELOG.md`](../CHANGELOG.md) под новый заголовок.
3. `make release` (package + gui + `dist/` архивы; **linux обязателен** — нужен `zig` на macOS).
4. Коммит: `release: vX.Y.Z — краткое why` (включая `bin/mac`, `bin/linux`, `bin/win`).
5. Тег: `git tag -a vX.Y.Z -m "connect-check vX.Y.Z"`.
6. Пуш: `git push origin main && git push origin vX.Y.Z`.
7. GitHub Release: прикрепить `dist/connect-check-{linux,mac,win}-*-vX.Y.Z.*` (полный linux-пакет, не один файл).

Каждая опубликованная версия должна уезжать на GitHub (ветка + тег). Не пушить «сырые» WIP-коммиты как релизные теги.

## Что коммитить в релизе

- Исходники, `resources.conf`, `VERSION`, документация
- **Готовые бинарники** в `bin/{mac,linux,win}/`, `bin/resources.conf`, `bin/VERSION`, GUI в корне `bin/` (`ConnectCheck-mac.app`, `connect-check-gui-linux`, `connect-check-gui-win.exe`)

## Что не коммитить

- `reports/`, HTML-отчёты
- `build/`, `top_domains_embed.h` (генерируется)
- отладочные бинарники в **корне** репозитория (`./connect-check`, `./probe-*`)
- `.venv/`, `.env`, `.DS_Store`, `*.zip` пакетов


## Структура каталогов

| Путь | Роль |
|------|------|
| `src/` | CLI и probe исходники |
| `gui/` | GUI |
| `bin/` | выход сборки (локально) |
| `docs/` | процесс |
| `scripts/` | генераторы для сборки |
| `wordlists/` | данные для embed DNS-списка |
| `third_party/` | вендоренные зависимости GUI |

## Имена артефактов

- CLI: `connect-check` / `connect-check.exe`
- пробы: `probe-*`
- GUI: `connect-check-gui`, `ConnectCheck.app` / `ConnectCheck-mac.app`
- env: `CONNECT_CHECK_BIN_DIR`
