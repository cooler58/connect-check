# Версии, сборки и релизы

## SemVer

Файл [`VERSION`](../VERSION) в корне — единственный источник правды (формат `MAJOR.MINOR.PATCH`).

| Изменение | Когда |
|-----------|--------|
| **PATCH** `x.y.Z` | фикс бага, правка списков в `resources.conf`, мелкие правки отчёта |
| **MINOR** `x.Y.0` | новый этап/проба, расширение GUI/движка |
| **MAJOR** `X.0.0` | ломающее изменение формата отчёта/`resources.conf` / поставки пакета |

Макрос сборки: `-DCONNECT_CHECK_VERSION="…"`. Заголовок: `src/version.h`.

Формат `resources.conf`: поле `connect-check-version` и `CONNECT_CHECK_RESOURCES_FORMAT` — при несовместимом формате поднимать MAJOR или формат+MINOR.

Секция `[ai]` (с 1.0.6): предпочтительно `name|host|port|crit` (TCP). Устаревший `name|url|crit` парсер всё ещё понимает.

## Процесс релиза

1. Обновить `VERSION`.
2. Запись в [`CHANGELOG.md`](../CHANGELOG.md) под новый заголовок.
3. `make release` (GUI all + `dist/` архивы; **linux GUI** — Docker/`zig` по ситуации).
4. Коммит: `release: vX.Y.Z — краткое why` (включая GUI в корне `bin/`).
5. Тег: `git tag -a vX.Y.Z -m "connect-check vX.Y.Z"`.
6. Пуш: `git push origin main && git push origin vX.Y.Z`.
7. GitHub Release: прикрепить `dist/connect-check-{linux,mac,win}-*-X.Y.Z.*` и **`dist/SHA256SUMS`**.

Автообновление клиентов: [`docs/UPDATE.md`](UPDATE.md).

С **1.3.0** пакет GUI-only: старые клиенты, ожидающие CLI в `mac|linux|win/`, не обновляются «частично» — в notes релиза указать переход.

## Что коммитить в релизе

- Исходники, `resources.conf`, `VERSION`, документация
- **GUI только в корне `bin/`:** `ConnectCheck-mac.app`, `connect-check-gui-linux`, `connect-check-gui-win.exe` (+ `libglfw*.so` на Linux, `resources.conf`, `VERSION`); шрифты системные

## Что не коммитить

- `reports/`, HTML-отчёты
- `build/`, `dist/`, `top_domains_embed.h`
- отладочные бинарники в **корне репозитория** (`./connect-check`, `./probe-*`)
- CLI в `bin/mac|linux|win/` (снято с релиза)
- `.venv/`, `.env`, `.DS_Store`, `*.zip`

## Структура каталогов

| Путь | Роль |
|------|------|
| `src/` | движок (`connect-check.c`, `cc_engine.h`, `cc_probes.c`), self-update |
| `gui/` | GUI (Nuklear), линкует движок |
| `bin/` | GUI + `resources.conf` + `VERSION` |
| `docs/` | процесс |
| `scripts/` | генераторы для сборки |
| `wordlists/` | данные для embed DNS-списка |
| `third_party/` | вендоренные зависимости GUI |

## Имена артефактов

- GUI: `bin/ConnectCheck-mac.app`, `bin/connect-check-gui-linux`, `bin/connect-check-gui-win.exe`
- Отладочный CLI: `make cli` → корневые бинарники (не в `dist/`)
