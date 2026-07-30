# Автообновление connect-check

Проверка и установка обновлений с GitHub Releases: [`cooler58/connect-check`](https://github.com/cooler58/connect-check/releases).

## CLI

```bash
connect-check --check-update   # 0 = актуально, 2 = есть новее, 1 = ошибка
connect-check --self-update    # скачать, заменить пакет, перезапустить
```

Без `--self-update` ничего не качается.

## GUI

При старте GUI дергает `releases/latest`. Если remote semver больше локального — баннер и кнопка **«Обновить»**. По кнопке: download → staging → helper после выхода процесса → relaunch.

## Что обновляется

Корень пакета (автодетект):

- рядом с CLI (`mac` / `linux` / `win`) есть GUI (`ConnectCheck-mac.app`, `connect-check-gui-linux`, `connect-check-gui-win.exe`) или `VERSION` → обновляется весь пакет (как в release-архиве);
- иначе — только каталог CLI.

Ассеты: `connect-check-mac-arm64-*.tar.gz`, `connect-check-linux-x86_64-*.tar.gz`, `connect-check-win-x86_64-*.zip`. Если в релизе есть `SHA256SUMS` — хеш проверяется до распаковки.

На macOS после подмены снимается quarantine (`xattr`), иначе Gatekeeper может мешать запуску.

## Переменные окружения

| Переменная | Назначение |
|------------|------------|
| `CONNECT_CHECK_UPDATE_REPO` | `owner/name` вместо `cooler58/connect-check` |
| `CONNECT_CHECK_NO_UPDATE=1` | запретить apply (check остаётся) |

## Ограничения v1

Нет тихого автоапдейта, Homebrew/Store, notarize. Замена идёт через helper после выхода процесса (нельзя надёжно перезаписать running binary).
