# Автообновление connect-check

Проверка и установка обновлений с GitHub Releases: [`cooler58/connect-check`](https://github.com/cooler58/connect-check/releases).

## GUI (основной путь с 1.3.0)

При старте GUI дергает `releases/latest`. Если remote semver больше локального — баннер и кнопка **«Обновить»**. По кнопке: download → staging → helper после выхода процесса → relaunch GUI.

Relaunch:

- macOS: `open ConnectCheck-mac.app`
- Linux: `connect-check-gui-linux`
- Windows: `connect-check-gui-win.exe`

## Отладочный CLI

```bash
./connect-check --check-update   # только если собран make cli
./connect-check --self-update
```

Headless CLI **не входит** в release-архивы с 1.3.0.

## Что обновляется

Корень пакета (автодетект по GUI-маркеру / `VERSION` / `resources.conf`):

- обновляется весь GUI-пакет (как в release-архиве);
- ожидается GUI-бинарник ОС, не каталог `mac|linux|win/connect-check`.

Ассеты: `connect-check-mac-arm64-*.tar.gz`, `connect-check-linux-x86_64-*.tar.gz`, `connect-check-win-x86_64-*.zip`. Если в релизе есть `SHA256SUMS` — хеш проверяется до распаковки.

На macOS после подмены снимается quarantine (`xattr`), иначе Gatekeeper пишет «приложение повреждено».
При первой распаковке архива удобнее запускать `ConnectCheck-mac.command` (тоже снимает quarantine), либо:
`xattr -dr com.apple.quarantine ConnectCheck-mac.app`.

## Переменные окружения

| Переменная | Назначение |
|------------|------------|
| `CONNECT_CHECK_UPDATE_REPO` | `owner/name` вместо `cooler58/connect-check` |
| `CONNECT_CHECK_NO_UPDATE=1` | запретить apply (check остаётся) |

## Ограничения

Нет тихого автоапдейта, Homebrew/Store, notarize. Замена идёт через helper после выхода процесса.

Клиенты **&lt; 1.3.0**, ожидающие CLI в архиве, могут не принять GUI-only пакет — обновление вручную с Releases.
