#!/bin/bash
# Запуск GUI из каталога пакета. Снимает quarantine (иначе Gatekeeper: «приложение повреждено»).
cd "$(dirname "$0")" || exit 1
APP="./ConnectCheck-mac.app"
if [ -d "$APP" ]; then
  xattr -dr com.apple.quarantine "$APP" 2>/dev/null || true
  xattr -cr "$APP" 2>/dev/null || true
fi
xattr -dr com.apple.quarantine . 2>/dev/null || true
exec open "$APP" --args "$@"
