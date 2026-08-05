#!/bin/bash
# Запуск GUI: снимает quarantine и стартует бинарь напрямую (без open/Gatekeeper UI).
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
APP="$DIR/ConnectCheck-mac.app"
BIN="$APP/Contents/MacOS/connect-check-gui"

if [ ! -d "$APP" ]; then
  echo "Нет $APP" >&2
  exit 1
fi
if [ ! -x "$BIN" ]; then
  echo "Нет исполняемого $BIN" >&2
  exit 1
fi

# Gatekeeper: «повреждено» = quarantine / битая подпись после скачивания
xattr -dr com.apple.quarantine "$DIR" 2>/dev/null || true
xattr -cr "$APP" 2>/dev/null || true

cd "$DIR"
exec "$BIN" "$@"
