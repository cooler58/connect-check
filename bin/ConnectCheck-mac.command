#!/bin/bash
# Запуск GUI из каталога пакета (cwd = эта папка; CLI в ./mac/).
cd "$(dirname "$0")" || exit 1
exec ./ConnectCheck-mac.app/Contents/MacOS/connect-check-gui "$@"
