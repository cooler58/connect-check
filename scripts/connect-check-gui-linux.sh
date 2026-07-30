#!/bin/sh
# Запуск GUI из каталога пакета (cwd = эта папка; CLI в ./linux/).
cd "$(dirname "$0")" || exit 1
exec ./connect-check-gui-linux "$@"
