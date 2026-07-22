# Changelog

Формат: [Keep a Changelog](https://keepachangelog.com/). Версии — semver из файла `VERSION`.

## [1.0.0] — 2026-07-22

### Added
- Первый публичный релиз репозитория **connect-check** (ранее рабочее имя netscan).
- CLI `connect-check`: полная диагностика с HTML-отчётом.
- Периодические пробы: `probe-quic`, `probe-battlenet`, `probe-mqtt`, `probe-video`, `probe-captive`, `probe-url`.
- GUI (Nuklear/GLFW): `connect-check-gui` / `ConnectCheck.app`.
- `resources.conf` с группами значимых ресурсов, игр, AI, видео, банков.
- Структура `src/`, `gui/`, `bin/`, правила версий в `docs/VERSIONING.md`.

### Notes
- Бинарники `bin/{mac,linux,win}` в git не хранятся — собираются через `make package`.
