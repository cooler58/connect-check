# Changelog

Формат: [Keep a Changelog](https://keepachangelog.com/). Версии — semver из файла `VERSION`.

## [1.0.2] — 2026-07-22

### Added
- Секция `[infra_https]`: рабочие HTTPS-проверки **AWS** и **AWS S3** (Health/Status + S3 403 AccessDenied = живой endpoint).

### Changed
- Убраны flaky TCP к `s3.amazonaws.com` / STS (из РФ часто TLS timeout); оставлены EU S3/EC2 TCP + HTTPS S3.

## [1.0.1] — 2026-07-22

### Added
- Этап **Облако** (`[infra_tcp]`): Selectel СПб/Мск (SSH/80/443), AWS (S3/EC2/STS EU), Azure (portal/management/login/blob).
- В git и релизы выкладываются собранные бинарники в `bin/`.

### Changed
- Политика репозитория: `bin/{mac,linux,win}` и GUI-пакеты коммитятся при релизе.

## [1.0.0] — 2026-07-22

### Added
- Первый публичный релиз репозитория **connect-check** (ранее рабочее имя netscan).
- CLI `connect-check`: полная диагностика с HTML-отчётом.
- Периодические пробы: `probe-quic`, `probe-battlenet`, `probe-mqtt`, `probe-video`, `probe-captive`, `probe-url`.
- GUI (Nuklear/GLFW): `connect-check-gui` / `ConnectCheck.app`.
- `resources.conf` с группами значимых ресурсов, игр, AI, видео, банков.
- Структура `src/`, `gui/`, `bin/`, правила версий в `docs/VERSIONING.md`.

### Notes
- Бинарники `bin/{mac,linux,win}` в git не хранились — начиная с 1.0.1 хранятся.
