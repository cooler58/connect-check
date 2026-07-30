@echo off
chcp 65001 >nul
cd /d "%~dp0"

REM cwd = папка пакета; GUI ищет CLI в .\win\ или рядом.
if not exist "%~dp0connect-check-gui-win.exe" (
  echo Не найден connect-check-gui-win.exe рядом с этим .cmd
  pause
  exit /b 1
)

start "" /D "%~dp0" "%~dp0connect-check-gui-win.exe" %*
if errorlevel 1 (
  echo GUI завершился с ошибкой. Без OpenGL/GPU используйте CLI:
  echo   win\connect-check.exe -y
  pause
)
