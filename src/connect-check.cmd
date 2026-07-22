@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo Диагностика интернета...
if not exist "%~dp0connect-check.exe" (
  echo Не найден connect-check.exe
  echo Соберите: make -f Makefile.diagnose win
  pause
  exit /b 1
)
"%~dp0connect-check.exe" %*
if errorlevel 1 pause
