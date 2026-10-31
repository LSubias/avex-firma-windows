@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0compilar_windows.ps1"
if errorlevel 1 (
  echo.
  echo La compilacion no pudo completarse. Revisa el mensaje anterior.
  pause
  exit /b 1
)
echo.
echo El instalador quedo en salida\AvexFirmaSetup.exe
pause

