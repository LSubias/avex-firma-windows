@echo off
setlocal
echo Verificando el agente en http://127.0.0.1:47812/estado ...
echo.
curl.exe --fail --silent --show-error http://127.0.0.1:47812/estado
if errorlevel 1 (
  echo.
  echo.
  echo No se pudo contactar al agente.
  echo Revisa el log en %%LOCALAPPDATA%%\AVEX\AgenteFirma\agente.log
  pause
  exit /b 1
)
echo.
echo.
echo Agente activo. Para leer el certificado, conecta el token y visita:
echo http://127.0.0.1:47812/certificado
pause

