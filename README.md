# Agente Firma AVEX para Windows (x86)

Este paquete construye un instalador único llamado `AvexFirmaSetup.exe`.
La PC de destino no necesita Python.

## Antes de compilar

En una PC Windows instalá:

1. Python 3.11 de **32 bits** (necesario para coincidir con SafeNet x32).
2. Inno Setup 6.
3. Visual Studio Build Tools 2022 con la carga de trabajo **Desarrollo para el
   escritorio con C++**. Se usa solamente para compilar `python-pkcs11`.
4. El MSI SafeNet 10.8 R6 x32 ya está incluido en `payload`.

Después hacé doble clic en `PREPARAR_Y_COMPILAR.cmd`. El resultado queda en:

`salida\AvexFirmaSetup.exe`

## Compilar con GitHub Actions

Este proyecto incluye `.github/workflows/build-windows.yml`. Subilo a un
repositorio **privado**, abrí la pestaña Actions, elegí `Compilar instalador
Windows` y ejecutá `Run workflow`. El artefacto publicado contiene:

`AvexFirmaSetup.exe`

El MSI de SafeNet es software de terceros. No publiques este repositorio ni
redistribuyas el instalador fuera del alcance autorizado por la organización.

## Qué instala el EXE

- SafeNet Authentication Client 10.8 R6 x32, si todavía no está instalado.
- El agente y todo su runtime Python en `C:\Program Files\AVEX\AgenteFirma`.
- Inicio automático para todos los usuarios de la computadora.
- El agente local en `http://127.0.0.1:47812`.

## Prueba posterior

Con SafeNet instalado y el token conectado, abrí en el navegador:

`http://127.0.0.1:47812/estado`

Luego probá:

`http://127.0.0.1:47812/certificado`

Los registros quedan en `%LOCALAPPDATA%\AVEX\AgenteFirma\agente.log`.

## Observaciones de distribución

- Compilá el instalador desde Windows; PyInstaller no genera correctamente
  ejecutables Windows desde Linux.
- El agente es x86 porque una aplicación x64 no puede cargar la DLL PKCS#11
  de 32 bits del MSI recibido. Funciona en Windows x86 y Windows x64.
- Probalo en una PC limpia antes de distribuirlo.
- Para evitar advertencias de SmartScreen en una distribución institucional,
  firmá el instalador y el ejecutable con un certificado de firma de código.
- El agente permite los frontends AVEX de preproducción y producción mediante
  una lista CORS explícita.
- El workflow de GitHub Actions también prueba que el ejecutable responda en
  `/estado` antes de publicar el instalador.
