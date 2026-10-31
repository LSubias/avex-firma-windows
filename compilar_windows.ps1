param(
    [string]$PythonExecutable = ""
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if ($env:OS -ne "Windows_NT") {
    throw "Este proyecto genera un EXE de Windows y debe compilarse desde Windows."
}

if (-not $PythonExecutable -and $env:pythonLocation) {
    $candidate = Join-Path $env:pythonLocation "python.exe"
    if (Test-Path $candidate) {
        $PythonExecutable = $candidate
    }
}

if (-not $PythonExecutable) {
    $launcher = Get-Command py -ErrorAction SilentlyContinue
    if (-not $launcher) {
        throw "No se encontró Python 3.11 de 32 bits."
    }
    $PythonExecutable = (& py -3.11-32 -c "import sys; print(sys.executable)").Trim()
}

if (-not (Test-Path $PythonExecutable)) {
    throw "No se encontró Python en: $PythonExecutable"
}

$pythonInfo = & $PythonExecutable -c "import platform, struct; print(platform.python_version() + '|' + str(struct.calcsize('P') * 8))"
$version, $bits = $pythonInfo.Trim().Split("|")
if ($LASTEXITCODE -ne 0 -or -not $version.StartsWith("3.11.") -or $bits -ne "32") {
    throw "Se necesita Python 3.11 de 32 bits para coincidir con el SafeNet x32 adjunto."
}

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "[1/5] Creando entorno de compilación..."
    & $PythonExecutable -m venv .venv
}

$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$venvBits = & $venvPython -c "import struct; print(struct.calcsize('P') * 8)"
if ($LASTEXITCODE -ne 0 -or $venvBits -ne "32") {
    throw "El entorno .venv existente no usa Python de 32 bits. Eliminá .venv y volvé a compilar."
}

Write-Host "[2/5] Instalando dependencias..."
& $venvPython -m pip install --upgrade pip
& $venvPython -m pip install -r requirements-build.txt
if ($LASTEXITCODE -ne 0) {
    throw "Falló la instalación de dependencias. python-pkcs11 requiere Visual Studio Build Tools 2022 con 'Desarrollo para el escritorio con C++'."
}

Write-Host "[3/5] Construyendo el agente..."
& $venvPython -m PyInstaller --noconfirm --clean AgenteFirmaAVEX.spec
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller no pudo construir el agente."
}

$isccCandidates = @(
    "$env:ProgramFiles(x86)\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
)
$iscc = $isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
    throw "No se encontró Inno Setup 6. Instalalo y volvé a ejecutar este archivo."
}

$sacMsi = "payload\SafeNetAuthenticationClient-x32.msi"
if (Test-Path $sacMsi) {
    Write-Host "[4/5] SafeNet Windows encontrado: se incluirá en el instalador."
} else {
    Write-Warning "No está $sacMsi. El instalador se creará sin SafeNet; sirve si las PCs ya lo tienen instalado."
}

Write-Host "[5/5] Construyendo el instalador único..."
& $iscc "installer\AgenteFirmaAVEX.iss"
if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup no pudo construir el instalador final."
}

$resultado = Join-Path $PSScriptRoot "salida\AvexFirmaSetup.exe"
if (-not (Test-Path $resultado)) {
    throw "La compilación terminó pero no apareció el instalador esperado."
}

Write-Host ""
Write-Host "LISTO: $resultado" -ForegroundColor Green
Write-Host "Probalo primero en una PC de prueba con el token conectado."
