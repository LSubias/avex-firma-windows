#define MyAppName "Agente Firma AVEX"
#define MyAppVersion "1.0.1"
#define MyAppPublisher "AVEX"
#define MyAppExeName "AgenteFirmaAVEX.exe"

[Setup]
AppId={{B24E7AB4-4354-4BA1-A157-FD5F8DD48B7D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\AVEX\AgenteFirma
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x86compatible and not arm64
OutputDir=..\salida
OutputBaseFilename=AvexFirmaSetup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Files]
Source: "..\dist\AgenteFirmaAVEX\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
#if FileExists("..\payload\SafeNetAuthenticationClient-x32.msi")
Source: "..\payload\SafeNetAuthenticationClient-x32.msi"; DestDir: "{tmp}"; Flags: deleteafterinstall
#endif

[Run]
#if FileExists("..\payload\SafeNetAuthenticationClient-x32.msi")
Filename: "msiexec.exe"; Parameters: "/i ""{tmp}\SafeNetAuthenticationClient-x32.msi"" /passive /norestart"; StatusMsg: "Instalando SafeNet Authentication Client 10.8 R6..."; Flags: waituntilterminated; Check: not SafeNetInstalado
#endif
Filename: "{app}\{#MyAppExeName}"; Description: "Iniciar {#MyAppName}"; Flags: nowait postinstall runasoriginaluser skipifsilent

[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "AgenteFirmaAVEX"; ValueData: """{app}\{#MyAppExeName}"""; Flags: uninsdeletevalue

[UninstallRun]
Filename: "{cmd}"; Parameters: "/C taskkill /F /IM {#MyAppExeName}"; Flags: runhidden waituntilterminated; RunOnceId: "DetenerAgente"

[Code]
function SafeNetInstalado: Boolean;
begin
  if IsWin64 then
    Result := FileExists(ExpandConstant('{syswow64}\eTPKCS11.dll'))
  else
    Result := FileExists(ExpandConstant('{sys}\eTPKCS11.dll'));
end;
