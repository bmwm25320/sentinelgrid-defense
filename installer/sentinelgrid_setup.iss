; ====================================================================
; SentinelGrid Defense // Professional Inno Setup Script
; Kaspersky-Grade Windows Setup Wizard
; Target: backend/releases/SentinelGrid_Setup_v1.0.exe
; ====================================================================

#define MyAppName "SentinelGrid Defense"
#define MyAppVersion "1.0.4"
#define MyAppPublisher "SentinelGrid Systems"
#define MyAppURL "https://github.com/bmwm25320/sentinelgrid-defense"
#define MyAppExeName "SentinelGridDefense.exe"

[Setup]
AppId={{5D87F3B1-94E6-49A8-B1F7-4180A28E5C1D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} v{#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE.txt
OutputDir=..\backend\releases
OutputBaseFilename=SentinelGrid_Setup_v1.0
SetupIconFile=..\sentinelgrid.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
CloseApplications=yes
RestartApplications=no
UninstallDisplayIcon={app}\sentinelgrid.ico
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=SentinelGrid Defense Setup Wizard
VersionInfoProductName={#MyAppName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "autostart"; Description: "Start SentinelGrid Defense automatically on Windows startup"; GroupDescription: "System Integration:"

[Files]
Source: "..\dist\SentinelGridDefense\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\sentinelgrid.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\sentinelgrid.ico"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\sentinelgrid.ico"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "SentinelGridDefense"; ValueData: """{app}\{#MyAppExeName}"""; Flags: uninsdeletevalue; Tasks: autostart

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  // Terminate any running instances of SentinelGrid Defense before overwriting files
  Exec('taskkill.exe', '/F /IM SentinelGridDefense.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(500);
end;
