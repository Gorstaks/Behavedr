; Behavedr - Windows Installer (Inno Setup 6+)
; Copyright (c) 2026 CroatiaSecurity. All rights reserved.
;
; Build:
;   iscc packaging\windows\behavedr.iss /DMyAppVersion=0.2.1 /DPublishDir=...\publish\agent-win-x64
;   Or use: installer\build.ps1 (recommended - handles version stamping automatically)

#ifndef MyAppVersion
  #define MyAppVersion "0.4.4"
#endif
#ifndef PublishDir
  #define PublishDir "..\..\publish\agent-win-x64"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist\windows"
#endif

#define MyAppName "Behavedr"
#define MyAppPublisher "CroatiaSecurity"
#define MyAppURL "https://github.com/CroatiaSecurity/Behavedr"
#define MyAppExeName "Behavedr.exe"
#define MyServiceName "Behavedr"

[Setup]
AppId={{A7C4E8F1-2B3D-4E5F-9A0B-1C2D3E4F5A6B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir={#OutputDir}
OutputBaseFilename=Behavedr-Setup-{#MyAppVersion}-win-x64
SetupIconFile={#PublishDir}\Assets\Behavedr.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}
; Allow upgrading over existing installation
UsePreviousAppDir=yes
CloseApplications=no
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked
Name: "startmenu"; Description: "Create a &Start Menu shortcut"; GroupDescription: "Additional icons:"; Flags: checkedonce
Name: "installservice"; Description: "Install as Windows &Service (auto-start)"; GroupDescription: "Service:"; Flags: checkedonce

[Files]
Source: "{#PublishDir}\Behavedr.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PublishDir}\appsettings.json"; DestDir: "{app}"; Flags: ignoreversion onlyifdoesntexist skipifsourcedoesntexist
Source: "{#PublishDir}\Assets\*"; DestDir: "{app}\Assets"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
Source: "{#PublishDir}\README.txt"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Dirs]
Name: "{app}"; Permissions: admins-full system-full users-readexec
Name: "{app}\logs"; Permissions: admins-full system-full users-readexec
Name: "{app}\quarantine"; Permissions: admins-full system-full
Name: "{app}\buffer"; Permissions: admins-full system-full

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: startmenu
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"; Tasks: startmenu
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
; Safe Mode persistence - ensures the service starts in Safe Mode (prevents T1562.009 evasion)
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\{#MyServiceName}"; ValueType: string; ValueName: ""; ValueData: "Service"; Flags: uninsdeletekey; Tasks: installservice
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\SafeBoot\Network\{#MyServiceName}"; ValueType: string; ValueName: ""; ValueData: "Service"; Flags: uninsdeletekey; Tasks: installservice

[Run]
; Clean up .old files from previous upgrade fallback
Filename: "{sys}\cmd.exe"; Parameters: "/c del /f /q ""{app}\*.old"""; Flags: runhidden waituntilterminated
; Register and start the Windows Service
Filename: "{sys}\sc.exe"; Parameters: "create {#MyServiceName} binPath= ""{app}\{#MyAppExeName}"" start= auto DisplayName= ""{#MyAppName} Agent"""; Flags: runhidden waituntilterminated; Tasks: installservice
Filename: "{sys}\sc.exe"; Parameters: "description {#MyServiceName} ""Behavedr behavioral EDR agent"""; Flags: runhidden waituntilterminated; Tasks: installservice
Filename: "{sys}\sc.exe"; Parameters: "failure {#MyServiceName} reset= 86400 actions= restart/5000/restart/10000/restart/30000"; Flags: runhidden waituntilterminated; Tasks: installservice
Filename: "{sys}\sc.exe"; Parameters: "start {#MyServiceName}"; Flags: runhidden waituntilterminated; Tasks: installservice
; If not installing as service, offer to launch manually
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent; Tasks: not installservice

[UninstallRun]
; Handled by CurUninstallStepChanged Pascal Script (see [Code] section)

[UninstallDelete]
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\buffer"
Type: filesandordirs; Name: "{app}\quarantine"
Type: filesandordirs; Name: "{app}"

[Code]
// ============================================================================
// Pascal Script - Upgrade and Uninstall Resilience
//
// Problem: Behavedr's self-protection sets a DACL on its own process that denies
// PROCESS_TERMINATE to non-SYSTEM callers. The SCM failure recovery policy auto-
// restarts the service within 5 seconds of a stop. Together, these make it
// impossible to upgrade or uninstall without special handling.
//
// Solution: Disable failure recovery before stopping, poll for STOPPED state,
// force-kill remaining processes, reset ACLs on the install directory (to undo
// the hardened permissions), and rename locked files as a last resort.
// ============================================================================

procedure StopBehavedrService();
var
  ResultCode: Integer;
  PsPath: String;
  Cmd: String;
begin
  PsPath := ExpandConstant('{sysnative}\WindowsPowerShell\v1.0\powershell.exe');

  // 1. Disable failure recovery so sc stop does not trigger auto-restart
  Exec(ExpandConstant('{sysnative}\sc.exe'),
    'failure "Behavedr" reset= 86400 actions= ""',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // 2. Stop the service
  Exec(ExpandConstant('{sysnative}\sc.exe'),
    'stop "Behavedr"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // 3. Poll for STOPPED state (20 iterations x 500ms = 10s timeout)
  Cmd := '-ExecutionPolicy Bypass -NoProfile -Command "for ($i = 0; $i -lt 20; $i++) { $out = & sc.exe queryex ''Behavedr'' 2>&1; if ($out -match ''STOPPED'' -or $out -match ''1060'') { break }; Start-Sleep -Milliseconds 500 }"';
  Exec(PsPath, Cmd, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // 4. Force-kill any remaining Behavedr processes (retry loop)
  Cmd := '-ExecutionPolicy Bypass -NoProfile -Command "foreach ($i in 1..5) { $procs = Get-Process -Name ''Behavedr'' -ErrorAction SilentlyContinue; if (-not $procs) { break }; $procs | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 500 }"';
  Exec(PsPath, Cmd, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(1000);
end;

procedure ResetInstallDirAcls(const DirPath: String);
var
  ResultCode: Integer;
begin
  if not DirExists(DirPath) then
    Exit;

  // Take ownership as Administrators (bypasses restrictive DACLs)
  Exec(ExpandConstant('{sysnative}\takeown.exe'),
    '/F "' + DirPath + '" /R /A /D Y',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // Grant full control to Administrators and SYSTEM
  Exec(ExpandConstant('{sysnative}\icacls.exe'),
    '"' + DirPath + '" /grant Administrators:F /T /C /Q',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\icacls.exe'),
    '"' + DirPath + '" /grant SYSTEM:F /T /C /Q',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  NeedsRestart := False;

  // If an existing installation is present, stop and prepare for upgrade
  if RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\Behavedr') or
     DirExists(ExpandConstant('{app}')) then
  begin
    StopBehavedrService();
    ResetInstallDirAcls(ExpandConstant('{app}'));

    // Rename locked files as fallback (if still in use despite stop attempts)
    if FileExists(ExpandConstant('{app}\Behavedr.exe')) then
      RenameFile(ExpandConstant('{app}\Behavedr.exe'), ExpandConstant('{app}\Behavedr.exe.old'));
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    // Stop and remove the service
    StopBehavedrService();
    ResetInstallDirAcls(ExpandConstant('{app}'));

    // Delete the service registration
    Exec(ExpandConstant('{sysnative}\sc.exe'),
      'delete "Behavedr"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    // Remove Safe Mode registry keys
    RegDeleteKeyIncludingSubkeys(HKLM,
      'SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\Behavedr');
    RegDeleteKeyIncludingSubkeys(HKLM,
      'SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Behavedr');
  end;
end;
