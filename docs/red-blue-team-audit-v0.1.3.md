# Behavedr EDR - Red/Blue Team Security Audit v0.1.3

**Date:** 2026-07-21
**Version Audited:** 0.1.3
**Previous Audit:** v0.1.2
**Auditor:** AI-assisted security analysis (Kiro)
**Scope:** Full source code review, architecture analysis, evasion modeling, Sentinel EDR cross-reference
**Sentinel Reference Version:** 1.5.5 (Windows-only EDR with mature install/uninstall patterns)

---

## Executive Summary

Behavedr v0.1.3 resolves **all critical, high, and medium findings** from the v0.1.2 audit.
The response engine, communication layer, and auto-updater are now fully wired into the
runtime. The codebase is clean, well-documented, and demonstrates strong security fundamentals.

**However**, cross-referencing with Sentinel EDR reveals significant **operational gaps** in
the Windows installation, upgrade, and self-protection lifecycle that would cause real-world
deployment failures. These are not code bugs - they are missing infrastructure patterns that
a production Windows EDR requires.

**New findings in this audit:**
- 0 Critical (all resolved from prior audit)
- 2 High (installer resilience, missing build automation)
- 4 Medium (Safe Mode gap, test project absent, architecture limitation, version stamping)
- 3 Low (minor operational improvements)
- 7 Sentinel-learned recommendations (new patterns to adopt)

**Residual risk profile: LOW-MEDIUM.** Code quality and security are excellent.
Operational deployment readiness on Windows needs the Sentinel-derived patterns.


---

## RESOLVED FINDINGS FROM v0.1.2 AUDIT

All prior findings have been verified as resolved in v0.1.3:

| Finding | Resolution | Verification |
|---------|-----------|--------------|
| C-1: Response Engine never wired | **RESOLVED** | Program.cs registers ResponseEngine, ProcessKillAction, FileQuarantineAction, IsolationResponseEngine; MonitoringService calls RespondAsync |
| C-2: ETW Session never created | **RESOLVED** | PlatformMonitors.BuildMonitorList() creates shared NativeEtwSession and injects into BehavioralMonitor + DnsQueryMonitor |
| C-3: Communication never wired | **RESOLVED** | GrpcBehavedrClient, OfflineBuffer, CommunicationService all registered in DI; MonitoringService sends reports |
| H-1: Duplicate GetKeyDirectory | **RESOLVED** | ConfigProtection delegates to KeyProtection.GetMachineKey(); no own GetKeyDirectory() |
| H-2: Dead GetMachineKeyBytes | **RESOLVED** | Removed; SecureEnvelope.DeriveKey calls KeyProtection directly |
| H-3: Sync-over-async deadlock | **RESOLVED** | No GetAwaiter().GetResult() calls remain in codebase |
| H-4: ProcessAncestryCache not shared | **RESOLVED** | PlatformMonitors creates shared cache, passes to ParentPidSpoofDetector and ChainTracer |
| H-5: Targeted events go nowhere | **RESOLVED** | MonitoringService executes response actions on attributed detections |
| H-6: AutoUpdater never instantiated | **RESOLVED** | Registered in DI, UpdateCheckService runs it on a 6-hour interval |
| M-2: EtwSession vs NativeEtwSession | **RESOLVED** | BehavioralMonitor now accepts NativeEtwSession via PlatformMonitors |
| M-4: IsolationResponseEngine not IResponseAction | **RESOLVED** | Now implements IResponseAction interface |
| M-6: contents:write on PRs | **RESOLVED** | build.yml uses `permissions: contents: read`; write scoped only to auto-tag job |
| M-7: Duplicate binary integrity | **RESOLVED** | SelfProtectionService no longer does binary hash; delegates to AntiTamperGuard |
| M-8: Config validation incomplete | **RESOLVED** | ValidateConfigBeforeSealing now checks Communication, Response, and Agent sections |


---

## PART 1: RED TEAM ANALYSIS (Attack Surface)

### RT-1: Installer Cannot Upgrade Over Running Agent [HIGH]

**Type:** Operational / Deployment Failure
**Location:** `packaging/windows/behavedr.iss`
**MITRE:** N/A (operational, not attack technique)

**Current behavior:** The Inno Setup installer uses a simple `[UninstallRun]` section:
```
sc.exe stop Behavedr
sc.exe delete Behavedr
```

**Problems identified:**
1. **No failure recovery disable before stop** - The service has `actions=restart/5000/restart/10000/restart/30000` configured. When `sc stop` executes, the SCM failure recovery immediately restarts the service within 5 seconds, making the stop ineffective.
2. **No polling for STOPPED state** - The installer proceeds to file overwrite while the service may still be running, causing "file in use" errors.
3. **No ACL reset** - Behavedr's `AgentWatchdog.TrySetProcessProtection()` sets a DACL that denies PROCESS_TERMINATE. The installer's `sc stop` may fail silently due to this DACL, and subsequent file replacement fails because the running process holds locks.
4. **No rename-as-fallback** - If files are locked, the installer has no recovery path.
5. **No .old file cleanup** - If manual workarounds leave `.old` files, they accumulate.

**Impact:** Upgrades will reliably fail on machines where Behavedr is actively running with self-protection enabled. The administrator must manually stop the service (potentially requiring PsExec as SYSTEM to bypass the DACL) before upgrading.

**Sentinel reference:** Sentinel solves this with a Pascal Script `PrepareToInstall` function that:
1. Disables failure recovery: `sc failure "Sentinel" reset= 86400 actions= ""`
2. Stops the service: `sc stop "Sentinel"`
3. Polls for STOPPED state (20 attempts x 500ms = 10s timeout)
4. Force-kills remaining processes
5. Resets ACLs with `takeown /F /R /A /D Y` + `icacls /grant Administrators:F /T`
6. Renames locked files as `.old` fallback
7. Post-install: `cmd /c del /f /q "{app}\*.old"` cleans up

---

### RT-2: No Local Build Automation Script [HIGH]

**Type:** Supply Chain / Developer Experience
**Location:** Project root (missing `build.ps1`)

**Current state:** Behavedr relies exclusively on GitHub Actions for building releases.
There is no local build script that can produce a complete installer from source.
The CI workflow (`release.yml`) embeds complex logic for:
- Inno Setup discovery and installation (via `choco install innosetup`)
- Asset copying (README.txt, Assets/, appsettings.json)
- Version stamping via git tag parsing

**Problems:**
1. **No offline build capability** - Developers or security teams cannot reproduce a release build without GitHub Actions infrastructure.
2. **No version stamping from a single source** - Version lives in `Directory.Build.props` but the installer ISS script has a hardcoded `#define MyAppVersion "0.0.4"` that must be overridden via CLI `/D` flag.
3. **No clean build guarantee** - No automated clean of `bin/obj` before publish.
4. **Supply chain risk** - The `choco install innosetup` step in CI downloads and installs software during the build. If Chocolatey is compromised, the installer compiler itself could be trojanized.

**Sentinel reference:** Sentinel's `installer/build.ps1` provides:
1. Single version source: reads `version.txt`, stamps all `.csproj` files and the ISS script
2. Clean build: removes all `bin/obj` directories and publish folder
3. Self-contained publish for each component
4. Inno Setup discovery in standard locations (no package manager needed)
5. Release packaging: copies installer to `releases/{version}/` for upload
6. Fully offline-capable after initial .NET SDK install

---

### RT-3: No Safe Mode Persistence [MEDIUM]

**Type:** Evasion / Persistence Gap
**Location:** `packaging/windows/behavedr.iss`
**MITRE:** T1562.009 (Safe Mode Boot)

**Issue:** Behavedr does not register itself for Safe Mode operation. An attacker who
reboots the machine into Safe Mode can operate with zero EDR coverage because only
services registered in `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\{Minimal,Network}`
are started in Safe Mode.

**Attack scenario:**
1. Attacker gains admin access
2. Sets next boot to Safe Mode: `bcdedit /set {current} safeboot minimal`
3. Reboots machine (or waits for reboot)
4. Operates freely in Safe Mode - Behavedr not running
5. Installs rootkit/persistence, then disables Safe Mode boot and reboots back to normal

**Sentinel reference:** Sentinel registers for both Minimal and Network Safe Mode:
```
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\Sentinel"; ValueType: string; ValueName: ""; ValueData: "Service"
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Sentinel"; ValueType: string; ValueName: ""; ValueData: "Service"
```

**Recommendation:** Add `[Registry]` entries to `behavedr.iss` for Safe Mode registration,
and add a `SafeBootRegistryMonitor` to AntiTamperGuard that detects if these keys are deleted.

---

### RT-4: Single-Process Architecture Limits Resilience [MEDIUM]

**Type:** Architecture / Self-Protection
**Location:** Entire agent design

**Issue:** Behavedr runs as a single Windows Service process. The `AgentWatchdog` runs
as a hosted service *within the same process*. If the process is killed (via SYSTEM
privilege, kernel driver, or exploitation), ALL protection ceases simultaneously -
detection, response, communication, and watchdog are all gone.

**Sentinel reference:** Sentinel uses a dual-process architecture:
- `Sentinel.Service` - SYSTEM-level service (detection, response, ETW)
- `Sentinel.Agent` - User-session process (tray icon, user-context monitoring)

Each watches the other. Killing the Service leaves the Agent to alert; killing the
Agent triggers the Service to restart it via the registry Run key.

**Impact:** Not a vulnerability per se, but a resilience limitation. A sophisticated
attacker who achieves SYSTEM can terminate Behavedr completely in one operation.

**Mitigation already in place:** Process DACL protection, binary integrity monitoring,
service re-registration, and SCM failure recovery (3-stage restart). These provide
defense-in-depth against most kill attempts.

**Recommendation for future:** Consider a lightweight out-of-process watchdog
(e.g., a second Windows Service or a PPL-protected stub) that monitors the main
agent heartbeat and triggers restart/alert if it stops.

---

### RT-5: Test Project Not Present in Workspace [MEDIUM]

**Type:** Verification Gap / Supply Chain
**Location:** `tests/` directory (referenced in CI, not in workspace)

**Issue:** The `build.yml` CI workflow references `tests/Behavedr.Tests/Behavedr.Tests.csproj`
but this directory is not present in the current workspace. The tests may exist in a
different branch, be git-ignored, or have been deleted.

**Impact:** Without a test project:
- Security-critical logic (scoring thresholds, kill decisions, crypto operations) has
  no automated regression testing.
- Refactoring introduces undetected breakage risk.
- Contributors cannot validate their changes locally.

**Recommendation:** Ensure the test project is committed to `main` and covers at minimum:
- `ProcessKillAction` protected-process logic (path verification, DACL evasion)
- `ScoringEngine` threshold calculations
- `ConfigIntegrity` seal/verify/tamper detection
- `SecureEnvelope` encrypt/decrypt round-trip
- `UpdateSignatureVerifier` signature validation (with test vectors)
- `BehavioralCorrelationEngine` composite rule evaluation
- `SecurityValidation` path traversal prevention

---

### RT-6: Version Stamping Gap Between Source and Installer [MEDIUM]

**Type:** Supply Chain / Build Integrity
**Location:** `Directory.Build.props` vs `packaging/windows/behavedr.iss`

**Issue:** The canonical version lives in `Directory.Build.props` (`0.1.3`) but the
Inno Setup script hardcodes `#define MyAppVersion "0.0.4"`. The CI passes the correct
version via `/DMyAppVersion=...` CLI flag, but this creates two risks:
1. A developer building locally without the flag produces an installer stamped "0.0.4"
2. Version mismatch between the binary (`0.1.3.0` from MSBuild) and installer metadata

**Sentinel reference:** Sentinel uses a single `version.txt` at the project root.
The `build.ps1` reads it and stamps BOTH `.csproj` files AND the `.iss` script before
building. This guarantees version consistency regardless of build environment.

**Recommendation:** Either:
- Add a `build.ps1` that reads `Directory.Build.props` and patches `behavedr.iss` before build, OR
- Remove the `#define MyAppVersion` from the ISS file and REQUIRE the `/D` flag (with a clear error if missing)

---

### RT-7: Auto-Updater Applies Updates In-Place Without Rollback [LOW]

**Type:** Availability / Self-DoS
**Location:** `src/Behavedr.Core/Update/AutoUpdater.cs`

**Issue:** `ApplyUpdateAsync` extracts the update zip directly over the running binary
directory. If the update is corrupted (passes signature but has runtime bugs), the
agent will fail to start after restart with no rollback mechanism.

**Sentinel reference:** Sentinel doesn't have auto-update (manual installer upgrades only),
but its rename-as-fallback pattern (`.exe.old`) provides implicit rollback - the old
binary remains on disk and could be restored.

**Recommendation:** Before extraction, rename the current binary to `.bak`. If the new
binary fails health check within 60s of restart, the SCM failure recovery should
restore the `.bak` version. Or: extract to a staging directory, validate the new binary
can start (e.g., `Behavedr.exe --health-check`), then swap atomically.

---

### RT-8: Offline Buffer Has No Size Limit Enforcement on Disk [LOW]

**Type:** Resource Exhaustion
**Location:** `src/Behavedr.Core/Communication/OfflineBuffer.cs`

**Issue:** While `_maxBufferedReports` (1000) limits the count, each encrypted report
could be arbitrarily large. A sustained high-detection-rate scenario with server
unreachable could fill disk. The buffer uses `Directory.GetFiles()` for counting, which
is O(n) and increasingly expensive as buffer grows.

**Recommendation:** Add a total byte cap (e.g., 100MB) in addition to count. Use a
simple running total rather than re-enumerating the directory.

---

### RT-9: Certificate Password in appsettings.json [LOW]

**Type:** Credential Exposure
**Location:** `src/Behavedr.Agent/appsettings.json` field `ClientCertPassword`

**Issue:** The client certificate password is stored in plaintext in `appsettings.json`.
While ConfigIntegrity seals the file and ConfigProtection can encrypt values, the
default template shows an empty string - a deployment that sets a real password here
exposes it on disk until manually encrypted.

**Recommendation:** Document in README that sensitive values should be encrypted using
`ConfigProtection.Encrypt()` and stored with `ENC:` prefix. Consider auto-encrypting
plaintext sensitive fields on first seal.

---

---

## PART 2: BLUE TEAM ANALYSIS (Defensive Posture)

### Current Defensive Strengths (v0.1.3)

Behavedr v0.1.3 demonstrates excellent defensive engineering:

| Capability | Implementation | Confidence |
|-----------|---------------|------------|
| Process monitoring | Native ETW (50ms latency) + WMI fallback | High |
| Behavioral correlation | 120s sliding window, 6 composite rules | High |
| Self-protection (anti-debug) | FailFast in Release builds | High |
| Self-protection (DACL) | Deny PROCESS_TERMINATE to Everyone | High |
| Self-protection (anti-tamper) | QPC suspension, binary integrity, ETW health, AMSI/ETW prologue | High |
| Cryptography | DPAPI + HKDF + AES-256-GCM + RSA-4096 PSS | Excellent |
| Communication security | mTLS with cert pinning, fail-closed TLS | Excellent |
| Supply chain | Deterministic builds, lock files, SBOM generation, signed updates | Good |
| Config integrity | HMAC-SHA256 seal with pre-seal validation | High |
| Response | Process kill (path-verified), file quarantine (path-traversal safe) | High |
| Offline resilience | Encrypted buffer with replay, dead-letter handling | High |
| Replay prevention | Boot nonce + monotonic sequence + unique nonce per report | Excellent |

### Detection Coverage (29 Monitors)

| Category | Monitors | Coverage Assessment |
|----------|----------|-------------------|
| Process behavior | BehavioralMonitor, EphemeralProcessMonitor, GhostProcessMonitor | Strong |
| Credential theft | LsassDumpMonitor, CredentialGuardMonitor, CredentialCanaryMonitor | Strong |
| Network | NetworkConnectionMonitor, BeaconingDetector, DataExfiltrationMonitor, ConnectivityCanary | Strong |
| Injection/hollowing | MemoryAnalyzer, ThreadStartAddressScanner | Strong |
| Evasion | ParentPidSpoofDetector, DllSideloadDetector, TokenIntegrityMonitor | Strong |
| Persistence | RegistryPersistenceMonitor, ScheduledTaskMonitor | Good |
| Lateral movement | NetworkShareMonitor, WslMonitor | Good |
| Anti-tamper | AntiTamperGuard (QPC, binary, ETW, AMSI/ntdll, service reg) | Excellent |
| DNS | DnsQueryMonitor (DGA, tunneling, suspicious TLDs) | Good |
| Raw disk | RawDiskAccessMonitor (NtQuerySystemInformation handle enumeration) | Good |

### Gaps Identified (Blue Team Perspective)

**BT-1: No Detection of Safe Mode Boot Manipulation**
An attacker setting `bcdedit /set {current} safeboot minimal` goes undetected.
The registry keys under `BCD00000000` could be monitored, or the `RegistryPersistenceMonitor`
extended to watch for SafeBoot changes.

**BT-2: No WFP (Windows Filtering Platform) Integration**
Network monitoring relies on periodic connection enumeration (`GetExtendedTcpTable`)
rather than real-time WFP callouts. This means very short-lived connections (connect ->
exfil -> close in <5s) between monitoring cycles are invisible.
Sentinel uses a `WfpIntegrityMonitor` and `AppNetworkPolicyMonitor` for tighter network control.

**BT-3: No Firewall Rule Manipulation Detection**
An attacker could add a firewall rule allowing C2 traffic, and Behavedr has no monitor
for `netsh advfirewall` changes or WFP filter modifications.

**BT-4: No Driver Load Monitoring**
Kernel driver loading (a common rootkit installation step) is not monitored.
Sentinel has a `DriverLoadMonitor` that watches for unsigned driver installations.

---

---

## PART 3: SENTINEL CROSS-REFERENCE - PATTERNS TO ADOPT

### S-1: Build Automation Script (Priority: HIGH)

Create `installer/build.ps1` that:

```powershell
# Reads version from Directory.Build.props
# Cleans bin/obj/publish
# Publishes self-contained single-file for win-x64
# Stamps behavedr.iss with correct version
# Locates ISCC.exe in standard paths
# Compiles installer
# Copies to releases/ folder
```

**Why:** Enables offline reproducible builds, eliminates CI-only build dependency,
ensures version consistency, removes Chocolatey supply chain risk from CI.

---

### S-2: Installer Upgrade Resilience (Priority: HIGH)

Add Pascal Script `PrepareToInstall` function to `behavedr.iss`:

```pascal
procedure PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  // 1. Disable failure recovery (prevents auto-restart during upgrade)
  // 2. sc stop Behavedr
  // 3. Poll for STOPPED state (20 x 500ms)
  // 4. Force-kill remaining Behavedr processes
  // 5. Reset ACLs (takeown + icacls) to recover from DACL protection
  // 6. Rename locked files as .old fallback
end;
```

Add to `[Run]` section:
```
Filename: "{sys}\cmd.exe"; Parameters: "/c del /f /q ""{app}\*.old"""; Flags: runhidden
```

**Why:** Behavedr's own self-protection (DACL on process, SCM failure recovery) makes
it impossible to upgrade without this logic. The installer will fail on every machine
where the agent is running - which is every machine it's supposed to protect.

---

### S-3: Safe Mode Registration (Priority: MEDIUM)

Add to `behavedr.iss` `[Registry]` section:

```ini
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\Behavedr"; ValueType: string; ValueName: ""; ValueData: "Service"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Behavedr"; ValueType: string; ValueName: ""; ValueData: "Service"; Flags: uninsdeletekey
```

**Why:** Without this, Safe Mode is an attacker escape hatch. Many ransomware families
(REvil, Snatch) reboot into Safe Mode to encrypt files without EDR interference.

---

### S-4: Version Single Source of Truth (Priority: MEDIUM)

Option A (Sentinel pattern): Create `version.txt` at project root, have `build.ps1`
stamp `Directory.Build.props` and `behavedr.iss` from it.

Option B (Keep current): Change `behavedr.iss` to NOT define a default version and
error if `/DMyAppVersion` is not passed. Add a `build.ps1` that extracts version from
`Directory.Build.props` and passes it to ISCC.

**Why:** Prevents version mismatch between binary and installer metadata.

---

### S-5: Installer Uninstall Cleanup (Priority: LOW)

Enhance `[UninstallRun]` to properly handle the service lifecycle:

```ini
[UninstallRun]
; Disable failure recovery first
Filename: "sc.exe"; Parameters: "failure Behavedr reset= 86400 actions= """""; Flags: runhidden waituntilterminated
; Stop the service
Filename: "sc.exe"; Parameters: "stop Behavedr"; Flags: runhidden waituntilterminated
; Wait for stop (poll via PowerShell)
Filename: "powershell.exe"; Parameters: "-NoProfile -Command ""for($i=0;$i -lt 20;$i++){if((sc.exe queryex Behavedr 2>&1) -match 'STOPPED'){break};Start-Sleep -ms 500}"""; Flags: runhidden waituntilterminated
; Delete the service
Filename: "sc.exe"; Parameters: "delete Behavedr"; Flags: runhidden waituntilterminated
```

Add Pascal Script `CurUninstallStepChanged` for thorough cleanup:
- Remove registry Run key (if added for user-session agent in future)
- Clean up any scheduled tasks
- Remove firewall rules
- Preserve logs (like Sentinel preserves ProgramData logs)

---

### S-6: Directory ACL Hardening in Installer (Priority: LOW)

Current `behavedr.iss` already sets `[Dirs]` permissions correctly:
```ini
Name: "{app}"; Permissions: admins-full system-full users-readexec
```

But consider adding explicit removal of inherited permissions (like Sentinel does with
`icacls /remove:d Users /T` and `/remove:d Everyone /T`) for defense against
permissive parent directory inheritance.

---

### S-7: Agent-in-User-Session (Future Consideration)

Sentinel's dual-process architecture (`Service` + `Agent`) provides:
- User-session monitoring (clipboard, browser, shell history)
- Mutual watchdog (each monitors the other)
- Tray icon for user visibility

For Behavedr's future user-context monitoring needs (if any), consider:
- Registry Run key for auto-start: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `postinstall runasoriginaluser` flag in Inno Setup for first launch

---

---

## PART 4: SECURITY POSTURE SCORECARD (v0.1.3)

| Category | Score | Delta from v0.1.2 |
|----------|-------|-------------------|
| Cryptography | 10/10 | (unchanged) |
| Communication | 10/10 | (unchanged) |
| Supply Chain | 8/10 | -1 (no local build script, test project absent) |
| Self-Protection | 10/10 | (unchanged) |
| Detection Breadth | 9/10 | (unchanged) |
| Detection Depth | 9/10 | (unchanged) |
| Response Capability | 9/10 | +1 (fully wired, response actions execute) |
| Input Validation | 9/10 | (unchanged) |
| Platform Coverage | 5/10 | (unchanged - Linux/macOS still weak) |
| Architecture | 9/10 | (unchanged) |
| **Deployment/Install** | **5/10** | **NEW** (missing upgrade resilience, Safe Mode, build script) |

**Overall: 8.5/10** (considering deployment readiness as a factor)
**Code quality only: 9.3/10** (up from 8.8/10 due to wiring fixes)

---

## PART 5: RECOMMENDED BUILD.PS1 IMPLEMENTATION

Based on Sentinel's proven pattern, here is the recommended `installer/build.ps1` for Behavedr:

```powershell
# Behavedr Installer Build Script
# Usage: .\build.ps1
# Requires: .NET 10 SDK, Inno Setup 6+

$ErrorActionPreference = "Stop"

Write-Host "=== Behavedr Build ===" -ForegroundColor Cyan

# 1. Read version from Directory.Build.props (single source of truth)
$PropsFile = Join-Path $PSScriptRoot "..\Directory.Build.props"
$PropsXml = [xml](Get-Content $PropsFile)
$Version = $PropsXml.Project.PropertyGroup[0].Version
Write-Host "Version: $Version" -ForegroundColor Green

# 2. Clean previous artifacts
$SrcDir = Join-Path $PSScriptRoot "..\src"
$PublishDir = Join-Path $PSScriptRoot "..\publish"
Write-Host "Cleaning..." -ForegroundColor Yellow
Get-ChildItem -Path $SrcDir -Include bin,obj -Directory -Recurse | Remove-Item -Recurse -Force -EA SilentlyContinue
if (Test-Path $PublishDir) { Remove-Item $PublishDir -Recurse -Force }

# 3. Publish self-contained single-file
Write-Host "Publishing win-x64..." -ForegroundColor Yellow
$AgentProj = Join-Path $PSScriptRoot "..\src\Behavedr.Agent\Behavedr.Agent.csproj"
dotnet publish $AgentProj -c Release -r win-x64 --self-contained `
    -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true `
    -p:DebugType=none -p:DebugSymbols=false `
    -p:Version=$Version -o (Join-Path $PublishDir "agent-win-x64")
if ($LASTEXITCODE -ne 0) { throw "Publish failed" }

# 4. Copy assets
Copy-Item (Join-Path $PSScriptRoot "..\src\Behavedr.Agent\appsettings.json") (Join-Path $PublishDir "agent-win-x64\") -Force
$AssetsDir = Join-Path $PSScriptRoot "..\Assets"
if (Test-Path $AssetsDir) {
    New-Item -ItemType Directory -Force -Path (Join-Path $PublishDir "agent-win-x64\Assets") | Out-Null
    Copy-Item "$AssetsDir\*" (Join-Path $PublishDir "agent-win-x64\Assets\") -Recurse -Force
}

# 5. Locate Inno Setup
$IsccPaths = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
)
$Iscc = $IsccPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $Iscc) { throw "ISCC.exe not found. Install Inno Setup 6." }

# 6. Compile installer
$Publish = (Resolve-Path (Join-Path $PublishDir "agent-win-x64")).Path
$OutDir = Join-Path $PSScriptRoot "..\dist\windows"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
& $Iscc (Join-Path $PSScriptRoot "behavedr.iss") "/DMyAppVersion=$Version" "/DPublishDir=$Publish" "/DOutputDir=$OutDir"
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed" }

Write-Host "=== Build complete: dist\windows\Behavedr-Setup-$Version-win-x64.exe ===" -ForegroundColor Green
```

---

---

## PART 6: RECOMMENDED INSTALLER PASCAL SCRIPT

Add this to `packaging/windows/behavedr.iss` for upgrade resilience:

```pascal
[Code]
procedure StopBehavedrService();
var
  ResultCode: Integer;
  PsPath: String;
begin
  PsPath := ExpandConstant('{sysnative}\WindowsPowerShell\v1.0\powershell.exe');

  // Disable failure recovery to prevent auto-restart during upgrade
  Exec(ExpandConstant('{sysnative}\sc.exe'),
    'failure "Behavedr" reset= 86400 actions= ""',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // Stop the service
  Exec(ExpandConstant('{sysnative}\sc.exe'),
    'stop "Behavedr"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // Poll for STOPPED state (10s timeout)
  Exec(PsPath,
    '-ExecutionPolicy Bypass -Command "for($i=0;$i -lt 20;$i++){' +
    '$out = sc.exe queryex ''Behavedr'' 2>&1;' +
    'if($out -match ''STOPPED''){break};Start-Sleep -ms 500}"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // Force-kill any remaining processes
  Exec(PsPath,
    '-ExecutionPolicy Bypass -Command "Get-Process -Name ''Behavedr'' -EA SilentlyContinue | Stop-Process -Force"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(1000);
end;

procedure ResetInstallDirAcls(const DirPath: String);
var
  ResultCode: Integer;
begin
  if not DirExists(DirPath) then Exit;
  Exec(ExpandConstant('{sysnative}\takeown.exe'),
    '/F "' + DirPath + '" /R /A /D Y', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\icacls.exe'),
    '"' + DirPath + '" /grant Administrators:F /T /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sysnative}\icacls.exe'),
    '"' + DirPath + '" /grant SYSTEM:F /T /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\Behavedr') or
     DirExists(ExpandConstant('{app}')) then
  begin
    StopBehavedrService();
    ResetInstallDirAcls(ExpandConstant('{app}'));
    // Rename locked files as fallback
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
    StopBehavedrService();
    Exec(ExpandConstant('{sys}\sc.exe'), 'delete "Behavedr"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;
```

Also add to `[Run]` section (after service registration):
```ini
; Clean up .old files from upgrade fallback
Filename: "{sys}\cmd.exe"; Parameters: "/c del /f /q ""{app}\*.old"""; Flags: runhidden waituntilterminated
```

And add Safe Mode registration to `[Registry]`:
```ini
; Safe Mode persistence (prevents Safe Mode evasion)
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\Behavedr"; ValueType: string; ValueName: ""; ValueData: "Service"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Behavedr"; ValueType: string; ValueName: ""; ValueData: "Service"; Flags: uninsdeletekey
```

---

---

## PART 7: SUMMARY TABLE

| ID | Severity | Type | One-Line Description |
|----|----------|------|---------------------|
| RT-1 | HIGH | Installer | Cannot upgrade over running agent (DACL + SCM recovery blocks it) |
| RT-2 | HIGH | Supply Chain | No local build.ps1 - CI-only builds, Chocolatey dependency |
| RT-3 | MEDIUM | Evasion | No Safe Mode persistence - attacker can reboot to evade |
| RT-4 | MEDIUM | Architecture | Single-process - one kill terminates all protection |
| RT-5 | MEDIUM | Verification | Test project not in workspace - no local regression testing |
| RT-6 | MEDIUM | Build | Version mismatch risk between Directory.Build.props and ISS |
| RT-7 | LOW | Availability | Auto-updater has no rollback on corrupted update |
| RT-8 | LOW | Resource | Offline buffer has no disk space cap |
| RT-9 | LOW | Credential | Cert password stored plaintext in appsettings template |
| BT-1 | INFO | Detection | No Safe Mode boot manipulation detection |
| BT-2 | INFO | Detection | No WFP real-time network filtering |
| BT-3 | INFO | Detection | No firewall rule manipulation detection |
| BT-4 | INFO | Detection | No driver load monitoring |

---

## PART 8: PRIORITY IMPLEMENTATION ROADMAP

### P0 - Immediate (before next release)

1. **Create `installer/build.ps1`** - Based on template in Part 5. Enables offline builds.
2. **Add PrepareToInstall Pascal Script to `behavedr.iss`** - Based on template in Part 6. Fixes upgrade failures.
3. **Add Safe Mode registry entries to `behavedr.iss`** - Two lines. Closes the Safe Mode evasion gap.

### P1 - Short-term (v0.2.0)

4. **Add .old file cleanup to installer [Run] section** - One line.
5. **Commit test project to main branch** - Ensure CI tests run and developers can test locally.
6. **Fix version stamping** - Either build.ps1 stamps ISS, or ISS errors without `/D` flag.
7. **Add disk space cap to OfflineBuffer** - Simple running total.
8. **Document cert password encryption** - README guidance for ConfigProtection.

### P2 - Medium-term (v0.3.0)

9. **Add SafeBoot registry key monitoring** to AntiTamperGuard.
10. **Add driver load monitoring** (ETW provider: Microsoft-Windows-Kernel-File, event ID 15).
11. **Add firewall rule change detection** (WFP or netsh parsing).
12. **Add auto-update rollback mechanism** (rename current -> .bak before extraction).

### P3 - Long-term (v0.4.0+)

13. **Out-of-process watchdog** (separate service or PPL-protected stub).
14. **WFP callout driver** for real-time network filtering (kernel component).
15. **Linux eBPF integration** (already planned per SECURITY.md).

---

## APPENDIX A: Sentinel Patterns Summary

Key patterns learned from Sentinel `installer/build.ps1` and `setup.iss`:

| Pattern | Sentinel Implementation | Behavedr Status |
|---------|------------------------|-----------------|
| Single version source | `version.txt` -> stamps .csproj + .iss | Missing (Directory.Build.props only, ISS hardcoded) |
| Clean before build | `Remove-Item bin,obj -Recurse` | CI only, no local script |
| Self-contained publish | `-r win-x64 --self-contained -p:PublishSingleFile=true` | CI only, no local script |
| ISCC discovery | Searches standard paths (no choco) | CI uses choco install |
| Release packaging | Copies to `releases/{version}/` | CI uses artifacts only |
| Failure recovery disable before stop | `sc failure ... actions= ""` | Not implemented |
| Stop polling | PowerShell loop checking for STOPPED | Not implemented |
| Force-kill after stop | `Stop-Process -Force` with retry loop | Not implemented |
| ACL reset on upgrade | `takeown /R /A` + `icacls /grant Administrators:F` | Not implemented |
| Rename-as-fallback | `.exe` -> `.exe.old` | Not implemented |
| .old cleanup post-install | `cmd /c del /f /q "*.old"` | Not implemented |
| Safe Mode registration | `SafeBoot\Minimal` + `SafeBoot\Network` | Not implemented |
| Uninstall: proper stop | Disable recovery -> stop -> poll -> delete | Simple sc stop/delete only |
| Service description | `sc description` | Already implemented |
| Agent auto-start (user session) | Registry Run key + `runasoriginaluser` | N/A (single-process) |

---

*End of audit. Next review scheduled for v0.2.0 (with installer improvements implemented).*
