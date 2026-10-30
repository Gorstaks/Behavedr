# Behavedr Red/Blue Team Audit Report

**Date:** July 21, 2026  
**Scope:** Full codebase review - Behavedr.Agent, Behavedr.Core, Behavedr.Mobile  
**Methodology:** Static analysis, architecture review, wiring verification, naming analysis, dead code detection  

---

## Executive Summary

Behavedr is a well-architected behavioral EDR agent with strong security fundamentals (DPAPI key protection, mTLS, cert pinning, config integrity sealing, signature-verified updates). However, the audit reveals **critical wiring gaps** where sophisticated detection and response components exist in code but are never connected to the runtime. An attacker studying this codebase would identify these gaps as reliable blind spots.

**Critical:** 3 | **High:** 6 | **Medium:** 8 | **Low/Info:** 5

---

## CRITICAL Findings

### C-1: Response Engine Never Wired - Agent Detects But Cannot Respond

**Type:** Wiring / Sabotage Vector  
**Location:** `src/Behavedr.Agent/Program.cs`  

The `ResponseEngine`, `ProcessKillAction`, `FileQuarantineAction`, `ChainTracer`, and `IsolationResponseEngine` are **never registered in DI or instantiated** in the agent's `Program.cs`. The `MonitoringService` runs detections and logs scores but **never invokes any response action**.

```csharp
// Program.cs registers these:
builder.Services.AddSingleton<DetectionEngine>();
builder.Services.AddHostedService<MonitoringService>();
// But NEVER registers:
// - ResponseEngine
// - ProcessKillAction
// - FileQuarantineAction
// - ChainTracer
// - IsolationResponseEngine
```

**Impact:** The agent will detect threats, log them, and do absolutely nothing. A red team operator can run malware at will - the EDR will observe but never kill processes, quarantine files, or trace attack chains.

**Recommendation:** Register `ResponseEngine` in DI, wire `ProcessKillAction` and `FileQuarantineAction` as response actions, and call `responseEngine.RespondAsync(result)` after each detection cycle in `MonitoringService.RunDetectionCycleAsync()`.

---

### C-2: ETW Session Never Created - BehavioralMonitor Runs Blind

**Type:** Wiring / Dead Code  
**Location:** `src/Behavedr.Core/Platform/PlatformMonitors.cs:32`  

`BehavioralMonitor` accepts an optional `EtwSession?` parameter but `PlatformMonitors.BuildMonitorList()` instantiates it with no arguments:

```csharp
monitors.Add(new BehavioralMonitor()); // etwSession: null
```

Since no `EtwSession` or `NativeEtwSession` is created and passed, the real-time ETW process event pipeline is **completely dead**. The monitor falls through to WMI scanning only (slower, 1-2s latency vs 50ms).

Similarly, `DnsQueryMonitor` and `ParentPidSpoofDetector` expect shared `NativeEtwSession` / `ProcessAncestryCache` instances but each creates their own or gets null.

**Impact:** Real-time process start detection (~50ms) is disabled. The behavioral monitor only catches processes that are still running during the periodic WMI scan (5s interval). Short-lived malware (run-and-exit in <5s) is invisible.

**Recommendation:** Create a shared `NativeEtwSession` instance in `PlatformMonitors.BuildMonitorList()` and pass it to `BehavioralMonitor`, `DnsQueryMonitor`, and any other ETW consumers. Create a shared `ProcessAncestryCache` and pass it to both `ParentPidSpoofDetector` and `ChainTracer`.

---

### C-3: Communication Layer Never Wired - Detections Never Leave the Box

**Type:** Wiring / Sabotage Vector  
**Location:** `src/Behavedr.Agent/Program.cs`  

`GrpcBehavedrClient`, `OfflineBuffer`, and `IBehavedrClient` are **never registered in DI**. Detection reports are never sent to any server. The heartbeat mechanism is dead. Policy updates are never fetched.

**Impact:** The agent operates in complete isolation. A SOC team monitoring a dashboard will receive zero alerts regardless of what the agent detects locally. The offline buffer (encrypted at-rest reporting) is never used.

**Recommendation:** Register `CommunicationConfig`, `GrpcBehavedrClient` (as `IBehavedrClient`), and `OfflineBuffer` in DI. Add a communication service that sends reports after each detection cycle, with offline buffering on failure.

---

## HIGH Findings

### H-1: Duplicate `GetKeyDirectory()` - Key Desync Risk

**Type:** Dead Code / Potential Sabotage  
**Location:** `ConfigProtection.cs:236` and `KeyProtection.cs:227`  

Both classes contain **identical** `GetKeyDirectory()` implementations. `ConfigProtection.GetOrCreateMachineKey()` manages its own key file, while `KeyProtection.GetMachineKey()` does the same. The comment in `ConfigIntegrity.cs` says "V-3 FIX: Delegates to KeyProtection.GetMachineKey()" but **ConfigProtection still has its own independent key path**.

**Risk:** If `ConfigProtection` creates a key and `KeyProtection` creates a different key (race, first-run ordering), the config integrity HMAC and the config encryption will use **different machine keys**. This could cause:
- Config files encrypted with one key but integrity-checked with another
- Silent integrity verification failures after key rotation

**Recommendation:** Remove `GetOrCreateMachineKey()` from `ConfigProtection` and delegate to `KeyProtection.GetMachineKey()` like `ConfigIntegrity` and `SecureEnvelope` already do.

---

### H-2: `SecureEnvelope.GetMachineKeyBytes()` - Dead Code

**Type:** Dead Code  
**Location:** `src/Behavedr.Core/Security/SecureEnvelope.cs:132`  

```csharp
private static byte[] GetMachineKeyBytes() => KeyProtection.GetMachineKey();
```

This method is defined but **never called**. The `DeriveKey()` method (which is the only key consumer) calls `KeyProtection.GetMachineKey()` directly. This dead method could mislead future developers into thinking there's an alternate key path.

**Recommendation:** Delete `GetMachineKeyBytes()`.

---

### H-3: `DetectionEngine.ProcessEvent()` Sync-Over-Async Deadlock Risk

**Type:** Security / Reliability  
**Location:** `src/Behavedr.Core/DetectionEngine.cs`  

```csharp
[Obsolete("Use ProcessEventAsync instead. Sync-over-async can cause deadlocks.")]
public DetectionResult ProcessEvent(DetectionEvent evt)
{
    return ProcessEventAsync(evt, CancellationToken.None).GetAwaiter().GetResult();
}
```

This method is marked obsolete but still exists. If called from a synchronization-context-bound environment (UI thread, ASP.NET classic), it will deadlock. Its presence invites misuse.

**Recommendation:** Remove or make `internal` for test-only use.

---

### H-4: `ProcessAncestryCache` Not Shared - PPID Spoof Detector Isolated

**Type:** Wiring  
**Location:** `PlatformMonitors.cs` / `ParentPidSpoofDetector.cs`  

`ParentPidSpoofDetector` creates its own `ProcessAncestryCache` when none is injected:
```csharp
_ancestryCache = ancestryCache ?? new ProcessAncestryCache();
```

Since `PlatformMonitors` passes no cache, the detector has an **empty ancestry cache** - it can only detect PPID spoofing for processes that start AFTER the detector is created and that it happens to capture via `NtQueryInformationProcess`. The ETW-populated ancestry (which would provide ground truth) is in a separate, unreachable cache.

`ChainTracer` also requires a `ProcessAncestryCache` but is never instantiated in the runtime at all (see C-1).

**Impact:** PPID spoof detection is severely degraded. The cache is effectively always empty because no ETW events feed into it.

---

### H-5: `MonitoringService` Creates Targeted Events That Go Nowhere

**Type:** Wiring / Dead Logic  
**Location:** `src/Behavedr.Agent/MonitoringService.cs:95-120`  

The `ExtractAttributedSignals` method parses PIDs from signals and creates "targeted" `DetectionResult` objects, but then **only logs them** - no response actions are taken, no reports are sent:

```csharp
var targetedResult = new DetectionResult(targetedEvt, result.Score, result.PresidentKill, signals);
_logger.LogInformation("Attributed detection: {Process} (PID {Pid})...");
// Result is never used after this
```

**Impact:** The agent identifies which specific process is malicious but does nothing with that attribution.

---

### H-6: Auto-Updater Never Instantiated

**Type:** Wiring / Dead Code  
**Location:** `src/Behavedr.Core/Update/AutoUpdater.cs`  

The `AutoUpdater` class with signature verification, Zip Slip protection, and SBOM-aware downloading is fully implemented but **never instantiated or registered in DI**. The agent will never self-update.

**Recommendation:** Register as a periodic background service or manual trigger.

---

## MEDIUM Findings

### M-1: File Name `NetworkMonitor.cs` Contains Class `NetworkConnectionMonitor`

**Type:** Naming Confusion  
**Location:** `src/Behavedr.Core/Monitors/NetworkMonitor.cs`  

The file is named `NetworkMonitor.cs` but the class inside is `NetworkConnectionMonitor`. This makes grep/find operations unreliable and could cause a developer to create a duplicate `NetworkMonitor` class thinking one doesn't exist.

**Recommendation:** Rename the file to `NetworkConnectionMonitor.cs`.

---

### M-2: `EtwSession` vs `NativeEtwSession` - Confusing Dual Implementation

**Type:** Naming Confusion / Architecture  
**Location:** `src/Behavedr.Core/Monitors/EtwSession.cs` and `NativeEtwSession.cs`  

Two ETW session classes exist:
- `EtwSession` - WMI-based fallback (slower, ~1-2s latency)
- `NativeEtwSession` - Native P/Invoke ETW (faster, ~50ms latency), which internally wraps `EtwSession` as its fallback

`BehavioralMonitor` takes `EtwSession?` (the fallback only), while `DnsQueryMonitor` takes `NativeEtwSession?` (the better one). This inconsistency means:
- `BehavioralMonitor` can never use native ETW even if someone wires it
- The two monitors can't share an ETW session

**Recommendation:** Standardize on `NativeEtwSession` (which already falls back internally). Update `BehavioralMonitor` to accept `NativeEtwSession` and expose `DrainProcessEvents()` through it.

---

### M-3: `ConfigProtection.EncryptWindows()` Uses `DataProtectionScope.LocalMachine`

**Type:** Security  
**Location:** `src/Behavedr.Core/Security/ConfigProtection.cs:58`  

Config values encrypted with DPAPI `LocalMachine` scope can be decrypted by **any process running on the same machine**, including malware running as any user. This is weaker than the `KeyProtection` approach (which adds per-install entropy).

**Recommendation:** Use `CurrentUser` scope (running as SYSTEM, this restricts to SYSTEM-context processes) or migrate to the `SecureEnvelope` approach with purpose-derived keys.

---

### M-4: `IsolationResponseEngine` Not Implementing `IResponseAction`

**Type:** Architecture / Wiring  
**Location:** `src/Behavedr.Core/Response/IsolationResponseEngine.cs`  

Unlike `ProcessKillAction` and `FileQuarantineAction` (which implement `IResponseAction`), `IsolationResponseEngine` is a standalone class with ad-hoc methods (`HandleIsoThreatAsync`, `HandleDockerThreatAsync`, `HandleVmThreatAsync`). It can't be registered in the `ResponseEngine` action pipeline.

**Recommendation:** Create an `IResponseAction` adapter or refactor to implement the interface.

---

### M-5: Unbounded `_alertedPids` / `_alertedKeys` Growth Before Pruning

**Type:** Resource Exhaustion  
**Location:** Multiple monitors (`ParentPidSpoofDetector`, `DllSideloadDetector`, `LsassDumpMonitor`)  

Several monitors use `HashSet<>` for deduplication with a `Count > N` hard-clear:
```csharp
if (_alertedPids.Count > 500) _alertedPids.Clear();
```

This means: after 500 unique alerts, ALL history is lost and alerts will re-fire for previously-seen items. An attacker could flood the monitor with 500 low-priority alerts to reset the dedup state, then re-trigger the actual detection.

**Recommendation:** Use an LRU/time-bounded eviction strategy instead of hard-clear.

---

### M-6: Build Pipeline `contents: write` Permission on PRs

**Type:** Supply Chain  
**Location:** `.github/workflows/build.yml:6`  

```yaml
permissions:
  contents: write
```

The build workflow has write permissions even on pull requests (`on: pull_request`). A malicious PR could potentially abuse the auto-tag job (though it's guarded by `if: github.ref == 'refs/heads/main'`). The write permission is overly broad for the CI job.

**Recommendation:** Scope `contents: write` only to the `auto-tag` job, not the entire workflow.

---

### M-7: `SelfProtectionService` and `AntiTamperGuard` - Duplicate Binary Integrity Checks

**Type:** Duplicate Code  
**Location:** Both `SelfProtectionService.cs` and `AntiTamperGuard.cs`  

Both perform SHA-256 binary integrity verification of the running executable on a periodic timer. Both compute a baseline hash at startup and compare on each check cycle. This is pure duplication:

| Feature | SelfProtectionService | AntiTamperGuard |
|---------|----------------------|-----------------|
| Binary hash check | Yes (30s) | Yes (10s) |
| Anti-debug | Yes | No |
| Process DACL | No (in AgentWatchdog) | No |
| Service re-registration | No | Yes |
| ETW session health | No | Yes |
| Function prologue check | No | Yes |

**Risk:** They may race to read the binary file simultaneously. The duplicate logic bloats the codebase and makes it unclear which is authoritative.

**Recommendation:** Consolidate binary integrity into `AntiTamperGuard` (which already has the richer implementation) and remove it from `SelfProtectionService`.

---

### M-8: `ConfigIntegrity.ValidateConfigBeforeSealing` Only Checks Select Fields

**Type:** Security Gap  
**Location:** `src/Behavedr.Core/Security/ConfigIntegrity.cs:27-75`  

The validation only checks `Scoring.PresidentKillThreshold`, `Scoring.UserTargetedMultiplier`, `Scoring.HighScoreAlertThreshold`, and `Agent.MonitoringIntervalSeconds`. An attacker could pre-place a config with:
- `Agent.EnableSelfProtection: false` (disables protection in debug builds)
- `Communication.ServerUrl` pointing to attacker C2
- Arbitrary new keys that downstream code might read

**Recommendation:** Validate all known config keys. Reject unknown keys. Validate `Communication` section bounds.

---

## LOW / Informational Findings

### L-1: `DetectionEvent.Score` Field - Always 0.0, Never Used

**Type:** Dead Code  
**Location:** `src/Behavedr.Core/Models/DetectionEvent.cs`  

The `Score` property is always initialized to `0.0` in `DetectionEvent.Create()` and is never read or set to any other value. Scoring is done externally by `ScoringEngine`. This field is misleading.

---

### L-2: `AgentBootstrap.CreateEngine()` - Partially Redundant with `MonitoringService`

**Type:** Dead Code  
**Location:** `src/Behavedr.Core/AgentBootstrap.cs`  

`AgentBootstrap.CreateEngine()` creates a `DetectionEngine` and registers monitors. But `MonitoringService.ExecuteAsync()` also registers monitors if `_engine.RegisteredMonitors.Count == 0`. The `AgentBootstrap` path is used by the Mobile project; the agent uses DI. These two paths could diverge silently.

---

### L-3: Hardcoded Fallback Entropy Weakens DPAPI Binding

**Type:** Security (Documented)  
**Location:** `src/Behavedr.Core/Security/KeyProtection.cs:165`  

```csharp
return "Behavedr-MachineKey-v2-2026-fallback"u8.ToArray();
```

If the entropy file cannot be created, all installations fall back to the same static string. This is documented with a `Trace.TraceError` but no alert is raised through the detection pipeline.

---

### L-4: No Test Project in Workspace

**Type:** Verification Gap  

The `build.yml` and `release.yml` reference `tests/Behavedr.Tests/Behavedr.Tests.csproj` but this directory is not present in the workspace. Tests exist but cannot be verified locally.

---

### L-5: `PolicyUpdate.VerifySignature()` Falls Through in Dev Mode

**Type:** Security (Acceptable)  
**Location:** `src/Behavedr.Core/Communication/IBehavedrClient.cs`  

```csharp
if (!Security.UpdateSignatureVerifier.IsProductionKeyConfigured())
    return true; // Dev mode - accept all policies
```

If the production key is not baked in, all policy updates are accepted without verification. This is acceptable for development but dangerous if a release build accidentally ships without the key.

---

## Red Team Attack Paths (Exploiting Found Weaknesses)

1. **Silent Operation:** Given C-1/C-3, an attacker can run freely. The agent detects but never responds or reports. No SOC visibility.

2. **Short-lived Malware:** Given C-2, run payload for <5s. No ETW means the WMI scan (5s interval) will miss it entirely.

3. **Alert Flooding -> Dedup Reset:** Trigger 500+ unique low-priority signals (M-5), then execute the real attack. Previous alert state is cleared.

4. **Config Pre-poisoning:** On a fresh install, place a modified `appsettings.json` with `EnableSelfProtection: false` (DEBUG builds) or an attacker-controlled server URL. The validation (M-8) won't catch unvalidated keys.

5. **Key Desync:** Race the first-run key generation (H-1) to create a key via `ConfigProtection` path before `KeyProtection` runs, causing crypto operations to silently use different keys.

---

## Blue Team Recommendations (Priority Order)

1. **Wire the Response Engine** (C-1) - Without this, the agent is a logger, not an EDR.
2. **Wire Communication** (C-3) - Without this, detections never reach a SOC.
3. **Create and share ETW session** (C-2) - Without this, real-time detection is severely degraded.
4. **Consolidate key management** (H-1) - Remove `ConfigProtection.GetOrCreateMachineKey()`.
5. **Share `ProcessAncestryCache`** (H-4) - Single instance across all consumers.
6. **Remove dead code** (H-2, H-3, L-1) - Reduces attack surface and confusion.
7. **Rename `NetworkMonitor.cs`** (M-1) - Prevent future naming collisions.
8. **Standardize ETW interface** (M-2) - All monitors should use `NativeEtwSession`.
9. **Scope CI permissions** (M-6) - Least privilege for build workflows.
10. **Implement LRU deduplication** (M-5) - Prevent dedup reset attacks.

---

## Summary Table

| ID | Severity | Category | Summary |
|----|----------|----------|---------|
| C-1 | Critical | Wiring | Response engine never registered - agent cannot act |
| C-2 | Critical | Wiring | ETW session never created - behavioral monitor runs blind |
| C-3 | Critical | Wiring | Communication layer never wired - no SOC visibility |
| H-1 | High | Duplicate | Dual `GetKeyDirectory()` / key management implementations |
| H-2 | High | Dead Code | `SecureEnvelope.GetMachineKeyBytes()` never called |
| H-3 | High | Reliability | Sync-over-async `ProcessEvent()` deadlock risk |
| H-4 | High | Wiring | `ProcessAncestryCache` not shared between components |
| H-5 | High | Dead Logic | Attributed signals computed but never acted upon |
| H-6 | High | Dead Code | `AutoUpdater` never instantiated |
| M-1 | Medium | Naming | File/class name mismatch (`NetworkMonitor.cs` vs `NetworkConnectionMonitor`) |
| M-2 | Medium | Naming | `EtwSession` vs `NativeEtwSession` inconsistent usage |
| M-3 | Medium | Security | DPAPI LocalMachine scope too broad |
| M-4 | Medium | Architecture | `IsolationResponseEngine` doesn't implement `IResponseAction` |
| M-5 | Medium | Security | Hard-clear dedup enables alert flooding attacks |
| M-6 | Medium | Supply Chain | Overly broad `contents: write` on PR builds |
| M-7 | Medium | Duplicate | Binary integrity check duplicated across two services |
| M-8 | Medium | Security | Config pre-seal validation incomplete |
| L-1 | Low | Dead Code | `DetectionEvent.Score` always 0, never used |
| L-2 | Low | Dead Code | `AgentBootstrap` partially redundant with `MonitoringService` |
| L-3 | Low | Security | Hardcoded fallback entropy (documented) |
| L-4 | Low | Verification | Test project not in workspace |
| L-5 | Low | Security | Policy verification bypassed in dev mode |
