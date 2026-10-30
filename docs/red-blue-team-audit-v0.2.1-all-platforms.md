# Behavedr Red/Blue Team Security Audit v0.2.1 - All Platforms

**Date:** 2026-07-25  
**Version Audited:** 0.2.1 (source tree at audit time; remediations shipped in **0.2.2**)  
**Previous Audits:** v0.1.3, cross-platform, v0.1.6, v0.2.0  
**Auditor:** Independent red/blue reassessment against current source  
**Scope:** Windows, Linux, macOS, Android, iOS + supply chain, crypto, CI/CD, packaging  
**Goal:** Concrete path to 10/10 protection grades on all platforms  

**Evidence baseline:** 49 unit tests pass (`dotnet test` Release). ~17.8k LOC Core, ~3.8k Mobile, ~1.0k Agent, **~0.6k Tests**.

---

## Executive Summary

Behavedr v0.2.1 is a **mature userland EDR** with strong Windows/Linux foundations, a credible Android stack after the v0.2.0-0.2.1 remediations, and meaningful macOS progress (kqueue + Keychain). Prior audit fixes (config HMAC, mTLS fail-closed, RSA-PSS updates, Zip Slip defense, Linux cn_proc/fanotify, Android response/VPN/Keystore) largely land in the tree.

**You are not at 10/10 on any platform.** The ceiling is now set by:

1. **Supply chain / release trust** (unsigned installers, no lockfiles on disk, soft mobile CI)
2. **iOS** (still the weak platform by a wide margin)
3. **macOS real-time depth** (kqueue != EndpointSecurity)
4. **Test and attestation depth** (security-critical paths under-tested; Play Integrity via reflection)

### Platform Scores (Current -> Realistic 10/10 Target)

| Category | Windows | Linux | macOS | Android | iOS | 10/10 Means |
|----------|:-------:|:-----:|:-----:|:-------:|:---:|-------------|
| Self-Protection | 9.5 | 9.0 | 8.0 | 9.0 | 4.5 | Multi-layer, no single kill path, proven by tests |
| Detection Coverage | 9.5 | 9.0 | 8.0 | 9.0 | 5.5 | MITRE-mapped suite with low blind spots |
| Real-Time Events | 10 | 9.5 | 7.5 | 8.0 | 3.0 | Sub-second exec/file/net without poll gaps |
| Crypto & Key Mgmt | 9.5 | 9.0 | 8.5 | 9.0 | 3.5 | Hardware-backed keys, no filesystem secrets |
| Communication | 9.5 | 9.5 | 9.5 | 8.5 | 7.0 | mTLS + pin + signed policy only |
| Update Security | 8.5 | 8.5 | 8.5 | 9.0 | 4.0 | Signed packages + auto-rollback + anti-downgrade |
| Service Hardening | 9.5 | 9.0 | 8.0 | 9.0 | 3.5 | Least privilege + restart + anti-unload |
| Response Actions | 9.0 | 8.5 | 7.5 | 8.5 | 2.0 | Safe kill/isolate/quarantine with TOCTOU mitigations |
| Anti-Forensics Resistance | 9.0 | 8.5 | 7.5 | 7.5 | 3.0 | Hard to blind, suspend, or log-wipe |
| Supply Chain | **7.0** | **7.0** | **6.5** | **7.0** | **5.0** | Signed artifacts, lockfiles, SLSA, SBOM |
| **Overall** | **9.1** | **8.8** | **7.9** | **8.5** | **4.1** | **10** |

**Headline:** Windows ~= 9.1, Linux ~= 8.8, Android ~= 8.5, macOS ~= 7.9, **iOS ~= 4.1**.  
**Shared drag:** Supply chain is the fastest way to raise *every* platform score without new detectors.

Changelog's Android "9.1 overall" is optimistic relative to independent review (Play Integrity reflection risk, non-root response limits, soft CI). Use this document's scores for planning.

---

## What Is Already Strong (Blue Team Wins)

Keep these; they are the foundation of high grades:

| Control | Where | Notes |
|---------|-------|-------|
| Config HMAC seal + pre-seal bounds | `ConfigIntegrity`, `Program.cs` | Fail closed on tamper; first-run injection hard |
| mTLS fail-closed without CA | `GrpcBehavedrClient` | No CA path -> reject all server certs |
| AES-256-GCM envelopes + HKDF | `SecureEnvelope`, `KeyProtection` | Correct modern crypto shape |
| RSA-4096 PSS update signatures | `UpdateSignatureVerifier` | Production key baked in (not PLACEHOLDER) |
| Zip Slip + min size on updates | `AutoUpdater` | Staging + `.previous` backup |
| Windows ETW suite + DACL + prologue checks | Monitors + `AntiTamperGuard` | Best platform |
| Linux cn_proc + fanotify + systemd hardening | Monitors + `behavedr.service` | Near real-time parity |
| Android Keystore bridge, VPN inspect, Device Owner hooks | Mobile platform injection | Large jump from v0.2.0 |
| Deterministic builds + pinned Actions SHAs | `Directory.Build.props`, workflows | Good hygiene |
| Default response mode `AlertOnly` | `appsettings.json` | Safe default for operators |

---

# PART 1 - RED TEAM FINDINGS (Attack)

Findings ordered by impact on grades and exploitability.

### RT-1: Release Artifacts Are Not Code-Signed [CRITICAL - Supply Chain / All Platforms]

**Severity:** CRITICAL (for store/OS trust and "10/10 supply chain")  
**MITRE:** T1195.002 - Supply Chain Compromise  
**Location:** `.github/workflows/release.yml`, `packaging/windows/behavedr.iss`, no `signtool`/`codesign`/`jarsigner` steps

**Attack / impact:**
- Windows: SmartScreen "Unknown publisher" -> low enterprise trust; installer can be swapped post-build if only zip hashes are relied upon.
- macOS: Gatekeeper blocks unsigned/unnotarized binaries.
- Android: Debug/CI-signed APKs fail enterprise deployment and Play Protect confidence.
- iOS: No device distribution without proper signing pipeline.

**Grade impact:** Caps **Supply Chain** at ~7 across desktop; blocks "production-grade" claims on Apple platforms.

**Fix (required for 10/10):**
1. Windows: Azure Sign / DigiCert EV -> `signtool sign /tr ... /td sha256 /fd sha256` on `Behavedr.exe` + Setup.
2. macOS: Developer ID Application + `codesign --options runtime` + notarization + staple.
3. Android: Release keystore (or Play App Signing) with pinned cert fingerprint already expected by `SupplyChainVerifier`.
4. Publish SHA-256 + `.sig` for every asset; fail release if any unsigned.

---

### RT-2: Package Lock Files Declared but Not Present [HIGH - Supply Chain]

**Severity:** HIGH  
**MITRE:** T1195.002  
**Location:** `Directory.Build.props` (`RestorePackagesWithLockFile=true`); **no** `packages.lock.json` under any project

**Issue:** Property enables lock-file mode, but lock files are not committed. Restores are not reproducible; a compromised NuGet feed or dependency confusion can change transitive graphs without a CI diff.

**Fix:**
```powershell
dotnet restore --force-evaluate
# commit packages.lock.json for Agent, Core, Mobile, Tests
```
CI: `dotnet restore --locked-mode` and fail on mismatch.

---

### RT-3: iOS Platform Remains Detection-Light and Response-Blind [CRITICAL - iOS]

**Severity:** CRITICAL (for iOS 10/10 goal)  
**MITRE:** T1622, T1630, T1406 (mobile)  
**Location:** `IosMonitor.cs`, `IosPersistenceMonitor.cs`, `PlatformMonitors` (iOS only registers those two), `Info.plist`

**Issue:**
- Only jailbreak heuristics + persistence file scans; no network filter provider, no response engine, no Secure Enclave key path, no background reliability stack comparable to Android WorkManager.
- `Info.plist` still reports `CFBundleShortVersionString` **0.0.7** while product is 0.2.1.
- No iOS platform-injection layer (unlike Android's rich `PlatformInjection/`).
- README claims "Production" iOS; security depth does not match that claim.

**Attack:** On stock iOS, most agent value is limited to self-jailbreak indicators. Malware in other apps is largely invisible without MDM/Network Extension privileges.

**Fix path to ~9+ iOS:**
1. Secure Enclave / Keychain key storage (parity with Android Keystore).
2. `NEFilterDataProvider` / content filter for DNS/C2 patterns (requires supervised/MDM path).
3. App Attest / DeviceCheck for integrity.
4. Background: BGAppRefresh + silent push keep-alive (document limits honestly).
5. Version sync in plist; dedicated iOS response policy (quarantine local artifacts only; remote MDM wipe via server).
6. Do not claim "full EDR" without Network Extension + MDM.

---

### RT-4: macOS Real-Time Coverage Has Discovery Gaps [HIGH - macOS]

**Severity:** HIGH  
**MITRE:** T1059, T1070  
**Location:** `MacOSKqueueMonitor.cs` (documents limitations)

**Issue:** kqueue requires PID subscription after discovery (2s scan interval). Short-lived processes between discovery windows can still race. No file-exec blocking; no EndpointSecurity.

**Attack:** `curl|bash` / JXA one-shots that complete before the next PID scan remain partially invisible.

**Fix:** EndpointSecurity System Extension (`ES_EVENT_TYPE_NOTIFY_EXEC`, `AUTH_OPEN`, etc.) or at minimum FSEvents for high-value paths + shorter discovery + `proc_listpids` hot path. Package as System Extension with Full Disk Access guidance.

---

### RT-5: Linux `CAP_SYS_ADMIN` Undermines Least Privilege [HIGH - Linux]

**Severity:** HIGH  
**MITRE:** T1068  
**Location:** `packaging/unix/behavedr.service`

**Issue:** fanotify needs elevated capability; unit grants full `CAP_SYS_ADMIN`. Seccomp drops `@mount` etc., but CAP_SYS_ADMIN remains a large privilege blob (namespace, module-adjacent, device ops depending on kernel).

**Fix options:**
1. Prefer fanotify API flags that work with narrower caps where kernel allows; or run a **tiny privileged helper** for fanotify only.
2. Document residual risk; add `SystemCallFilter` denser denylist; consider `NoNewPrivileges` already set (good).
3. Long-term: eBPF CO-RE monitors in a restricted loader.

---

### RT-6: Auto-Update Trust Is Strong but Incomplete [MEDIUM-HIGH - Desktop]

**Severity:** MEDIUM-HIGH  
**MITRE:** T1195.002, T1036  
**Location:** `AutoUpdater.cs`, `UpdateSignatureVerifier.cs`

**Good:** Requires `.sig`, RSA-PSS, Zip Slip, size floor, staging + `.previous`.

**Gaps:**
1. **No post-extract binary re-hash / nested signature** of the staged `Behavedr` executable (zip is signed; inner payload trust is transitive).
2. **No automatic rollback** if agent fails health-check after restart (`.previous` exists but operator/manual).
3. **Desktop anti-downgrade** weaker than Android's version-history logic.
4. Root `update-signing-key.pub.pem` is **0 bytes** (dead file; real key is baked into source).
5. Update HTTPS uses system trust roots (acceptable for GitHub) but no optional pin/SPKI.
6. Same public key used for **updates and policy** (`PolicyUpdate.GetServerPublicKey`) - key compromise is dual-impact.

**Fix:** Separate policy key; verify inner file digests listed in signed manifest; auto-rollback on failed start; delete empty PEM or populate for tooling; optional GitHub cert pin.

---

### RT-7: Policy Signature Canonicalization Fragility [MEDIUM]

**Severity:** MEDIUM  
**Location:** `IBehavedrClient.cs` -> `PolicyUpdate.VerifySignature`

**Issue:** Payload is `JsonSerializer.Serialize` of an anonymous type. Property order and null handling must match server exactly or verification fails (availability) or, if server is sloppy, becomes bypass-prone if someone "fixes" it by accepting unsigned in errors.

**Fix:** Explicit canonical JSON (sorted keys, fixed null policy) or protobuf + signature over bytes. Unit tests with golden vectors.

---

### RT-8: Android Play Integrity May Be a No-Op [MEDIUM - Android]

**Severity:** MEDIUM  
**Location:** `PlayIntegrityAttestor.cs` (reflection on `com.google.android.play.core.integrity.*`)

**Issue:** No Play Integrity NuGet/AAR dependency; reflection failure -> `play_integrity_unavailable` signal only. Cloud project number defaults to `0`. Attestation quality depends on packaging that is not enforced in CI.

**Attack:** Compromised/repacked device never fails strong integrity if API never runs.

**Fix:** Add official Play Integrity dependency; require non-zero project number in Release; server-side token decrypt for production; fail closed for Device Owner deployments that require attestation.

---

### RT-9: Android Non-Root Response Still Privilege-Gated [MEDIUM - Android]

**Severity:** MEDIUM  
**Location:** `AndroidResponseEngine.cs`, Device Owner managers

**Issue:** Full kill/iptables needs root; force-stop/uninstall needs Device Owner. Stock consumer install is largely detect + VPN isolation (if user grants VPN). That is honest architecture, but grades for "Response" cannot be 10 without deployment model docs + forced enterprise path.

**Fix:** Document supported profiles (Consumer / DO / Rooted). Gate "production EDR" marketing on DO. Integrate VPN deny-list automatically on high-score detections without root.

---

### RT-10: Mobile CI Is Best-Effort [MEDIUM - Android/iOS Supply Chain]

**Severity:** MEDIUM  
**Location:** `build.yml` / `release.yml` (`continue-on-error: true` on mobile jobs)

**Issue:** Broken mobile builds do not fail the pipeline; Android artifact optional on release. Undermines "production" mobile.

**Fix:** Fail release if Android APK missing for tagged versions that claim Android support; track iOS as separate gated job when certs available.

---

### RT-11: Test Surface Far Below Security Code Surface [MEDIUM - All]

**Severity:** MEDIUM (quality / regression safety)  
**Location:** `tests/Behavedr.Tests` (~627 LOC vs ~22k product LOC)

**Issue:** 49 tests cover scoring/detection basics. Missing:
- Zip Slip / path traversal vectors
- Config seal tamper matrices
- Update signature verify true/false
- Policy canonical signature
- SecurityValidation edge cases
- ProcessKill protected-name spoof
- SecureEnvelope bit-flip rejection

**Impact:** High-grade security features can regress silently.

**Fix:** Target >=80% line coverage on `Security/`, `Update/`, `Response/`, and communication policy path; add fuzz tests for path APIs.

---

### RT-12: Version / Doc Drift [LOW-MEDIUM]

| Artifact | Claims | Actual product |
|----------|--------|----------------|
| `Info.plist` | 0.0.7 | 0.2.1 |
| `build.yml` SBOM `-pv` | 0.0.7 | should use Directory.Build version |
| `THREAT_MODEL.md` | 0.1.4 / July 21 | Missing Android 0.2.x, iOS, kqueue |
| `SECURITY.md` self-protection table | "v0.1.6" label | Features newer |
| README iOS | "Production - full ..." | Overstated vs code |

**Fix:** Single version source; regenerate threat model for 0.2.1; honest platform status table.

---

### RT-13: Accepted / Residual Risks (Still Valid)

From threat model + code comments - still true:

| Risk | Residual |
|------|----------|
| No kernel visibility | Rootkits invisible |
| ProcessKill TOCTOU (PID reuse) | Documented sub-ms race |
| Single-process agent | Kill window until SCM/systemd restart |
| DPAPI entropy filesystem fallback | Containers degrade binding |
| Userland fanotify/ETW privilege needs | Elevation required for full power |

These prevent a pure theoretical 10/10 against kernel adversaries; **operational 10/10** should be defined as "best-in-class userland + supply chain," not "beats kernel rootkits."

---

# PART 2 - BLUE TEAM FINDINGS (Defense Improvements)

### BT-1: Raise Supply Chain to 10/10 First (Highest ROI)

| Step | Effort | Score lift |
|------|--------|------------|
| Commit lockfiles + `--locked-mode` | S | +0.5-1.0 all platforms |
| Sign Windows installer + portable | M | +1.0 Win supply chain; SmartScreen |
| codesign + notarize macOS | M | Unblocks macOS enterprise |
| Release-sign Android APK | M | +0.5-1.0 Android |
| SBOM all RIDs + attach to release | S | Compliance |
| SLSA provenance / cosign on containers if any | M | Bonus |
| Dependabot + `dotnet list package --vulnerable` in CI | S | Continuous |

### BT-2: Hardening Checklist by Platform

#### Windows (9.1 -> 10)
- [ ] EV Authenticode on Setup + exe  
- [ ] Optional: early WFP filter for isolation response  
- [ ] Driver-load monitoring (userland: registry + ETW ImageLoad already partial)  
- [ ] Security unit tests for kill/path/Authenticode cache  
- [ ] Document SYSTEM-only install ACL verification in post-install script  

#### Linux (8.8 -> 10)
- [ ] Reduce CAP_SYS_ADMIN blast radius or helper split  
- [ ] eBPF process/file probes (replace fanotify dependency long-term)  
- [ ] `IPAddressAllow` template in packaging README for production  
- [ ] Landlock/seccomp profile review against actual syscalls used  
- [ ] Package as deb/rpm with signed repo metadata  

#### macOS (7.9 -> 10)
- [ ] EndpointSecurity System Extension  
- [ ] codesign + notarize + launchd package installer  
- [ ] TCC/FDA install documentation  
- [ ] `codesign -v` self-check at startup (binary integrity beyond hash)  
- [ ] NetworkExtension optional for DNS parity  

#### Android (8.5 -> 10)
- [ ] Real Play Integrity dependency + server verify  
- [ ] Enforce DO profile for "full response" product SKU  
- [ ] VPN auto-isolate on high score (no root)  
- [ ] Release signing in CI; pin cert in `SupplyChainVerifier`  
- [ ] Gate CI on APK build  
- [ ] UI/privacy: justify `ACCESS_FINE_LOCATION` / `READ_PHONE_STATE` (Play policy risk)  

#### iOS (4.1 -> 9-10 ceiling under Apple policy)
- [ ] Keychain/Secure Enclave machine key  
- [ ] App Attest  
- [ ] Network Extension content filter (supervised)  
- [ ] MDM configuration profile channel for policy  
- [ ] Background durability honest limits  
- [ ] Sync version; add platform injection project folder parity with Android  
- [ ] Response: local quarantine + MDM signal only  

### BT-3: Crypto & Keys

- [ ] Split **update signing key** vs **policy signing key**  
- [ ] Document offline HSM/ceremony for private keys  
- [ ] Ensure Android StrongBox preference is verified in logs/metrics  
- [ ] iOS Secure Enclave path  
- [ ] Remove or fill empty `update-signing-key.pub.pem`  

### BT-4: Detection & Response Quality

- [ ] MITRE ATT&CK coverage matrix per platform (export from code attributes)  
- [ ] False-positive regression suite (golden process trees)  
- [ ] Rate-limit and audit log every response action (immutable)  
- [ ] Desktop anti-downgrade for AutoUpdater (mirror Android)  
- [ ] Health-check-triggered update rollback  

### BT-5: Observability & Ops

- [ ] Expand `BehavedrMetrics` for monitor heartbeats, signature fails, isolation counts  
- [ ] Structured security event schema for SIEM  
- [ ] Crash-safe last-gasp already partially present - verify on each OS  

### BT-6: Documentation Honesty (Trust Grade)

- [ ] README platform table: "Production" only where scores >= 8.5 and signed builds exist  
- [ ] Update `THREAT_MODEL.md` to 0.2.1 + mobile  
- [ ] Operator guide: AlertOnly vs Active response  
- [ ] Legal/privacy: what data is collected on Android (location/phone state)  

---

# PART 3 - PRIORITIZED ROADMAP TO 10/10

### Phase A - 1-2 weeks (largest multi-platform lift)

1. Generate + commit `packages.lock.json`; CI `--locked-mode`  
2. Wire Authenticode (Windows) + document Apple/Android signing secrets  
3. Publish release checksums + ensure every asset has `.sig`  
4. Fix version drift (plist, SBOM `-pv`, threat model header)  
5. Security-focused unit tests for `Security/*`, Zip Slip, policy sig  
6. Fail release job if Android APK absent when version claims Android  

**Expected overall:** Win 9.1->9.4, Linux 8.8->9.1, Android 8.5->8.8, macOS 7.9->8.2 (signing alone).

### Phase B - 2-4 weeks

1. Auto-update: signed manifest of inner files + auto-rollback  
2. Separate policy key  
3. Play Integrity real dependency + server path  
4. Linux capability split / eBPF spike  
5. Android VPN auto-isolate on detection  
6. macOS codesign/notarize pipeline  

**Expected:** Desktop ~9.5+, Android ~9.2.

### Phase C - Platform excellence (4-10 weeks)

1. macOS EndpointSecurity extension  
2. iOS Keychain + App Attest + Network Extension (MDM SKU)  
3. Optional Windows WFP isolation  
4. Full MITRE matrix + external pen-test  

**Expected:** Win/Linux 9.7-10 (userland definition), macOS 9.5+, Android 9.5+, iOS 8.5-9.5 depending on MDM.

---

# PART 4 - RED TEAM ATTACK PATHS (Top 5 Scenarios)

| # | Scenario | Current mitigation | Residual | Next control |
|---|----------|-------------------|----------|--------------|
| 1 | Trojanized GitHub release zip | RSA-PSS `.sig` required | Stolen signing key; unsigned SmartScreen social engineering | EV signing + key in HSM + dual control |
| 2 | Disable agent (admin) | DACL, SCM restart, anti-suspend, registry heal | Admin + SeDebug can still win | Tamper-evident remote heartbeat alert SLA |
| 3 | Ephemeral macOS payload | kqueue + poll | Discovery race | EndpointSecurity |
| 4 | Android sideload malware on non-DO device | Detection + optional VPN | Weak kill | Device Owner enrollment |
| 5 | Dependency confusion on restore | Intent: lockfiles | **Locks not committed** | Commit locks + locked-mode CI |

---

# PART 5 - SCORE RATIONALE NOTES

- **Windows Real-Time 10:** Native ETW process/DNS path is best-in-class in this codebase.  
- **Supply Chain 7.0:** Strong design docs, weak release cryptography *for OS trust* (Authenticode/notarization) and missing lockfiles.  
- **Android 8.5 not 9.1:** Feature breadth is high; attestation and enterprise response are not yet fail-closed / CI-proven.  
- **iOS 4.1:** Architecture sketches exist; production depth does not.  
- **10/10 definition used here:** Best achievable **userland** EDR + **provable** supply chain for each OS's distribution model - not kernel omnipotence.

---

# PART 6 - QUICK WIN PATCH LIST (Concrete)

| ID | Change | Files |
|----|--------|-------|
| Q1 | Commit package locks | `**/packages.lock.json`, CI |
| Q2 | SBOM version from props | `build.yml` replace hard-coded `0.0.7` |
| Q3 | Sync iOS version | `Info.plist` -> 0.2.1 |
| Q4 | Delete or fill empty PEM | `update-signing-key.pub.pem` |
| Q5 | Threat model bump | `THREAT_MODEL.md` |
| Q6 | README iOS status honesty | `README.md` |
| Q7 | Add tests: Zip Slip, config tamper, sig verify | `tests/` |
| Q8 | Release signing steps | `release.yml` |
| Q9 | `dotnet list package --vulnerable` gate | `build.yml` |
| Q10 | AutoUpdater min-version anti-downgrade | `AutoUpdater.cs` |

---

## Conclusion

Behavedr's **detection and self-protection engineering is already excellent on Windows and strong on Linux**, with **Android rapidly approaching parity** for a userland mobile agent. The gap to **10/10 on all platforms** is no longer "add more random monitors" - it is:

1. **Prove the supply chain** (sign, lock, gate CI),  
2. **Close macOS real-time** (EndpointSecurity),  
3. **Build iOS for real** (or scope it as MDM companion, not full EDR),  
4. **Test security invariants** so grades cannot silently regress.

Recommended next execution order: **Phase A (Q1-Q10)** immediately, then macOS ES + iOS Keychain/App Attest as platform epics.

---

*This audit is source-based and independent of marketing claims in README/CHANGELOG. Re-score after Phase A before investing in long platform epics.*
