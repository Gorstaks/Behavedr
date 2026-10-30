# Behavedr Supply Chain & Release Trust

**Document version:** 0.2.4  
**Last updated:** 2026-07-25  
**Audience:** Maintainers, release engineers, security reviewers, enterprise evaluators  

This document states what Behavedr currently guarantees about build and distribution integrity, what it does **not** guarantee, and the exact controls operators should verify before trusting a release.

It is written for engineering judgment, not marketing.

---

## 1. Threat model (distribution)

| Threat | Attacker goal | Primary control | Residual risk |
|--------|---------------|-----------------|---------------|
| Trojanized GitHub Release asset | Ship malware as "Behavedr" | RSA-PSS `.sig` over each asset; agent rejects unsigned updates | Stolen update private key; user installs without verifying |
| Compromised CI runner | Inject code into build | Pinned Actions SHAs; locked NuGet restores; no runtime package download | Compromised GitHub org / maintainer account |
| Dependency confusion / feed swap | Change transitive packages | `packages.lock.json` + `dotnet restore --locked-mode` | Lockfile not yet present for Mobile until MAUI restore on a workload machine |
| Downgrade to vulnerable version | Force old agent | Anti-downgrade version check in `AutoUpdater` | Manual install of older portable zip still possible |
| Bad-but-signed update that fails to run | Break protection | `.previous` backup + `.update-pending` health-check rollback | Locked Windows image may require manual restore from `.previous` |
| Unsigned Windows/macOS/Android binaries | OS distrust / swap post-download | Optional Authenticode / codesign / keystore secrets in release workflow | **If secrets are not configured, OS-level trust is not present** |

---

## 2. Cryptographic controls (what the agent enforces)

### 2.1 Auto-update package signatures

| Item | Value |
|------|--------|
| Algorithm | RSA-PSS, SHA-256, salt length = digest |
| Key size | 4096-bit |
| Public key | Baked into `UpdateSignatureVerifier` at compile time |
| Sidecar | `{asset}.sig` (raw signature bytes) |
| Fail mode | No `.sig` or invalid signature -> **reject update** |

Signing command (OpenSSL 3.x), matching agent verification:

```bash
openssl dgst -sha256 \
  -sigopt rsa_padding_mode:pss \
  -sigopt rsa_pss_saltlen:digest \
  -sign update-signing-key.pem \
  -out Behavedr-Portable-0.2.4-win-x64.zip.sig \
  Behavedr-Portable-0.2.4-win-x64.zip
```

Automation: `tools/sign-release.ps1` / `tools/sign-release.sh`.

### 2.2 SHA-256 manifests

Release workflow publishes `SHA256SUMS` (and `SHA256SUMS.sig` when the update key is available).

- Agents treat SHA-256 match as a **second factor** when the manifest is present.
- Signature verification remains the hard gate. A missing line for an asset is logged and does not override a valid RSA-PSS signature.
- Operators should always verify `SHA256SUMS` offline before first install.

### 2.3 Policy signatures (key path separation)

As of **0.2.4**, server policy verification uses `PolicySignatureVerifier` - a separate code path and PEM constant from package updates.

| State | Meaning |
|-------|---------|
| Distinct policy PEM | Preferred. Compromise of update key does not authorize policy injection. |
| Shared with update key (`IsUsingSharedUpdateKey() == true`) | **Current interim state.** Keys are dual-use until an offline ceremony provisions a second RSA-4096 pair. Startup self-test logs this fact. |

Rotation procedure is section 6.

### 2.4 Anti-downgrade and health-check rollback

1. `ApplyUpdateAsync` rejects any package whose version is not strictly greater than the running agent.
2. After a successful stage, the agent writes `.update-pending` containing the new version and backs up current binaries to `.previous/`.
3. On next start, `StartupSelfTest` runs critical crypto health (SecureEnvelope round-trip, machine key, production update key present).
4. Failure with a pending marker -> restore from `.previous/` and clear the marker; operator must restart to load restored images.
5. Success -> clear the marker.

**Honest limits:** this is process-local recovery, not remote attestation. A fully corrupted install directory may still need reinstall from a verified release asset.

---

## 3. Build integrity

| Control | Status in 0.2.4 | Notes |
|---------|-----------------|-------|
| Deterministic MSBuild (`Deterministic=true`) | Yes | `Directory.Build.props` |
| `RestorePackagesWithLockFile` | Yes | Property set globally |
| Lockfiles committed | Agent, Core, Tests: **yes**. Mobile: **generate on workload host** | CI uses `--locked-mode` for desktop; Mobile uses locked-mode when lockfile exists |
| Pinned GitHub Actions by commit SHA | Yes | No floating `@v4` tags |
| SBOM generation | Best-effort on Linux publish | Tool install may soft-skip; do not treat missing SBOM as a silent success in compliance programs |
| `dotnet list package --vulnerable` in CI | Yes | Fails desktop build on reported Critical/High/Moderate/Low findings |
| Dependabot | Yes | Weekly NuGet + Actions (`.github/dependabot.yml`) |
| Runtime package downloads during build | No | Inno Setup discovered locally / via CI choco install with checksum type |

---

## 4. "I have no certs" - what that actually means

Two different trust layers. Do not conflate them.

| Layer | What it is | Cost | Required for Behavedr to work? |
|-------|------------|------|--------------------------------|
| **Update `.sig` (RSA-4096 PSS)** | Free self-generated keypair. Agent verifies with baked-in public key. | $0 | **Yes for auto-update.** Manual install of zips still works without signatures. |
| **OS / store certs** | Authenticode (Windows), Apple Developer ID, Android Play/keystore | Paid / enrollment | **No.** Optional. Affects SmartScreen, Gatekeeper, Play trust only. |

### Android "cert pins" (publisher only - not end users)

A **cert pin** is the SHA-256 fingerprint of the certificate that signed your APK.
It is **not** something users type in. Users only install the APK.

| Who | Action |
|-----|--------|
| **End user** | Install APK (Play / sideload). Nothing else. |
| **You (publisher)** | Optional: once you have a release keystore, paste its cert hash into `AndroidCertPins.BakedInPins` so fake APKs signed with other keys are rejected. |
| **Default today** | Empty pin -> **self-pin**: first run remembers the installed APK's cert; if it later changes -> repackage alert. |

```bash
# After you sign a release APK (publisher machine only):
apksigner verify --print-certs Behavedr.apk
# Copy the SHA-256, strip colons, put in AndroidCertPins.cs BakedInPins
```

### If you have no commercial certificates

That is fine for engineering and for many self-hosted deployments:

- Ship portable zips + installer **unsigned by Microsoft/Apple**.
- Still publish **RSA-PSS `.sig`** using a free key so agents can auto-update safely.
- Operators verify `SHA256SUMS` + `.sig` before install (section 7).
- Do **not** claim "signed by CroatiaSecurity as a Windows publisher" or "notarized for macOS."

### If you also have no update private key

Generate one (no CA involved):

```powershell
dotnet run --project tools
# writes update-signing-key.pem (private, gitignored)
# writes update-signing-key.pub.pem (public, commit this)
```

Then:

1. Bake the public PEM into `UpdateSignatureVerifier` (and policy verifier if dual-use).
2. Put the **entire** private PEM into GitHub Actions secret **`UPDATE_SIGNING_KEY`**.
3. Re-run a release. CI will produce `.sig` files automatically via `tools/sign-release.sh`.

Local sign without CI:

```powershell
.\tools\sign-release.ps1 -AssetsDir .\release-assets -PrivateKeyPath .\update-signing-key.pem
```

---

## 5. OS / store trust signing (optional secrets)

Behavedr's **agent-enforced** trust is RSA-PSS on release assets. **OS trust** (SmartScreen, Gatekeeper, Play Protect confidence) requires platform code-signing certificates that are **not** stored in this repository.

The release workflow implements conditional signing. When secrets are absent, the workflow **warns and continues** for OS signing, and for package RSA-PSS either signs (secret present) or publishes checksums only (secret absent) with a clear warning that production agents will reject unsigned auto-updates.

### 4.1 Required GitHub Actions secrets (production)

| Secret | Purpose |
|--------|---------|
| `UPDATE_SIGNING_KEY` | Full RSA private key PEM for package + SHA256SUMS signatures |
| `WINDOWS_CODESIGN_PFX_BASE64` | Base64-encoded Authenticode PFX (EV/OV) |
| `WINDOWS_CODESIGN_PASSWORD` | PFX password |
| `MACOS_CERTIFICATE_P12_BASE64` | Developer ID Application certificate (P12) |
| `MACOS_CERTIFICATE_PASSWORD` | P12 password |
| `MACOS_CODESIGN_IDENTITY` | Identity string for `codesign --sign` |
| `ANDROID_KEYSTORE_BASE64` | Release PKCS#12 (`keys/android/behavedr-release.p12`, base64) |
| `ANDROID_KEYSTORE_PASSWORD` | Keystore password |
| `ANDROID_KEY_ALIAS` | Key alias (default `behavedr` if unset) |
| `ANDROID_KEY_PASSWORD` | Key password (defaults to keystore password if unset) |

When those secrets are set, **release.yml auto-signs** the Android APK with the
release keystore so it matches `AndroidCertPins`. See `keys/android/README.md`.
| `ANDROID_KEY_ALIAS` | Key alias |
| `ANDROID_KEY_PASSWORD` | Key password |

### 4.2 What "unsigned" means in practice

| Platform | Without OS signing | With OS signing |
|----------|--------------------|-----------------|
| Windows | SmartScreen "unknown publisher"; enterprise trust low | Authenticode on `Behavedr.exe` + Setup |
| macOS | Gatekeeper friction; no notarization | Developer ID `codesign --options runtime` (notarization still separate) |
| Android | Debug/CI-signed APK; Play Protect / MDM weaker | Release keystore or Play App Signing |

**Truthful statement for evaluators:** until Authenticode, Developer ID + notarization, and Android release signing secrets are configured and verified in a release audit, Behavedr must not be described as "OS-trusted distribution." It can still be described as "cryptographically signed auto-update packages" when `UPDATE_SIGNING_KEY` is used.

---

## 6. Release hard gates (0.2.4+)

The `release.yml` workflow:

1. Builds Windows, Linux, and macOS desktop packages.
2. **Requires** a successful Android APK (no longer `continue-on-error`).
3. Requires the Windows installer and all three portable zips before publish.
4. Generates `SHA256SUMS` for every published binary asset.
5. When `UPDATE_SIGNING_KEY` is set, signs every asset and the checksum file; **fails** if any `.sig` is missing.
6. Attaches all assets, checksums, and signatures to the GitHub Release.

PR/main CI (`build.yml`) still treats Android as best-effort so desktop development is not blocked by MAUI toolchain flake. That asymmetry is intentional and documented. iOS is not a SKU and is not built.

---

## 7. Key ceremony (update and policy)

### 6.1 Generate update signing key

```bash
dotnet run --project tools
# or openssl genrsa -out update-signing-key.pem 4096
# openssl rsa -in update-signing-key.pem -pubout -out update-signing-key.pub.pem
```

1. Store the **private** key offline (HSM or sealed secret store). Never commit it.
2. Bake the **public** key into `UpdateSignatureVerifier.PublicKeyPem`.
3. Commit `update-signing-key.pub.pem` for operator reference (already present).
4. Configure `UPDATE_SIGNING_KEY` in GitHub Environments with dual-control where possible.

### 6.2 Split policy key (recommended)

1. Generate a second RSA-4096 pair.
2. Replace `PolicySignatureVerifier` PEM with the new public key.
3. Sign policy payloads only with the policy private key.
4. Confirm `PolicySignatureVerifier.IsUsingSharedUpdateKey()` returns **false**.
5. Keep update and policy private keys under separate access controls.

---

## 8. Operator verification checklist

Before deploying a release asset:

1. Download the asset, `SHA256SUMS`, and corresponding `.sig` files from the official GitHub Release only.
2. `sha256sum -c SHA256SUMS` (or equivalent) for the chosen asset.
3. Verify RSA-PSS with the published public key:

```bash
openssl dgst -sha256 \
  -sigopt rsa_padding_mode:pss \
  -sigopt rsa_pss_saltlen:digest \
  -verify update-signing-key.pub.pem \
  -signature Behavedr-Portable-0.2.4-linux-x64.zip.sig \
  Behavedr-Portable-0.2.4-linux-x64.zip
```

4. Prefer the Windows installer only after Authenticode inspection (`signtool verify /pa`) when OS signing is enabled for that release.
5. Leave response mode at **AlertOnly** until detection noise is baselined for the environment.

---

## 9. What this project still does not claim

- **SLSA Level 3+ provenance** for every artifact (SBOM is best-effort; provenance attestation not yet mandated).
- **Notarization staple** for macOS (codesign step exists; notarize/staple is a follow-on when Apple ID secrets exist).
- **Kernel-level supply-chain immunity** (userland agent).
- **iOS** (not a Behavedr SKU; see [IOS.md](IOS.md)).
- **That every historical release was signed** - verify per-tag assets.

---

## 10. Related documents

| Document | Role |
|----------|------|
| [RELEASE.md](RELEASE.md) | Step-by-step release procedure |
| [SECURITY.md](../SECURITY.md) | Vulnerability reporting and architecture summary |
| [THREAT_MODEL.md](../THREAT_MODEL.md) | System threat model |
| [CHANGELOG.md](../CHANGELOG.md) | Version history |
| Audits under `docs/red-blue-team-audit-*.md` | Independent findings and residual grades |
