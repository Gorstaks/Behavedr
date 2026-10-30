# Behavedr Release Procedure

**Applies to:** 0.4.x and later  
**Last updated:** 2026-08-24  

This is the operational runbook for cutting a Behavedr release. Follow it in order. Do not skip verification steps to "save time."

---

## 0. Version numbering policy

| Kind | When | Example |
|------|------|---------|
| **Patch** | Normal incremental work | `0.4.0` -> `0.4.1` |
| **Minor** | Product-line capability step (cumulative depth) | `0.3.x` -> **`0.4.0`** |
| **Major** | Breaking product/API contract (rare pre-1.0) | `0.x` -> `1.0.0` |

**Do not** keep stacking patch numbers past a real line break (`0.3.10` when you mean **0.4.0**).  
**Do not** invent minors for marketing of a single PR - use patch unless the line truly advanced.

After **0.4.0**, default is patch-only until the next deliberate minor.

Scope (eBPF, EndpointSecurity, packaging) is described in the **changelog body**, not by skipping version numbers.

---

## 1. Preconditions

- [ ] All intended changes are on `main` and green on desktop CI.
- [ ] `Directory.Build.props` version matches the intended release (e.g. `0.3.0` or next patch).
- [ ] `CHANGELOG.md` has a dated section for that version (not only `Unreleased`).
- [ ] `SECURITY.md` supported-versions table lists the new version.
- [ ] `THREAT_MODEL.md` version header matches.
- [ ] Mobile version fields aligned: `Behavedr.Mobile.csproj`, Inno `behavedr.iss` (auto-stamped via `/DMyAppVersion` but default should match).
- [ ] Production secrets present in the GitHub repository environment for the trust level you intend to claim (see [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) 4).

### Minimum secrets for agent auto-update

| Secret | Required for |
|--------|----------------|
| `UPDATE_SIGNING_KEY` | Agents with baked production public key accepting auto-updates |

### Additional secrets for OS trust claims

Authenticode, macOS Developer ID, Android release keystore - see SUPPLY_CHAIN.md. Without them, release notes must not claim SmartScreen-clean or Gatekeeper-clean distribution.

---

## 2. Version bump checklist

Edit (or confirm) these together:

| Location | Field |
|----------|--------|
| `Directory.Build.props` | `Version`, `AssemblyVersion`, `FileVersion`, `InformationalVersion` |
| `CHANGELOG.md` | New `## [x.y.z] - YYYY-MM-DD` section |
| `README.md` | Current version line |
| `SECURITY.md` | Supported versions table |
| `THREAT_MODEL.md` | Version / last updated |
| `src/Behavedr.Mobile/Behavedr.Mobile.csproj` | `ApplicationDisplayVersion`, `ApplicationVersion` (integer bump) |
| `packaging/windows/behavedr.iss` | Default `MyAppVersion` |

---

## 3. Local verification (before push)

```powershell
# Restore locked graphs
dotnet restore src/Behavedr.Core/Behavedr.Core.csproj --locked-mode
dotnet restore src/Behavedr.Agent/Behavedr.Agent.csproj --locked-mode
dotnet restore tests/Behavedr.Tests/Behavedr.Tests.csproj --locked-mode

# Vulnerability scan (must report no known vulnerable packages)
dotnet list src/Behavedr.Agent/Behavedr.Agent.csproj package --vulnerable --include-transitive
dotnet list tests/Behavedr.Tests/Behavedr.Tests.csproj package --vulnerable --include-transitive

# Tests
dotnet test tests/Behavedr.Tests/Behavedr.Tests.csproj -c Release

# Optional desktop publish smoke
dotnet publish src/Behavedr.Agent/Behavedr.Agent.csproj -c Release -r win-x64 --self-contained -o publish/smoke-win
```

If lockfiles change after package updates, regenerate with:

```powershell
dotnet restore <csproj> --force-evaluate
# commit the resulting packages.lock.json
```

Mobile lockfile (requires MAUI Android workload):

```powershell
dotnet workload install maui-android
dotnet restore src/Behavedr.Mobile/Behavedr.Mobile.csproj -p:MobileTfms=net10.0-android --force-evaluate
```

---

## 4. Shipping

### Automated path (preferred)

1. Merge to `main` with the version already bumped in `Directory.Build.props`.
2. `build.yml` desktop jobs must pass.
3. `auto-tag` creates `v{Version}` if the tag does not exist and dispatches `release.yml`.
4. `release.yml`:
   - builds all desktop RIDs,
   - builds Android APK (**hard fail if missing**),
   - optionally Authenticode / codesign / keystore-signs when secrets exist,
   - produces `SHA256SUMS` and RSA-PSS `.sig` files when `UPDATE_SIGNING_KEY` is set,
   - publishes the GitHub Release.

### Manual path

```bash
git tag -a v0.3.0 -m "Release v0.3.0"
git push origin v0.3.0
# or: gh workflow run release.yml --ref v0.3.0
```

---

## 5. Post-release verification

1. Open the GitHub Release page for the tag.
2. Confirm assets:
   - `Behavedr-Setup-*-win-x64.exe`
   - `Behavedr-Portable-*-win-x64.zip`
   - `Behavedr-Portable-*-linux-x64.zip`
   - `Behavedr-Portable-*-osx-arm64.zip`
   - `Behavedr-*-android.apk`
   - `SHA256SUMS`
   - `.sig` for each binary asset + `SHA256SUMS.sig` (if update key configured)
3. Spot-check one portable zip with OpenSSL verify (SUPPLY_CHAIN.md 7).
4. Install in a lab VM with **AlertOnly** response; confirm service starts and self-test logs pass.
5. If an update was staged in lab: confirm `.update-pending` clears after healthy restart.

---

## 6. Failure modes and response

| Failure | Action |
|---------|--------|
| Android job fails | Fix MAUI/SDK issue; re-run release. Do not publish desktop-only "production" builds while README claims Android production. |
| RSA-PSS signing fails | Do not publish unsigned assets to a channel used by production agents. Fix key secret formatting (PEM, newlines). |
| Authenticode fails | Release may still proceed for package signatures; document that Windows OS trust is absent for that build. |
| Bad update already staged in field | Agent should auto-rollback on failed crypto health; if not, restore from `.previous/` or reinstall from verified release. |
| Version tag already exists | Bump version; never move or force-push release tags after assets are public. |

---

## 7. Documentation after release

- [ ] CHANGELOG section is accurate (no aspirational language).
- [ ] README platform table still honest (iOS is not a SKU).
- [ ] Any new known limitation added to SECURITY.md.
- [ ] If grades changed, note residual risk in the next audit rather than inventing scores in the changelog.

---

## 8. Related documents

- [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) - trust boundaries and secrets  
- [SECURITY.md](../SECURITY.md) - security architecture  
- [THREAT_MODEL.md](../THREAT_MODEL.md) - system threats  
