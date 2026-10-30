# Behavedr

Behavioral endpoint detection and response agent. Monitors process activity, network connections, and system integrity in real time. Produces scored detections and executes configurable response actions.

**Current version: 0.4.4**

Versioning: current product line is **0.4.x**. Prefer patch bumps for incremental work; use a **minor** when cumulative capability advances the line. See [docs/RELEASE.md](docs/RELEASE.md) 0.

**Platform epics (0.4.0):** in-repo implementation is complete. Field activation (eBPF object, ES entitlement, SE product, paid certs) is documented in [docs/EPICS_STATUS.md](docs/EPICS_STATUS.md).

## Platforms

| Platform | Status |
|----------|--------|
| Windows (x64) | Production - ETW detection, BYOVD, WFP isolation (+ advfirewall fallback) |
| Linux (x64) | Production - cn_proc, fanotify, **eBPF suite** (exec/file/net depth), nftables, hardened systemd |
| macOS (ARM64) | Production - kqueue + **EndpointSecurity** (NOTIFY; optional AUTH), VNODE, codesign, pf/route |
| Android | Production - detect/respond, VPN isolate, Play Integrity fail-closed option, Device Owner |
| iOS | **Not a SKU** - Apple sandbox cannot host device EDR; use MDM for phones. See [docs/IOS.md](docs/IOS.md). |

"Production" means the platform is intended for operational deployment **within the limits of a userland agent**. It does not mean kernel omnipotence, notarized Apple distribution, or that every release is Authenticode-signed. Release trust details: [docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md).

Default response mode is **AlertOnly**. Enable Active response only after understanding process kill, quarantine, and isolation side effects.

## Quick Start

**Windows (installer):**
```
Behavedr-Setup-<version>-win-x64.exe
```

**Windows (portable):**
```
Behavedr.exe
```

**Linux:**
```
chmod +x Behavedr
sudo ./Behavedr
```

Before production install, verify `SHA256SUMS` and RSA-PSS `.sig` files for the asset (see [docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md) 7).

## Building from Source

Requires .NET 10 SDK.

```powershell
# Windows - full installer build
.\installer\build.ps1

# Any platform - portable binary only
dotnet publish src/Behavedr.Agent/Behavedr.Agent.csproj -c Release -r win-x64 --self-contained
```

## Documentation

| Document | Contents |
|----------|----------|
| [SECURITY.md](SECURITY.md) | Vulnerability reporting, security design, known limitations |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Threat model, attack surface, trust boundaries |
| [docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md) | Build integrity, signing, secrets, operator verification |
| [docs/RELEASE.md](docs/RELEASE.md) | Release runbook |
| [docs/MITRE_COVERAGE.md](docs/MITRE_COVERAGE.md) | ATT&CK technique map (userland) |
| [docs/OPERATOR_GUIDE.md](docs/OPERATOR_GUIDE.md) | AlertOnly vs Active, platform activation |
| [docs/EPICS_STATUS.md](docs/EPICS_STATUS.md) | Honest field-readiness of platform epics |
| [docs/IOS.md](docs/IOS.md) | Why iOS is not a SKU |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [docs/](docs/) | Architecture decisions, audit reports |

## License

This software is provided under the terms specified in the repository license file. If no license file is present, all rights are reserved by CroatiaSecurity.

## Legal

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS, COPYRIGHT HOLDERS, OR CONTRIBUTORS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

**Behavedr is endpoint security software that monitors system activity and may terminate processes or quarantine files based on behavioral analysis.** Deployment and operation of this software is the sole responsibility of the operator. The operator must ensure compliance with all applicable laws, regulations, and organizational policies governing endpoint monitoring, data collection, and automated response actions in their jurisdiction.

CroatiaSecurity is not responsible for:
- Data loss resulting from automated response actions (process termination, file quarantine)
- System instability caused by interaction with other security software
- False positive detections leading to disruption of legitimate processes
- Regulatory non-compliance arising from deployment without appropriate authorization

By installing or running this software, the operator acknowledges these terms and accepts full responsibility for its configuration and operation.

---

Copyright (c) 2026 CroatiaSecurity. All rights reserved.
