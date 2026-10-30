# Behavedr Operator Guide

**Version:** 0.4.3



## Live policy (0.3.2+)

When `Communication:Enabled` and the management server returns a **signed** policy:

| Field | Effect |
|-------|--------|
| `ResponsePolicy` | Mode, thresholds, kill budget - hot-applied |
| `ScoringConfig` | President-kill / multipliers - hot-applied |
| `MonitoringIntervalSeconds` | Detection cycle delay (1-60s) without restart |

Unsigned or invalid policies are rejected; signature failures increment security metrics.

## Response modes

| Mode | Config | Behavior |
|------|--------|----------|
| **AlertOnly** (default) | `Response:Mode = AlertOnly` | Score, log, report - **no** kill/quarantine/isolate |
| **Active** | `Response:Mode = Active` | Executes registered response actions at thresholds |

Leave AlertOnly until you have baselined false positives for the environment.

### Response safety (0.3.6+)

Active mode will **not**:

- Kill the agent process, its parent host, or agent install binaries  
- Quarantine agent binaries or OS system paths  
- Firewall-block the agent image or system images  
- On Linux, UID-isolate the same user as the agent (uses destination IP block instead)  

Detection treats **staging paths** (Temp, `/tmp`, Downloads) as higher risk than tool **names** alone (rename-resistant).

### Thresholds

| Setting | Default | Meaning |
|---------|---------|---------|
| `AlertThreshold` | 50 | Log / report |
| `ResponseThreshold` | 75 | Isolation / quarantine class actions |
| President-kill | scoring config | Process kill class (desktop) |
| `MaxKillsPerMinute` | 15 | Kill-storm budget |

## Platform activation (0.3.0-0.3.0 depth)

| Feature | Enable |
|---------|--------|
| Windows WFP isolate | Run as SYSTEM; automatic when Active |
| Linux eBPF exec | `CAP_BPF`/`CAP_PERFMON` + optional `behavedr_exec.bpf.o` in `/opt/behavedr/` |
| macOS EndpointSecurity | `libbehavedr_es.dylib` + ES entitlement; `BEHAVEDR_ES_AUTH=1` for optional AUTH deny list |
| Android Play Integrity fail-closed | `BEHAVEDR_REQUIRE_PLAY_INTEGRITY=1` or non-zero cloud project number |
| Android VPN isolate | Active response + VPN permission / service running |
| Linux Landlock | `Platform:EnableLandlock` or `BEHAVEDR_LANDLOCK=1` (write sandbox) |
| Linux fanotify PERM | `Platform:EnableFanotifyPerm` or `BEHAVEDR_FANOTIFY_PERM=1` (deny tmp droppers) |
| Disable Windows WFP prefer | `BEHAVEDR_PREFER_WFP=0` (advfirewall only) |

## Legal / safety

Active response can terminate processes and isolate network paths. Confirm authority and change control before enabling. Default AlertOnly exists for this reason.

## Audit trail

Response outcomes append to `logs/response-audit.jsonl` (HMAC when machine key available).
