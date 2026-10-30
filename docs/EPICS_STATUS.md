# Platform epics - status (0.4.3)

**In-repo implementation for the platform epics is complete.**  
What remains is **field activation** (host artifacts, vendor enrollment), not more scaffolds.

## Summary

| Epic | In-repo code | Auto-on | Field activation (you / vendor) |
|------|--------------|---------|----------------------------------|
| Windows isolation (COM + WFP + netsh) | **Done** | Yes (SYSTEM) | Run agent elevated |
| Linux eBPF suite | **Done** | No | Build/install `.o`, bpftool, CAP_BPF |
| Linux cn_proc / fanotify | **Done** | Soft | CAP_NET_ADMIN / CAP_SYS_ADMIN |
| macOS ES (dylib + poll + JSONL) | **Done** | No | Entitlement + dylib or ES host |
| macOS System Extension product | **Partial** | No | Apple SE capability + install UX |
| Android pin + CI APK sign | **Done** | Soft | Release workflow secrets (set) |
| Response safety / rename-aware detect | **Done** | Yes | Always on |
| iOS | **Not a SKU** | No | Apple sandbox; use MDM (see `docs/IOS.md`) |
| Kernel callout / rootkit | **Out of scope** | N/A | Userland EDR only |
| Paid Authenticode / notarize | Hooks only | No | Paid certs |

## What "done" means

- Production code paths (not stubs): loaders, bridges, isolation engines, safety rails  
- Soft-fail when field extras missing (cn_proc / kqueue / netsh remain)  
- Public threat model assumes attackers read the source: rename-resistant heuristics, no easy self-kill  

## Field activation cheatsheet

```bash
# Linux eBPF
./native/build-native.sh dist/native   # on Linux
sudo cp dist/native/behavedr_exec.bpf.o /opt/behavedr/
sudo systemctl restart behavedr

# macOS ES (in-process)
# build dylib on Darwin, install to /opt/behavedr/, sign with ES entitlement

# Android release APK
# ANDROID_KEYSTORE_* secrets -> release.yml auto-signs (already documented)
```

## Will not claim

- eBPF/ES active on every install without host extras  
- Full App Store System Extension product without Apple enrollment  
- iOS as a Behavedr SKU (sandbox cannot host device EDR; see `docs/IOS.md`)
- Kernel-level rootkit defeat  

See also: `docs/PLATFORM_ABI.md`, `docs/OPERATOR_GUIDE.md`, `THREAT_MODEL.md` T-4b.
