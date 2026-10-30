# macOS Endpoint Security System Extension (0.3.4)

## Honest status

In-tree we ship a **real Endpoint Security host binary** (subscribes, AUTH_EXEC,
JSONL publisher) plus a **bundle shell** (`Info.plist`, entitlements, `build.sh`).

We do **not** yet ship a complete installable System Extension product
(`OSSystemExtensionRequest`, notarized app container, agent XPC consumer).
Release engineering still owns Apple enrollment + activation UX.

For enterprise deployment beyond an entitled agent process, the host is the
starting point for that work.

## What ships in-tree

| Piece | Path |
|-------|------|
| Host source | `native/macos/SystemExtension/main.m` |
| Entitlements | `native/macos/SystemExtension/entitlements.plist` |
| Bundle Info | `native/macos/SystemExtension/Info.plist` |
| Build | `native/macos/SystemExtension/build.sh` |
| In-process ABI (agent) | `native/macos/es_bridge/behavedr_es_bridge.c` |

## Host behavior

1. `es_new_client` + subscribe NOTIFY_EXEC/FORK/EXIT/OPEN/CREATE/WRITE/RENAME  
2. Optional AUTH_EXEC/AUTH_OPEN when `BEHAVEDR_ES_AUTH=1` (conservative denylist)  
3. AUTH answered on the ES callback thread  
4. Events published as **JSONL** to `/var/run/behavedr/es.events`  
   (override with `BEHAVEDR_ES_EVENTS_PATH`)  
5. stderr mirror for diagnostics  

## Layout (recommended)

```
Behavedr.app/
  Contents/MacOS/Behavedr          # agent
  Contents/Library/SystemExtensions/
    com.croatiasecurity.behavedr.es.systemextension
```

## Entitlements

- `com.apple.developer.endpoint-security.client`
- `com.apple.developer.system-extension.install`

These require Apple Developer Program capability approval. Unsigned local builds
will see `es_new_client` fail - expected; kqueue remains the agent's primary path.

## Build

```bash
cd native/macos/SystemExtension
export MACOS_CODESIGN_IDENTITY="Developer ID Application: ..."   # optional but required for field
./build.sh
# -> dist/com.croatiasecurity.behavedr.es.systemextension
```

Or from repo root: `./native/build-native.sh dist/native` (on Darwin).

## Activation

```bash
systemextensionsctl list
# User must approve in System Settings -> Privacy & Security -> System Extensions
```

## Bridge vs System Extension

| Mode | When |
|------|------|
| **In-process dylib** | Agent binary is entitled + `libbehavedr_es.dylib` present |
| **System Extension host** | ES entitlement lives in the extension; agent reads JSONL / future XPC |

The C ABI (`behavedr_es_*`) is intentionally small so the same event model can move
into the extension process. Full App-container XPC service generation is release-
engineering work against Apple's current System Extension templates; the host
binary itself is production-grade event capture.

## AUTH mode

```bash
export BEHAVEDR_ES_AUTH=1
```

Denies only high-confidence paths (`/tmp` droppers, known tool name substrings).
Default is NOTIFY-only telemetry.
