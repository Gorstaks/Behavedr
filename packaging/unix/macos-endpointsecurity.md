# macOS EndpointSecurity packaging (0.3.3 production)

Behavedr uses a **native ring-buffer bridge** (`libbehavedr_es.dylib`). The managed
monitor **polls** events; the ES callback never calls into the GC.

Without the dylib + entitlement, **kqueue** remains the real-time path.

## Components

| Piece | Path |
|-------|------|
| Managed monitor | `MacOSEndpointSecurityMonitor` (poll ABI + JSONL fallback) |
| Native bridge | `native/macos/es_bridge/behavedr_es_bridge.c` |
| ES host binary | `native/macos/SystemExtension/` |
| Install dylib | `/opt/behavedr/libbehavedr_es.dylib` |
| Host JSONL | `/var/run/behavedr/es.events` (override `BEHAVEDR_ES_EVENTS_PATH`) |

### Activation order (agent)

1. **In-process dylib** if `libbehavedr_es.dylib` loads and `es_new_client` succeeds  
2. Else **JSONL host fallback** if the ES host is writing events  
3. Else soft-fail -> **kqueue** remains primary

## Build bridge

```bash
clang -dynamiclib -O2 -o libbehavedr_es.dylib native/macos/es_bridge/behavedr_es_bridge.c \
  -framework EndpointSecurity -framework CoreFoundation
install_name_tool -id @rpath/libbehavedr_es.dylib libbehavedr_es.dylib
sudo mkdir -p /opt/behavedr
sudo cp libbehavedr_es.dylib /opt/behavedr/
# Sign dylib + agent with ES client entitlement
```

## Entitlement

The **agent process** (or a System Extension host) needs:

```xml
<key>com.apple.developer.endpoint-security.client</key>
<true/>
```

This requires an Apple Developer Program capability request. Unsigned/local builds
will see `es_new_client` fail - that is expected; kqueue continues to operate.

## Full Disk Access

Grant FDA to `/opt/behavedr/Behavedr` in System Settings -> Privacy & Security.

## AUTH mode (optional)

Set `BEHAVEDR_ES_AUTH=1` to subscribe AUTH_EXEC/AUTH_OPEN. The bridge **allows by
default** and **denies** only a conservative denylist (`/tmp` droppers, known tool
name substrings). Without the env var, subscription is NOTIFY-only.

## Production shape (optional System Extension)

For enterprise-hardened deployment, host the ES client inside an Endpoint Security
**System Extension** and XPC to the agent. See `macos-system-extension.md`.
The bridge API (`behavedr_es_*`) is intentionally small so it can live in the extension.

## Verification

Agent log on success:

```
[ES] Active - poll mode, events=..., auth=...
```

On failure (no entitlement / no dylib):

```
[ES] es_new_client failed ... kqueue path remains active
```

or

```
[ES] libbehavedr_es.dylib not found ... kqueue remains primary
```
