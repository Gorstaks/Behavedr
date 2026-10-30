# Behavedr Endpoint Security System Extension (0.3.3)

Production ES host for enterprise packaging. Not a placeholder.

## Build

```bash
./build.sh
# optional: MACOS_CODESIGN_IDENTITY="Developer ID Application: ..." ./build.sh
```

Output: `dist/com.croatiasecurity.behavedr.es.systemextension`

## Runtime

- ES client with NOTIFY (+ AUTH if `BEHAVEDR_ES_AUTH=1`)
- JSONL events: `/var/run/behavedr/es.events`
- Requires Apple ES entitlement + user approval of the system extension

See `packaging/unix/macos-system-extension.md` for full operator notes.
