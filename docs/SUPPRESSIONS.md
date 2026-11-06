# Operator suppressions

Use `suppressions.json` next to `Behavedr.exe` to silence a specific, reviewed false positive.
The agent loads it at startup. Without the file, no suppressions apply.

```json
{
  "rules": [
    {
      "processName": "installer",
      "imagePath": "C:\\Program Files\\ExampleVendor\\installer.exe",
      "signalPrefix": "short_lived_powershell",
      "reason": "Vendor installer launches short PowerShell helpers. Reviewed 2026-11-06."
    }
  ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `imagePath` | yes | Absolute path of the approved binary. Matched case-insensitively. |
| `signalPrefix` | yes | Start of the signal type to drop, for example `short_lived_powershell`. |
| `reason` | yes | Why the rule exists. Rules without a reason are ignored. |
| `processName` | no | Process base name, checked in addition to the path. |

## Guarantees

- A signal is dropped only when the process image matches `imagePath` and the file has a valid
  Authenticode signature. Unsigned binaries, and binaries in temp or download folders, never match.
- President's Law categories (credential access, injection, ransomware, evasion, C2, and similar)
  are never suppressed, whatever the file says.
- Suppressed signals are counted in the `behavedr.signals.suppressed` metric, so the effect of each rule
  stays visible.

A rule matches any validly signed file at its path, so re-check each rule after the vendor upgrades
the binary.
