# iOS is not a Behavedr SKU

**As of 0.4.3**, Behavedr does not ship, test, or support an iOS agent.

## Why

Apple's app sandbox cannot host device EDR:

- No visibility into other apps' processes or files
- No always-on daemon (background modes are short-lived)
- No kill / quarantine / isolate of other apps without MDM + special entitlements
- Network inspection requires a Network Extension, typically on supervised devices

A real phone-control product would be an **MDM client**, not this agent. macOS remains the Apple **endpoint** (kqueue + EndpointSecurity).

## What was removed

- Core iOS monitors and `IosResponseEngine`
- MAUI `Platforms/iOS` host, iOS target frameworks, iOS CI
- "MDM companion" / App Attest / Keychain injection sketches (they were never wired into a detect->score->respond loop)

Historical changelog entries before 0.4.3 describe that sketch. They are not a current product claim.

## Operators

Use MDM (or Apple Business Manager / your MDM vendor) for iPhone and iPad. Do not sideload Behavedr on iOS.
