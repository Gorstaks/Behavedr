# Android release signing (publisher only)

End users never touch this. They only install the APK.

## Baked cert pin

SHA-256 of `behavedr-release.cert` (DER):

```
7581EDDD52412F72786AA9B3274B5855801FF73293EC97DB2FBBCE8F5988B66F
```

Embedded in `AndroidCertPins.BakedInPins`.

## Files

| File | Commit? | Purpose |
|------|---------|---------|
| `behavedr-release.cert.pem` | Yes (public) | Release certificate |
| `behavedr-release.sha256.txt` | Yes (public) | Fingerprint |
| `behavedr-release.p12` | **No** | PKCS#12 keystore - local / CI secret |
| `behavedr-release.key.pem` | **No** | Private key |
| `behavedr-release.password.txt` | **No** | Keystore password |

## Sign a release APK

On a machine with the private keystore (not in git):

```bash
# jarsigner / apksigner example with PKCS#12
apksigner sign --ks behavedr-release.p12 --ks-key-alias behavedr \
  --ks-pass file:behavedr-release.password.txt \
  --out Behavedr-release.apk Behavedr-unsigned.apk

apksigner verify --print-certs Behavedr-release.apk
# SHA-256 must match the pin above
```

## GitHub Actions secrets (auto-sign on release)

Release workflow (`release.yml`) **automatically re-signs** the APK when these
secrets exist. No user action at install time.

| Secret | Value |
|--------|--------|
| `ANDROID_KEYSTORE_BASE64` | base64 of `behavedr-release.p12` |
| `ANDROID_KEYSTORE_PASSWORD` | contents of `behavedr-release.password.txt` |
| `ANDROID_KEY_ALIAS` | `behavedr` (optional; defaulted in workflow) |
| `ANDROID_KEY_PASSWORD` | same as keystore password if omitted |

### Upload secrets (from this machine)

```powershell
# From repo root, with GitHub CLI authenticated:
$ks = "keys/android/behavedr-release.p12"
$pw = Get-Content -Raw "keys/android/behavedr-release.password.txt"
$b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Resolve-Path $ks)))
$b64 | gh secret set ANDROID_KEYSTORE_BASE64 --repo CroatiaSecurity/Behavedr
$pw  | gh secret set ANDROID_KEYSTORE_PASSWORD --repo CroatiaSecurity/Behavedr
"behavedr" | gh secret set ANDROID_KEY_ALIAS --repo CroatiaSecurity/Behavedr
$pw  | gh secret set ANDROID_KEY_PASSWORD --repo CroatiaSecurity/Behavedr
```

After that, every `v*` tag / release workflow run produces
`Behavedr-<version>-android.apk` signed with this keystore (matches baked pin).

## Recreate keystore (only if compromised)

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout behavedr-release.key.pem -out behavedr-release.cert.pem \
  -subj "/CN=Behavedr Android Release/O=CroatiaSecurity/OU=Mobile/C=HR"
openssl pkcs12 -export -inkey behavedr-release.key.pem -in behavedr-release.cert.pem \
  -name behavedr -out behavedr-release.p12
openssl x509 -in behavedr-release.cert.pem -outform DER -out behavedr-release.cert.der
openssl dgst -sha256 -hex behavedr-release.cert.der
# Update AndroidCertPins.BakedInPins with the new fingerprint
```
