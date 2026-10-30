# Behavedr Privacy Policy

**Effective date:** 2026-07-25  
**Product:** Behavedr (Android package `com.croatiasecurity.behavedr` and related desktop agents)  
**Publisher:** CroatiaSecurity  

This policy describes how Behavedr handles information on devices where it is installed.

## 1. What Behavedr is

Behavedr is a **behavioral endpoint detection and response (EDR) agent**. It monitors device and app activity **to detect and respond to security threats**. It is intended for security operators, enterprises, and users who deliberately install it for that purpose.

Behavedr on Android runs primarily as a **foreground service** (notification: "Monitoring active"). It is not a consumer social app and does not provide a traditional end-user content feed.

## 2. Data we process on the device

Depending on platform permissions and configuration, Behavedr may process **security telemetry on the device**, including for example:

| Category | Examples | Purpose |
|----------|----------|---------|
| App / package activity | Installed packages, install sources, usage stats (if granted) | Detect sideloading, malware patterns, abuse |
| Process / runtime signals | Limited process and integrity indicators available to the app | Threat detection |
| Network-related signals | Connectivity type, VPN state, local traffic inspection if VPN isolation is enabled | Network threat detection / isolation |
| Device security settings | ADB/developer options, battery optimization, integrity signals | Hardening and anti-tamper |
| Device identifiers for security | Package name, app signing certificate fingerprints, optional Play Integrity tokens | Supply-chain integrity, attestation |
| Diagnostic / forensic logs | Local log files under the app's private storage | Debugging, crash and security forensics |

Processing is for **security protection of the device and the organization that deployed the agent**, not for advertising profiles.

## 3. What we do **not** do by default

- We do **not** sell personal data.
- We do **not** use collected security signals for third-party advertising.
- We do **not** require a public social login to use the core agent.
- End users are **not** asked to configure publisher certificate pins; that is a publisher/operator concern.

## 4. Transmission off the device

### 4.1 Local-first

By default, detection and response run **on the device**. Many signals stay local unless communication or updates are configured.

### 4.2 Optional management / updates

If an operator enables **management communication** or update channels, the agent may contact configured endpoints (for example operator-controlled servers, or published update URLs such as GitHub Releases / `api.croatiasecurity.com` when used) to:

- fetch **signed** configuration or policy,
- check for **application updates**,
- optionally submit **security events** to a management server the operator controls.

What leaves the device in that mode is limited to **security and operational data** needed for EDR (e.g. detection events, device/app identifiers for the managed asset, version information)-not advertising identifiers for marketing.

### 4.3 Play Integrity (optional)

If Play Integrity attestation is enabled, Google's Play Integrity API may process attestation-related data under Google's terms. Operators may optionally verify attestations on their own server.

## 5. Android permissions (high level)

Behavedr may request permissions required for EDR functions, such as:

- Internet / network state (updates, optional management, integrity)
- Foreground service and notifications (keep the agent running)
- Boot completed / alarms / wake lock (persistence after reboot)
- Usage access / query packages (app behavior and install analysis, when granted)
- VPN service (optional network isolation / inspection)
- Device admin / device owner (enterprise response features, when enrolled)
- Location or phone state **only if declared and used for security checks** on a given build-see the app's runtime permission prompts and Play Data safety form for the current build

Permissions that are not granted simply disable the related detection or response feature.

## 6. Children

Behavedr is **not directed at children under 13** (or the equivalent minimum age in your jurisdiction). It is a security agent, typically deployed by adults or organizations.

## 7. Data retention

- **On device:** local logs and self-pins remain until the app is uninstalled or the operator clears app data.
- **On operator servers:** retention is controlled by the organization running the management server, not by the open-source agent alone.
- **Publisher (CroatiaSecurity):** we do not operate a mandatory global telemetry backend for every install. If you use only sideloaded/GitHub builds with communication disabled, security processing can remain local.

## 8. Security measures

We design Behavedr with security controls such as:

- signed updates (where configured),
- package signing certificate checks,
- optional Play Integrity,
- least-privilege design for response actions (avoid self-harm / wrong-target kills).

No method is 100% secure; physical access, root/compromise, or OEM limitations may reduce effectiveness.

## 9. Your choices

- Uninstall the app to stop processing and remove ordinary app-private storage (subject to Android behavior).
- Revoke permissions in system settings to limit monitoring scope.
- Enterprise Device Owner enrollments may have additional admin policies controlled by the organization.

## 10. International operators

If an organization deploys Behavedr across regions, that organization is responsible for lawful basis, employee/user notice, and cross-border transfer rules for any events their servers receive.

## 11. Changes

We may update this policy when product behavior changes. The **Effective date** at the top will change. Continued use after an update means you accept the revised policy for new processing, where permitted by law.

## 12. Contact

Privacy and security contact:

- **Email:** security@croatiasecurity.com  
- **Project:** https://github.com/CroatiaSecurity/Behavedr  
- **Security policy:** https://github.com/CroatiaSecurity/Behavedr/blob/main/SECURITY.md  

For Google Play Data safety questions about a specific release, contact the same address and include the app version.

---

*This document is provided for transparency and Play Console compliance. It is not legal advice. Organizations deploying Behavedr should have counsel review deployment-specific notices.*
