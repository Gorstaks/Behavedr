# Platform monitors

Registered at runtime via `PlatformMonitors` / `AgentBootstrap` when `IsSupported` is true.

| Monitor | OS | Notes |
|---------|-----|-------|
| WindowsMonitor | Windows | Base process heuristics |
| DriverLoadMonitor | Windows | BYOVD / vulnerable driver (v0.2.2, Sentinel-inspired) |
| LinuxMonitor | Linux | Base process heuristics |
| LinuxKernelModuleMonitor | Linux | New/suspicious kernel module loads (v0.2.3) |
| LinuxAuthMonitor | Linux | auth.log/secure failure bursts + root sessions (v0.2.3) |
| MacOSMonitor | macOS | Base process heuristics |
| MacOSKqueueMonitor | macOS | Real-time process events (500ms discovery) |
| MacOSFileEventMonitor | macOS | VNODE watches on persistence/tmp paths (v0.2.3) |
| MacOSCodeSignMonitor | macOS | codesign self + LaunchDaemon scan (v0.2.3) |
| AndroidMonitor | Android | Root/process + platform signal injection |
| + many specialized monitors | per-OS | See `PlatformMonitors.BuildMonitorList` |

iOS is not a Behavedr SKU. See `docs/IOS.md`.
