namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Detects privilege escalation by finding elevated (admin) processes running
/// from user-writable directories (Temp, Downloads, AppData). Catches UAC bypass (T1548).
/// </summary>
[SupportedOSPlatform("windows")]
public class TokenIntegrityMonitor : IPlatformMonitor
{
    private readonly ILogger<TokenIntegrityMonitor> _logger;
    private readonly HashSet<int> _alertedPids = new();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass,
        IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    private const uint TOKEN_QUERY = 0x0008;
    private const int TokenElevation = 20;

    public string PlatformName => "TokenIntegrityMonitor";
    public bool IsSupported => OperatingSystem.IsWindows();

    public TokenIntegrityMonitor(ILogger<TokenIntegrityMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<TokenIntegrityMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    if (ct.IsCancellationRequested) break;
                    if (proc.Id <= 4) continue;
                    if (_alertedPids.Contains(proc.Id)) continue;

                    if (!OpenProcessToken(proc.Handle, TOKEN_QUERY, out var tokenHandle))
                        continue;

                    try
                    {
                        var elevBuffer = Marshal.AllocHGlobal(4);
                        try
                        {
                            if (GetTokenInformation(tokenHandle, TokenElevation, elevBuffer, 4, out _))
                            {
                                int elevated = Marshal.ReadInt32(elevBuffer);
                                if (elevated != 0)
                                {
                                    string? imagePath = null;
                                    try { imagePath = proc.MainModule?.FileName; } catch { }

                                    if (imagePath != null && IsUserWritablePath(imagePath))
                                    {
                                        signals.Add(new Signal(
                                            $"elevated_from_user_path:{proc.ProcessName}:pid:{proc.Id}:{imagePath}",
                                            75, 0.80));
                                        _alertedPids.Add(proc.Id);
                                    }
                                }
                            }
                        }
                        finally { Marshal.FreeHGlobal(elevBuffer); }
                    }
                    finally { CloseHandle(tokenHandle); }
                }
                catch (System.ComponentModel.Win32Exception) { }
                catch (InvalidOperationException) { }
                catch { }
                finally { proc.Dispose(); }
            }

            if (_alertedPids.Count > 500) _alertedPids.Clear();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[TokenIntegrityMonitor] Scan error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private static bool IsUserWritablePath(string path)
    {
        var lower = path.ToLowerInvariant();
        return lower.Contains(@"\temp\") ||
               lower.Contains(@"\downloads\") ||
               lower.Contains(@"\appdata\") ||
               lower.Contains(@"\users\public\");
    }
}
