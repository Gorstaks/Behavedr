namespace Behavedr.Core.Monitors;

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Credential honeypot (canary) using Windows Credential Manager.
/// Deploys a fake credential at startup. If anyone reads or deletes it, that's
/// a near-zero false positive indicator of credential harvesting.
/// Confidence: 0.98 (only credential dumpers/infostealers would access this).
/// </summary>
[SupportedOSPlatform("windows")]
public class CredentialCanaryMonitor : IPlatformMonitor
{
    private readonly ILogger<CredentialCanaryMonitor> _logger;
    private bool _canaryDeployed;
    private bool _canaryTripped;
    private long? _lastWrittenTime;
    private const string CanaryTarget = "WindowsLive:target=wl_blob:behavedr-internal-svc";
    private const string CanaryUser = "svc-internal@corp.local";

    public string PlatformName => "CredentialCanary";
    public bool IsSupported => OperatingSystem.IsWindows();

    public CredentialCanaryMonitor(ILogger<CredentialCanaryMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<CredentialCanaryMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        if (!_canaryDeployed)
        {
            DeployCanary();
            _canaryDeployed = true;
            _lastWrittenTime = GetCanaryLastWritten();
            return Task.FromResult<IEnumerable<Signal>>(signals);
        }

        // Check if canary credential still exists (deletion detection)
        if (!_canaryTripped && !CanaryExists())
        {
            _canaryTripped = true;
            signals.Add(new Signal("credential_canary_tripped:deleted", 95, 0.98));
            _logger.LogCritical(
                "SECURITY: Credential canary TRIPPED - honeypot credential was accessed/deleted. " +
                "This is a near-certain indicator of credential harvesting activity.");

            // Re-deploy to catch repeated harvesting
            DeployCanary();
            _canaryTripped = false;
        }

        // Check if canary was READ (LastWritten timestamp changes on CredRead in some cases,
        // or we detect enumeration via CredEnumerate by checking if our credential metadata changed)
        if (!_canaryTripped)
        {
            var currentLastWritten = GetCanaryLastWritten();
            if (_lastWrittenTime.HasValue && currentLastWritten.HasValue &&
                currentLastWritten.Value != _lastWrittenTime.Value)
            {
                signals.Add(new Signal("credential_canary_tripped:read_or_modified", 90, 0.95));
                _logger.LogCritical(
                    "SECURITY: Credential canary metadata changed - possible credential read/enumeration detected.");
                _lastWrittenTime = currentLastWritten;
            }
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("windows")]
    private void DeployCanary()
    {
        try
        {
            var cred = new CREDENTIAL
            {
                Type = CRED_TYPE_GENERIC,
                TargetName = CanaryTarget,
                UserName = CanaryUser,
                CredentialBlobSize = 32,
                CredentialBlob = System.Text.Encoding.UTF8.GetBytes("Behavedr-Canary-2026-Do-Not-Use!"),
                Persist = CRED_PERSIST_LOCAL_MACHINE,
                Comment = "Internal service credential (do not modify)"
            };

            if (CredWrite(ref cred, 0))
                _logger.LogInformation("[CredentialCanary] Honeypot credential deployed");
            else
                _logger.LogDebug("[CredentialCanary] Failed to deploy canary credential");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[CredentialCanary] Deploy failed");
        }
    }

    [SupportedOSPlatform("windows")]
    private bool CanaryExists()
    {
        try
        {
            return CredRead(CanaryTarget, CRED_TYPE_GENERIC, 0, out var credPtr) && credPtr != IntPtr.Zero;
        }
        catch { return false; }
    }

    [SupportedOSPlatform("windows")]
    private long? GetCanaryLastWritten()
    {
        try
        {
            if (CredRead(CanaryTarget, CRED_TYPE_GENERIC, 0, out var credPtr) && credPtr != IntPtr.Zero)
            {
                try
                {
                    // Use proper marshaling to read the native CREDENTIAL structure
                    var nativeCred = Marshal.PtrToStructure<NATIVE_CREDENTIAL>(credPtr);
                    return nativeCred.LastWritten;
                }
                finally
                {
                    CredFree(credPtr);
                }
            }
        }
        catch { }
        return null;
    }

    // P/Invoke for Credential Manager
    private const int CRED_TYPE_GENERIC = 1;
    private const int CRED_PERSIST_LOCAL_MACHINE = 2;

    /// <summary>
    /// Native CREDENTIAL structure for reading via PtrToStructure.
    /// Layout matches the Windows SDK CREDENTIALW definition exactly:
    ///   https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NATIVE_CREDENTIAL
    {
        public uint Flags;
        public uint Type;
        public IntPtr TargetName;       // LPWSTR
        public IntPtr Comment;          // LPWSTR
        public long LastWritten;        // FILETIME (8 bytes)
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;   // LPBYTE
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;       // PCREDENTIAL_ATTRIBUTEW
        public IntPtr TargetAlias;      // LPWSTR
        public IntPtr UserName;         // LPWSTR
    }

    /// <summary>
    /// Managed CREDENTIAL structure for CredWrite (uses string marshaling).
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL
    {
        public uint Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public byte[] CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredWrite(ref CREDENTIAL credential, uint flags);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credentialPtr);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern void CredFree(IntPtr buffer);
}
