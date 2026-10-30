namespace Behavedr.Core.Security;

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Authenticode signature verification service with write-time cache invalidation.
/// Being signed does NOT grant trust or immunity - it lowers detection confidence.
/// Used to harden allowlist decisions beyond name-only matching (T1036.005 defense).
/// </summary>
public class SignerTrustService
{
    private readonly ILogger<SignerTrustService> _logger;
    private readonly ConcurrentDictionary<string, (bool IsSigned, DateTime LastWrite)> _cache = new(StringComparer.OrdinalIgnoreCase);

    public SignerTrustService(ILogger<SignerTrustService>? logger = null)
    {
        _logger = logger ?? NullLogger<SignerTrustService>.Instance;
    }

    /// <summary>
    /// Returns true if the file has a valid Authenticode signature.
    /// Does NOT mean the file is trusted - only that it's signed.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public bool IsSignedFile(string filePath)
    {
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return false;

        if (_cache.TryGetValue(filePath, out var cached))
        {
            try
            {
                var currentWrite = File.GetLastWriteTimeUtc(filePath);
                if (currentWrite == cached.LastWrite) return cached.IsSigned;
                _cache.TryRemove(filePath, out _);
            }
            catch { return cached.IsSigned; }
        }

        bool isSigned = VerifyAuthenticode(filePath);
        DateTime writeTime = DateTime.MinValue;
        try { writeTime = File.GetLastWriteTimeUtc(filePath); } catch { }
        _cache[filePath] = (isSigned, writeTime);
        return isSigned;
    }

    /// <summary>
    /// Returns true if the process at the given PID has a valid Authenticode signature.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public bool IsSignedProcess(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            var path = proc.MainModule?.FileName;
            return !string.IsNullOrEmpty(path) && IsSignedFile(path);
        }
        catch { return false; }
    }

    /// <summary>
    /// Verify a file is in a trusted system path AND is signed.
    /// This is the proper dual-gate for allowlist verification.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public bool IsTrustedSystemBinary(string? filePath)
    {
        if (string.IsNullOrEmpty(filePath)) return false;
        return IsInSystemDirectory(filePath) && IsSignedFile(filePath);
    }

    private static bool IsInSystemDirectory(string path)
    {
        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrEmpty(winDir)) return false;
        var winDirSlash = winDir.TrimEnd('\\') + "\\";
        return path.StartsWith(winDirSlash, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verify Authenticode signature using WinVerifyTrust P/Invoke.
    /// This is a direct native call (~1ms) with no process spawning - cannot be defeated
    /// by PowerShell removal, Constrained Language Mode, or execution policy.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static bool VerifyAuthenticode(string filePath)
    {
        try
        {
            // WINTRUST_ACTION_GENERIC_VERIFY_V2
            var actionId = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = filePath,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero,
            };

            var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            try
            {
                Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

                var trustData = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                    dwUIChoice = 2, // WTD_UI_NONE
                    fdwRevocationChecks = 0, // WTD_REVOKE_NONE (offline-safe)
                    dwUnionChoice = 1, // WTD_CHOICE_FILE
                    pFile = fileInfoPtr,
                    dwStateAction = 0, // WTD_STATEACTION_IGNORE
                    dwProvFlags = 0x00000010, // WTD_CACHE_ONLY_URL_RETRIEVAL (no network)
                };

                // WinVerifyTrust returns 0 (ERROR_SUCCESS) if signature is valid
                long result = WinVerifyTrust(IntPtr.Zero, ref actionId, ref trustData);
                return result == 0;
            }
            finally
            {
                Marshal.FreeHGlobal(fileInfoPtr);
            }
        }
        catch { return false; }
    }

    // WinVerifyTrust P/Invoke declarations
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern long WinVerifyTrust(
        IntPtr hwnd,
        ref Guid pgActionID,
        ref WINTRUST_DATA pWVTData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile; // WINTRUST_FILE_INFO*
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }
}
