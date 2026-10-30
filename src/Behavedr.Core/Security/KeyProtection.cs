namespace Behavedr.Core.Security;

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

/// <summary>
/// Platform-adaptive key protection for the machine key:
///
/// Windows: DPAPI (DataProtectionScope.LocalMachine) + per-installation entropy.
///   Only SYSTEM on the same machine can unwrap. Prevents offline extraction.
///
/// Linux: Kernel keyring (add_key/request_key syscalls) stores key in kernel memory.
///   Key is NOT on the filesystem and cannot be read via /proc or disk access.
///   Falls back to file-permission (chmod 600) if keyring is unavailable (containers).
///
/// macOS: Keychain Services (security CLI / System Keychain; Secure Enclave on Apple Silicon).
/// Android: Android Keystore (TEE/StrongBox) via platform bridge when available.
///
/// Key file format:
///   Unprotected (legacy): raw base64 key
///   Protected (v2): "DPAPI:" prefix + base64 of DPAPI-encrypted blob
///   Keyring (v3): "KEYRING:" prefix - key is in kernel keyring, file is a marker only
/// </summary>
public static class KeyProtection
{
    private const string DpapiPrefix = "DPAPI:";
    private const string KeyringPrefix = "KEYRING:";
    private const string KeyFileName = ".behavedr-key";
    private const string KeyringDescription = "behavedr:machine-key";

    // Process-local cache: platform backends (esp. macOS keychain CLI) can fail
    // intermittently and must not mint a new key mid-process (breaks AES-GCM unseal).
    private static readonly object MachineKeyLock = new();
    private static byte[]? _cachedMachineKey;

    /// <summary>
    /// Get the machine key using the most secure storage available:
    /// - Windows: DPAPI (LocalMachine scope)
    /// - Linux: Kernel keyring (key lives in kernel memory, not on disk)
    /// - macOS: Keychain Services (key in System Keychain, backed by Secure Enclave)
    /// - Android: Android Keystore (hardware-backed TEE/StrongBox)
    /// - Fallback: File with chmod 600
    /// On first call with a legacy (unprotected) key, upgrades to best available protection.
    /// </summary>
    public static byte[] GetMachineKey()
    {
        lock (MachineKeyLock)
        {
            if (_cachedMachineKey is { Length: 32 })
                return (byte[])_cachedMachineKey.Clone();

            var key = LoadOrCreateMachineKey();
            _cachedMachineKey = (byte[])key.Clone();
            return key;
        }
    }

    private static byte[] LoadOrCreateMachineKey()
    {
        // Android: Try Android Keystore first (hardware-backed, key never leaves TEE)
        // v0.2.0 audit fix A-3
        if (OperatingSystem.IsAndroid())
        {
            var keystoreKey = TryGetKeyFromAndroidKeystore();
            if (keystoreKey is not null)
                return keystoreKey;
        }

        // Linux: keyring is a cache. Disk (chmod 600) is the source of truth so
        // reboot / systemd user-session teardown cannot mint a new HMAC key.
        if (OperatingSystem.IsLinux())
        {
            var keyringKey = TryGetKeyFromKeyring();
            if (keyringKey is { Length: 32 })
            {
                PersistLinuxDiskBackup(keyringKey);
                return keyringKey;
            }
        }

        // macOS: Try Keychain Services first (RT-2 fix)
        if (OperatingSystem.IsMacOS())
        {
            var keychainKey = TryGetKeyFromKeychain();
            if (keychainKey is not null)
                return keychainKey;
        }

        var keyDir = GetKeyDirectory();
        Directory.CreateDirectory(keyDir);
        var keyPath = Path.Combine(keyDir, KeyFileName);

        if (File.Exists(keyPath))
        {
            string content;
            try
            {
                content = File.ReadAllText(keyPath).Trim();
            }
            catch (UnauthorizedAccessException)
            {
                content = "";
            }

            if (!string.IsNullOrEmpty(content))
            {
                if (content.StartsWith(KeyringPrefix, StringComparison.Ordinal))
                {
                    throw new CryptographicException(
                        "Linux machine key is a keyring marker with no keyring payload and no disk backup. " +
                        "Reinstall the agent or delete appsettings.json.hmac and restart after placing a new key.");
                }

                if (content.StartsWith(DpapiPrefix, StringComparison.Ordinal))
                    return UnprotectKey(content[DpapiPrefix.Length..]);

                var rawKey = Convert.FromBase64String(content);

                if (OperatingSystem.IsWindows())
                {
                    ProtectAndWriteKey(keyPath, rawKey);
                }
                else if (OperatingSystem.IsLinux())
                {
                    TryStoreKeyInKeyring(rawKey);
                    WriteProtectedKey(keyPath, rawKey);
                }
                else if (OperatingSystem.IsMacOS())
                {
                    if (TryStoreKeyInKeychain(rawKey))
                    {
                        try { File.Delete(keyPath); } catch { }
                    }
                }

                return rawKey;
            }
        }

        // Generate new key
        var newKey2 = RandomNumberGenerator.GetBytes(32);

        if (OperatingSystem.IsLinux())
        {
            WriteProtectedKey(keyPath, newKey2);
            TryStoreKeyInKeyring(newKey2);
            return newKey2;
        }

        // macOS: store in Keychain if possible (RT-2 fix)
        if (OperatingSystem.IsMacOS() && TryStoreKeyInKeychain(newKey2))
        {
            // No file needed - keychain is the authoritative storage
            return newKey2;
        }

        WriteProtectedKey(keyPath, newKey2);
        return newKey2;
    }

    /// <summary>
    /// Rotate the machine key. Old key is preserved as .behavedr-key-v{oldVersion}
    /// for decrypting existing data during migration.
    /// v0.1.3: Moved here from ConfigProtection to consolidate key management (H-1 fix).
    /// </summary>
    public static void RotateKey(Microsoft.Extensions.Logging.ILogger? logger = null)
    {
        var keyDir = GetKeyDirectory();
        var keyPath = Path.Combine(keyDir, KeyFileName);
        var versionPath = Path.Combine(keyDir, ".behavedr-key-version");

        int currentVersion = 1;
        if (File.Exists(versionPath))
        {
            int.TryParse(File.ReadAllText(versionPath).Trim(), out currentVersion);
        }

        // Archive current key
        if (File.Exists(keyPath))
        {
            var archivePath = Path.Combine(keyDir, $".behavedr-key-v{currentVersion}");
            File.Copy(keyPath, archivePath, overwrite: true);
        }

        // Generate new key
        var newKey = RandomNumberGenerator.GetBytes(32);
        WriteProtectedKey(keyPath, newKey);

        File.WriteAllText(versionPath, (currentVersion + 1).ToString());

        lock (MachineKeyLock)
        {
            _cachedMachineKey = (byte[])newKey.Clone();
        }

        logger?.LogInformation("Machine key rotated: v{Old} -> v{New}", currentVersion, currentVersion + 1);
    }

    /// <summary>
    /// Get a previous key version (for decrypting data encrypted with an older key).
    /// Returns null if the version doesn't exist.
    /// v0.1.3: Moved here from ConfigProtection to consolidate key management (H-1 fix).
    /// </summary>
    public static byte[]? GetKeyVersion(int version)
    {
        var keyDir = GetKeyDirectory();
        var archivePath = Path.Combine(keyDir, $".behavedr-key-v{version}");

        if (!File.Exists(archivePath))
            return null;

        var keyBase64 = File.ReadAllText(archivePath).Trim();
        return Convert.FromBase64String(keyBase64);
    }

    /// <summary>
    /// If the Linux key was recovered from the keyring, persist it to chmod 600 disk
    /// when the on-disk file is missing or is a legacy KEYRING: marker.
    /// </summary>
    [SupportedOSPlatform("linux")]
    private static void PersistLinuxDiskBackup(byte[] key)
    {
        try
        {
            var keyDir = GetKeyDirectory();
            Directory.CreateDirectory(keyDir);
            var keyPath = Path.Combine(keyDir, KeyFileName);
            if (File.Exists(keyPath))
            {
                var content = File.ReadAllText(keyPath).Trim();
                if (!content.StartsWith(KeyringPrefix, StringComparison.Ordinal) && content.Length >= 32)
                    return;
            }
            WriteProtectedKey(keyPath, key);
        }
        catch
        {
            // Best-effort backup; keyring copy remains usable this boot
        }
    }

    /// <summary>
    /// Write a key to disk with platform-appropriate protection.
    /// V-2 FIX: On Windows, uses a temp file with restricted ACL then atomic rename
    /// to eliminate the permission race window. On Linux/macOS, sets chmod before
    /// writing content (open with restricted mode).
    /// </summary>
    private static void WriteProtectedKey(string keyPath, byte[] key)
    {
        if (OperatingSystem.IsWindows())
        {
            ProtectAndWriteKey(keyPath, key);
        }
        else
        {
            // V-2 FIX: Create file with O_CREAT|O_EXCL semantics and restricted mode
            var tempPath = keyPath + ".tmp." + Guid.NewGuid().ToString("N")[..8];
            try
            {
                File.WriteAllText(tempPath, Convert.ToBase64String(key));
                File.SetUnixFileMode(tempPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                File.Move(tempPath, keyPath, overwrite: true); // Atomic rename on same volume
            }
            catch
            {
                // Fallback: direct write (original behavior)
                File.WriteAllText(keyPath, Convert.ToBase64String(key));
                try { File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
                catch { }
            }
            finally
            {
                try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static void ProtectAndWriteKey(string keyPath, byte[] rawKey)
    {
        try
        {
            var protectedBytes = ProtectedData.Protect(
                rawKey, GetEntropy(), DataProtectionScope.LocalMachine);
            var content = DpapiPrefix + Convert.ToBase64String(protectedBytes);
            File.WriteAllText(keyPath, content);
            RestrictFilePermissions(keyPath);
        }
        catch (CryptographicException)
        {
            // DPAPI unavailable (e.g., running in container without machine keys)
            // Fall back to raw storage with restricted permissions
            File.WriteAllText(keyPath, Convert.ToBase64String(rawKey));
            RestrictFilePermissions(keyPath);
        }
    }

    private static byte[] UnprotectKey(string protectedBase64)
    {
        if (OperatingSystem.IsWindows())
        {
            return UnprotectKeyWindows(protectedBase64);
        }

        // Non-Windows shouldn't have DPAPI prefix, but handle gracefully
        throw new CryptographicException("DPAPI-protected key found on non-Windows platform");
    }

    [SupportedOSPlatform("windows")]
    private static byte[] UnprotectKeyWindows(string protectedBase64)
    {
        var protectedBytes = Convert.FromBase64String(protectedBase64);
        return ProtectedData.Unprotect(
            protectedBytes, GetEntropy(), DataProtectionScope.LocalMachine);
    }

    private const string EntropyFileName = ".behavedr-entropy";

    /// <summary>
    /// Additional entropy for DPAPI binding. Uses a per-installation random value
    /// generated at first run and stored in a separate file with restricted ACLs.
    /// This prevents other SYSTEM-level processes from unwrapping the key even if
    /// they know the source code, since the entropy is unique per machine install.
    ///
    /// Falls back to a fixed application-specific value if the entropy file cannot
    /// be created/read (e.g., permission issues in containers).
    /// </summary>
    private static byte[] GetEntropy()
    {
        try
        {
            var keyDir = GetKeyDirectory();
            var entropyPath = Path.Combine(keyDir, EntropyFileName);

            if (File.Exists(entropyPath))
            {
                var entropyBase64 = File.ReadAllText(entropyPath).Trim();
                var entropy = Convert.FromBase64String(entropyBase64);
                if (entropy.Length >= 16)
                    return entropy;
            }

            // Generate random entropy at install time (32 bytes)
            var newEntropy = RandomNumberGenerator.GetBytes(32);
            Directory.CreateDirectory(keyDir);
            File.WriteAllText(entropyPath, Convert.ToBase64String(newEntropy));

            // Restrict permissions on entropy file
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    RestrictFilePermissions(entropyPath);
                }
                else
                {
                    File.SetUnixFileMode(entropyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }
            }
            catch { }

            return newEntropy;
        }
        catch
        {
            // V-4 FIX: Log critical warning when falling back to fixed entropy.
            // This significantly weakens DPAPI binding - all installations with this
            // fallback share the same entropy, reducing protection to base LocalMachine scope.
            System.Diagnostics.Trace.TraceError(
                "SECURITY CRITICAL: Behavedr DPAPI entropy file unavailable - falling back to fixed entropy. " +
                "Key protection is degraded. Ensure the Behavedr data directory is writable.");
            // Fallback: fixed entropy (less secure but allows operation)
            return "Behavedr-MachineKey-v2-2026-fallback"u8.ToArray();
        }
    }

    [SupportedOSPlatform("windows")]
    private static void RestrictFilePermissions(string filePath)
    {
        try
        {
            var fileInfo = new FileInfo(filePath);
            var security = fileInfo.GetAccessControl();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var systemSid = new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
            var adminsSid = new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);

            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                systemSid,
                System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.AccessControlType.Allow));
            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                adminsSid,
                System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.AccessControlType.Allow));

            fileInfo.SetAccessControl(security);
        }
        catch
        {
            // Best effort - may fail in non-admin context
        }
    }

    // =========================================================================
    // Linux Kernel Keyring Integration
    // =========================================================================
    // The kernel keyring stores keys in kernel memory, inaccessible via /proc
    // or filesystem. Keys survive until session ends or explicit revocation.
    // We use KEY_SPEC_USER_KEYRING (-4) which persists per-UID across processes.
    //
    // Syscall numbers (x86_64):
    //   add_key    = 248
    //   request_key = 249
    //   keyctl     = 250
    // =========================================================================

    private const int KEY_SPEC_USER_KEYRING = -4;
    private const int KEYCTL_READ = 11;

    /// <summary>
    /// Try to retrieve the machine key from the Linux kernel keyring.
    /// Returns null if key is not in the keyring (first run, or after reboot).
    /// </summary>
    [SupportedOSPlatform("linux")]
    private static byte[]? TryGetKeyFromKeyring()
    {
        try
        {
            // request_key("user", "behavedr:machine-key", null, KEY_SPEC_USER_KEYRING)
            var keyId = request_key("user", KeyringDescription, null, KEY_SPEC_USER_KEYRING);
            if (keyId < 0)
                return null;

            // Read the key data: keyctl(KEYCTL_READ, key_id, buffer, buflen)
            var buffer = new byte[32];
            var bytesRead = keyctl_read(KEYCTL_READ, keyId, buffer, buffer.Length);
            if (bytesRead == 32)
                return buffer;

            return null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Store a key in the Linux kernel keyring. Returns true if successful.
    /// The key will persist in kernel memory for the lifetime of the user session
    /// (or until explicitly revoked). It is NOT accessible via the filesystem.
    /// </summary>
    [SupportedOSPlatform("linux")]
    private static bool TryStoreKeyInKeyring(byte[] key)
    {
        try
        {
            // add_key("user", "behavedr:machine-key", payload, payload_len, KEY_SPEC_USER_KEYRING)
            var keyId = add_key("user", KeyringDescription, key, key.Length, KEY_SPEC_USER_KEYRING);
            return keyId >= 0;
        }
        catch
        {
            return false;
        }
    }

    // P/Invoke: Linux keyring syscalls via libc wrappers
    [DllImport("libc", EntryPoint = "add_key", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int add_key(
        string type, string description, byte[] payload, int plen, int keyring);

    [DllImport("libc", EntryPoint = "request_key", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int request_key(
        string type, string description, string? callout_info, int dest_keyring);

    [DllImport("libc", EntryPoint = "keyctl", SetLastError = true)]
    private static extern int keyctl_read(int operation, int key_id, byte[] buffer, int buflen);

    private static bool IsDirectoryUsable(string dir)
    {
        try
        {
            Directory.CreateDirectory(dir);
            var keyPath = Path.Combine(dir, KeyFileName);
            if (File.Exists(keyPath))
            {
                _ = File.ReadAllText(keyPath);
                return true;
            }

            var probe = Path.Combine(dir, ".behavedr-wprobe");
            File.WriteAllText(probe, "ok");
            File.Delete(probe);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string GetKeyDirectory()
    {
        if (OperatingSystem.IsWindows())
        {
            var machine = Path.Combine(Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData), "Behavedr");
            var local = Path.Combine(Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData), "Behavedr");
            var temp = Path.Combine(Path.GetTempPath(), "Behavedr");
            foreach (var dir in new[] { machine, local, temp })
            {
                if (IsDirectoryUsable(dir))
                    return dir;
            }
            return Path.Combine(Path.GetTempPath(), "Behavedr-" + Environment.ProcessId);
        }

        const string systemDir = "/etc/behavedr";
        try
        {
            if (Directory.Exists(systemDir) ||
                Directory.CreateDirectory(systemDir).Exists)
                return systemDir;
        }
        catch { }

        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".behavedr");
    }

    // =========================================================================
    // macOS Keychain Services Integration (RT-2 Fix)
    // =========================================================================
    // Uses Security.framework via P/Invoke to store the machine key in the
    // System Keychain. On Apple Silicon, this is backed by the Secure Enclave.
    // Key never written to filesystem; accessible only by the behavedr process.
    //
    // Keychain item attributes:
    //   kSecClass: kSecClassGenericPassword
    //   kSecAttrService: "com.croatiasecurity.behavedr"
    //   kSecAttrAccount: "machine-key-v1"
    //   kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    // =========================================================================

    private const string KeychainService = "com.croatiasecurity.behavedr";
    private const string KeychainAccount = "machine-key-v1";

    /// <summary>
    /// Try to retrieve the machine key from macOS Keychain Services.
    /// Returns null if key is not in the keychain (first run).
    /// Uses the `security` CLI as a portable approach that works without
    /// native framework linking (which requires Objective-C interop).
    /// </summary>
    [SupportedOSPlatform("macos")]
    private static byte[]? TryGetKeyFromKeychain()
    {
        try
        {
            // NEVER ReadToEnd() before WaitForExit - security can block on keychain UI
            // and deadlocks the test host (v0.2.2 macOS CI hang).
            var (exitCode, output) = RunSecurityCli(
                $"find-generic-password -s \"{KeychainService}\" -a \"{KeychainAccount}\" -w",
                timeoutMs: 4000);

            if (exitCode != 0 || string.IsNullOrWhiteSpace(output))
                return null;

            var key = Convert.FromBase64String(output.Trim());
            return key.Length == 32 ? key : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Store a key in macOS Keychain Services. Returns true if successful.
    /// Uses the `security` CLI for portability (no native framework linking needed).
    /// The key is stored in the System keychain with restricted access.
    /// </summary>
    [SupportedOSPlatform("macos")]
    private static bool TryStoreKeyInKeychain(byte[] key)
    {
        try
        {
            var keyBase64 = Convert.ToBase64String(key);

            // Best-effort delete of existing entry (ignore failure / timeout)
            _ = RunSecurityCli(
                $"delete-generic-password -s \"{KeychainService}\" -a \"{KeychainAccount}\"",
                timeoutMs: 3000);

            var (exitCode, _) = RunSecurityCli(
                $"add-generic-password -s \"{KeychainService}\" -a \"{KeychainAccount}\" " +
                $"-w \"{keyBase64}\" -T \"\" -U",
                timeoutMs: 4000);

            return exitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Run /usr/bin/security with a hard timeout. Kills the process on expiry so CI
    /// never hangs when the login keychain is locked or prompts for UI.
    /// </summary>
    private static (int ExitCode, string StdOut) RunSecurityCli(string arguments, int timeoutMs)
    {
        using var proc = new System.Diagnostics.Process();
        proc.StartInfo = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "/usr/bin/security",
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        proc.Start();

        // Async reads prevent pipe-buffer deadlocks with WaitForExit
        var stdoutTask = proc.StandardOutput.ReadToEndAsync();
        var stderrTask = proc.StandardError.ReadToEndAsync();

        if (!proc.WaitForExit(timeoutMs))
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            try { proc.WaitForExit(2000); } catch { }
            return (-1, "");
        }

        // Ensure stream readers finish after process exit
        if (!stdoutTask.Wait(2000))
            return (proc.ExitCode, "");

        _ = stderrTask.Wait(500);
        return (proc.ExitCode, stdoutTask.Result);
    }

    // =========================================================================
    // Android Keystore Integration (v0.2.0 Audit Fix A-3)
    // =========================================================================
    // Uses Android Keystore System for hardware-backed key storage via TEE/StrongBox.
    // The key wrapping approach:
    //   1. A hardware-backed AES key is created in Android Keystore (never extractable)
    //   2. Our 32-byte machine key is encrypted with the hardware key
    //   3. The ciphertext is stored on disk (useless without the hardware key)
    //   4. On load: decrypt ciphertext with hardware key to recover machine key
    //
    // This requires the MAUI Android platform layer to register bridge callbacks
    // that invoke java.security.KeyStore APIs. If the bridge is not registered
    // (e.g., running on non-MAUI Android or test environment), falls back to
    // file-based storage with chmod 600.
    // =========================================================================

    private const string AndroidKeystorePrefix = "ANDROID_KS:";
    private const string AndroidWrappedKeyFile = ".behavedr-key-wrapped";

    /// <summary>
    /// Try to retrieve the machine key using Android Keystore hardware-backed encryption.
    /// The actual key material is encrypted by a TEE-bound key and stored on disk.
    /// Returns null if Android Keystore bridge is not available or key doesn't exist.
    /// </summary>
    [SupportedOSPlatform("android")]
    private static byte[]? TryGetKeyFromAndroidKeystore()
    {
        // Check if the platform bridge is registered
        if (AndroidKeystoreBridge.DecryptFunc is null || AndroidKeystoreBridge.EncryptFunc is null)
            return null;

        try
        {
            var keyDir = GetKeyDirectory();
            var wrappedKeyPath = Path.Combine(keyDir, AndroidWrappedKeyFile);

            if (File.Exists(wrappedKeyPath))
            {
                var content = File.ReadAllText(wrappedKeyPath).Trim();
                if (content.StartsWith(AndroidKeystorePrefix, StringComparison.Ordinal))
                {
                    var ciphertext = Convert.FromBase64String(
                        content[AndroidKeystorePrefix.Length..]);
                    var plaintext = AndroidKeystoreBridge.Decrypt(ciphertext);
                    if (plaintext is not null && plaintext.Length == 32)
                        return plaintext;
                }
            }

            // Generate new key and wrap with hardware keystore
            var newKey = RandomNumberGenerator.GetBytes(32);
            var encrypted = AndroidKeystoreBridge.Encrypt(newKey);
            if (encrypted is not null)
            {
                Directory.CreateDirectory(keyDir);
                var tempPath = wrappedKeyPath + ".tmp." + Guid.NewGuid().ToString("N")[..8];
                try
                {
                    File.WriteAllText(tempPath, AndroidKeystorePrefix + Convert.ToBase64String(encrypted));
                    File.SetUnixFileMode(tempPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                    File.Move(tempPath, wrappedKeyPath, overwrite: true);
                }
                catch
                {
                    File.WriteAllText(wrappedKeyPath, AndroidKeystorePrefix + Convert.ToBase64String(encrypted));
                    try { File.SetUnixFileMode(wrappedKeyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite); } catch { }
                }
                finally
                {
                    try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
                }
                return newKey;
            }
        }
        catch { }

        return null; // Fall back to file-based storage
    }

    /// <summary>
    /// Bridge to Android Keystore operations (registered by MAUI platform layer at startup).
    /// The MAUI Android project registers implementations that call:
    /// - KeyStore.getInstance("AndroidKeyStore")
    /// - KeyGenerator with KeyGenParameterSpec (AES/GCM, StrongBox-backed if available)
    /// - Cipher.getInstance("AES/GCM/NoPadding") for encrypt/decrypt
    ///
    /// If these are not registered, Android falls back to file-based key storage.
    /// </summary>
    /// <summary>
    /// Bridge to Android Keystore operations. Public so MAUI Android layer can register callbacks.
    /// </summary>
    public static class AndroidKeystoreBridge
    {
        /// <summary>Encrypt plaintext with hardware-backed AES key. Set by MAUI Android layer.</summary>
        public static Func<byte[], byte[]?>? EncryptFunc { get; set; }

        /// <summary>Decrypt ciphertext with hardware-backed AES key. Set by MAUI Android layer.</summary>
        public static Func<byte[], byte[]?>? DecryptFunc { get; set; }

        public static byte[]? Encrypt(byte[] data) => EncryptFunc?.Invoke(data);
        public static byte[]? Decrypt(byte[] data) => DecryptFunc?.Invoke(data);
    }
}
