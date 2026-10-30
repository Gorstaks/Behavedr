namespace Behavedr.Core.Security;

using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Provides encryption/decryption for sensitive configuration values.
/// Uses DPAPI on Windows, AES with machine-derived key on Linux/macOS.
/// </summary>
public static class ConfigProtection
{

    /// <summary>Encrypt a value for safe storage in config files.</summary>
    public static string Encrypt(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var bytes = Encoding.UTF8.GetBytes(plaintext);

        if (OperatingSystem.IsWindows())
        {
            return EncryptWindows(bytes);
        }

        return EncryptCrossPlatform(bytes);
    }

    /// <summary>Decrypt a previously encrypted value.</summary>
    public static string Decrypt(string ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);

        if (OperatingSystem.IsWindows())
        {
            return DecryptWindows(ciphertext);
        }

        return DecryptCrossPlatform(ciphertext);
    }

    /// <summary>Check if a string looks like an encrypted value.</summary>
    public static bool IsEncrypted(string value) =>
        value.StartsWith("ENC:", StringComparison.Ordinal);

    /// <summary>
    /// Decrypt a value if it's encrypted, otherwise return as-is.
    /// </summary>
    public static string DecryptIfNeeded(string value) =>
        IsEncrypted(value) ? Decrypt(value["ENC:".Length..]) : value;

    [SupportedOSPlatform("windows")]
    private static string EncryptWindows(byte[] data)
    {
        var encrypted = ProtectedData.Protect(data, null, DataProtectionScope.LocalMachine);
        return Convert.ToBase64String(encrypted);
    }

    [SupportedOSPlatform("windows")]
    private static string DecryptWindows(string ciphertext)
    {
        var encrypted = Convert.FromBase64String(ciphertext);
        var decrypted = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.LocalMachine);
        return Encoding.UTF8.GetString(decrypted);
    }

    private const int GcmNonceSize = 12;
    private const int GcmTagSize = 16;

    private static string EncryptCrossPlatform(byte[] data)
    {
        var key = KeyProtection.GetMachineKey();
        var nonce = RandomNumberGenerator.GetBytes(GcmNonceSize);
        var ciphertext = new byte[data.Length];
        var tag = new byte[GcmTagSize];

        using var aes = new AesGcm(key, GcmTagSize);
        aes.Encrypt(nonce, data, ciphertext, tag);

        // Format: nonce (base64) + "." + tag (base64) + "." + ciphertext (base64)
        return Convert.ToBase64String(nonce) + "." +
               Convert.ToBase64String(tag) + "." +
               Convert.ToBase64String(ciphertext);
    }

    private static string DecryptCrossPlatform(string ciphertext)
    {
        var parts = ciphertext.Split('.');

        // Support legacy AES-CBC format (2 parts) for migration
        if (parts.Length == 2)
        {
            return DecryptCrossPlatformLegacy(parts);
        }

        if (parts.Length != 3)
            throw new CryptographicException("Invalid encrypted format");

        var nonce = Convert.FromBase64String(parts[0]);
        var tag = Convert.FromBase64String(parts[1]);
        var encrypted = Convert.FromBase64String(parts[2]);

        var key = KeyProtection.GetMachineKey();
        var plaintext = new byte[encrypted.Length];

        using var aes = new AesGcm(key, GcmTagSize);
        aes.Decrypt(nonce, encrypted, tag, plaintext);

        return Encoding.UTF8.GetString(plaintext);
    }

    /// <summary>
    /// Legacy AES-CBC decryption for backward compatibility during migration.
    /// New values are always encrypted with AES-GCM.
    /// </summary>
    private static string DecryptCrossPlatformLegacy(string[] parts)
    {
        var iv = Convert.FromBase64String(parts[0]);
        var encrypted = Convert.FromBase64String(parts[1]);

        var key = KeyProtection.GetMachineKey();
        using var aes = Aes.Create();
        aes.Key = key;

        var decrypted = aes.DecryptCbc(encrypted, iv);
        return Encoding.UTF8.GetString(decrypted);
    }

    /// <summary>
    /// Rotate the machine key. Delegates to KeyProtection.
    /// Old key is preserved for decrypting existing data during migration.
    /// </summary>
    public static void RotateKey(ILogger? logger = null)
    {
        KeyProtection.RotateKey(logger);
    }

    /// <summary>
    /// Get a previous key version (for decrypting data encrypted with an older key).
    /// Returns null if the version doesn't exist.
    /// </summary>
    public static byte[]? GetKeyVersion(int version)
    {
        return KeyProtection.GetKeyVersion(version);
    }
}
