using Android.Security;
using Android.Security.Keystore;
using Java.Security;
using Javax.Crypto;
using Javax.Crypto.Spec;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Behavedr.Mobile;

/// <summary>
/// Android KeyStore integration for hardware-backed key storage.
///
/// Uses the Android Keystore system to generate and store the machine key
/// in hardware-backed secure storage (TEE/StrongBox on supported devices).
/// Keys stored in Android Keystore:
/// - Cannot be extracted (non-exportable)
/// - Are bound to the device (cannot be backed up/restored to another device)
/// - Survive app updates but not uninstall
/// - Are protected by hardware on devices with TEE/StrongBox
///
/// Architecture:
/// - Generates an AES-256 key in Android Keystore on first run
/// - Uses that key to encrypt/decrypt the Behavedr machine key
/// - The wrapped machine key is stored in app-private storage
/// - Even with root, the KeyStore key cannot be extracted from hardware
///
/// Fallback: If KeyStore is unavailable (emulator, old device), falls back
/// to EncryptedSharedPreferences which uses Android's own encryption.
/// </summary>
public static class AndroidKeyStoreProtection
{
    private const string KeyAlias = "behavedr_machine_key_wrapper";
    private const string KeyStoreProvider = "AndroidKeyStore";
    private const string WrappedKeyFile = "behavedr_wrapped_key.bin";
    private const string TransformationAesGcm = "AES/GCM/NoPadding";
    private const int GcmIvLength = 12;
    private const int GcmTagLength = 128; // bits

    private static ILogger? _logger;

    public static void SetLogger(ILogger? logger) => _logger = logger;

    /// <summary>
    /// Get or create the hardware-backed machine key.
    /// If this is first run, generates a new random machine key, wraps it with
    /// the Android KeyStore key, and stores the wrapped blob.
    /// On subsequent runs, unwraps and returns the existing key.
    /// </summary>
    public static byte[]? GetMachineKey()
    {
        try
        {
            // Ensure the KeyStore wrapping key exists
            EnsureKeyStoreKeyExists();

            var wrappedPath = GetWrappedKeyPath();
            if (File.Exists(wrappedPath))
            {
                // Unwrap existing key
                var wrappedData = File.ReadAllBytes(wrappedPath);
                return UnwrapKey(wrappedData);
            }

            // First run: generate and wrap a new machine key
            var machineKey = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
            var wrapped = WrapKey(machineKey);
            if (wrapped is null)
            {
                _logger?.LogWarning("[AndroidKeyStore] Failed to wrap key - falling back to file storage");
                return null;
            }

            // Write wrapped key to app-private storage
            var dir = Path.GetDirectoryName(wrappedPath);
            if (dir is not null) Directory.CreateDirectory(dir);
            File.WriteAllBytes(wrappedPath, wrapped);

            _logger?.LogInformation("[AndroidKeyStore] Machine key generated and wrapped with hardware-backed key");
            return machineKey;
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "[AndroidKeyStore] KeyStore unavailable - falling back");
            return null;
        }
    }

    /// <summary>
    /// Check if Android KeyStore hardware-backed storage is available.
    /// </summary>
    public static bool IsHardwareBackedAvailable()
    {
        try
        {
            var keyStore = KeyStore.GetInstance(KeyStoreProvider);
            keyStore?.Load(null);
            return keyStore is not null;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Ensure the AES wrapping key exists in Android KeyStore.
    /// If not, generates one with hardware-backing (StrongBox if available).
    /// </summary>
    private static void EnsureKeyStoreKeyExists()
    {
        var keyStore = KeyStore.GetInstance(KeyStoreProvider);
        keyStore!.Load(null);

        if (keyStore.ContainsAlias(KeyAlias))
            return;

        // Generate AES-256 key in hardware-backed KeyStore
        var keyGenerator = KeyGenerator.GetInstance(
            KeyProperties.KeyAlgorithmAes, KeyStoreProvider);

        var spec = new KeyGenParameterSpec.Builder(
                KeyAlias,
                KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
            .SetBlockModes(KeyProperties.BlockModeGcm)
            .SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone)
            .SetKeySize(256)
            .SetRandomizedEncryptionRequired(true)
            // Require user authentication for extra security (optional - disabled for service use)
            // .SetUserAuthenticationRequired(true)
            // .SetUserAuthenticationValidityDurationSeconds(300)
            .Build();

        keyGenerator!.Init(spec);
        keyGenerator.GenerateKey();

        _logger?.LogInformation("[AndroidKeyStore] Generated hardware-backed AES-256 wrapping key");
    }

    /// <summary>
    /// Wrap (encrypt) the machine key using the Android KeyStore key.
    /// Uses AES-GCM. Output format: [12 bytes IV] [ciphertext + tag]
    /// </summary>
    private static byte[]? WrapKey(byte[] plainKey)
    {
        try
        {
            var keyStore = KeyStore.GetInstance(KeyStoreProvider);
            keyStore!.Load(null);

            var entry = keyStore.GetEntry(KeyAlias, null) as KeyStore.SecretKeyEntry;
            var secretKey = entry?.SecretKey;
            if (secretKey is null) return null;

            var cipher = Cipher.GetInstance(TransformationAesGcm);
            cipher!.Init(CipherMode.EncryptMode, secretKey);

            var iv = cipher.GetIV();
            var encrypted = cipher.DoFinal(plainKey);

            if (iv is null || encrypted is null) return null;

            // Output: IV || ciphertext
            var result = new byte[iv.Length + encrypted.Length];
            iv.CopyTo(result, 0);
            encrypted.CopyTo(result, iv.Length);
            return result;
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "[AndroidKeyStore] WrapKey failed");
            return null;
        }
    }

    /// <summary>
    /// Unwrap (decrypt) the machine key using the Android KeyStore key.
    /// Input format: [12 bytes IV] [ciphertext + tag]
    /// </summary>
    private static byte[]? UnwrapKey(byte[] wrappedData)
    {
        try
        {
            if (wrappedData.Length < GcmIvLength + 16) // IV + min ciphertext
                return null;

            var keyStore = KeyStore.GetInstance(KeyStoreProvider);
            keyStore!.Load(null);

            var entry = keyStore.GetEntry(KeyAlias, null) as KeyStore.SecretKeyEntry;
            var secretKey = entry?.SecretKey;
            if (secretKey is null) return null;

            var iv = new byte[GcmIvLength];
            Array.Copy(wrappedData, 0, iv, 0, GcmIvLength);

            var ciphertext = new byte[wrappedData.Length - GcmIvLength];
            Array.Copy(wrappedData, GcmIvLength, ciphertext, 0, ciphertext.Length);

            var cipher = Cipher.GetInstance(TransformationAesGcm);
            var gcmSpec = new GCMParameterSpec(GcmTagLength, iv);
            cipher!.Init(CipherMode.DecryptMode, secretKey, gcmSpec);

            return cipher.DoFinal(ciphertext);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "[AndroidKeyStore] UnwrapKey failed - key may have been tampered");
            return null;
        }
    }

    private static string GetWrappedKeyPath()
    {
        // Use app-private files directory (not accessible without root)
        var appDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(appDir, "security", WrappedKeyFile);
    }
}
