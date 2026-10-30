using CoreKeyProtection = Behavedr.Core.Security.KeyProtection;
using Android.Security.Keystore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Behavedr.Mobile.PlatformInjection;

/// <summary>
/// Registers the Android Keystore bridge callbacks that connect
/// Core's KeyProtection.AndroidKeystoreBridge to the MAUI platform's
/// AndroidKeyStoreProtection implementation.
///
/// This is the critical glue between:
/// - Behavedr.Core.Security.KeyProtection (platform-agnostic, references bridge delegates)
/// - Behavedr.Mobile.AndroidKeyStoreProtection (Android-specific, uses Java.Security.KeyStore)
///
/// Without this registration, Core falls back to file-based key storage (less secure).
/// With it, keys are protected by hardware TEE/StrongBox (cannot be extracted even with root).
///
/// Call Register() as early as possible in app startup - before any key operations.
/// </summary>
public static class KeystoreBridgeRegistration
{
    private static bool _registered;
    private static ILogger? _logger;

    public static void SetLogger(ILogger? logger) => _logger = logger;

    /// <summary>
    /// Register the Android Keystore bridge callbacks.
    /// Must be called before any call to KeyProtection that needs hardware-backed keys.
    /// </summary>
    public static void Register()
    {
        if (_registered) return;

        try
        {
            // Verify Android Keystore is available on this device
            if (!AndroidKeyStoreProtection.IsHardwareBackedAvailable())
            {
                _logger?.LogWarning("[KeystoreBridge] Hardware-backed KeyStore not available - " +
                    "falling back to file-based storage");
                return;
            }

            // Register the encrypt callback
            CoreKeyProtection.AndroidKeystoreBridge.EncryptFunc = (plaintext) =>
            {
                try
                {
                    return EncryptWithKeystore(plaintext);
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "[KeystoreBridge] Encrypt failed");
                    return null;
                }
            };

            // Register the decrypt callback
            CoreKeyProtection.AndroidKeystoreBridge.DecryptFunc = (ciphertext) =>
            {
                try
                {
                    return DecryptWithKeystore(ciphertext);
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "[KeystoreBridge] Decrypt failed");
                    return null;
                }
            };

            _registered = true;
            _logger?.LogInformation("[KeystoreBridge] Android Keystore bridge registered - " +
                "hardware-backed key protection active");
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "[KeystoreBridge] Registration failed");
        }
    }

    /// <summary>
    /// Encrypt data using the hardware-backed Android Keystore.
    /// Uses AndroidKeyStoreProtection to wrap the data with the TEE-bound key.
    /// </summary>
    private static byte[]? EncryptWithKeystore(byte[] plaintext)
    {
        // The AndroidKeyStoreProtection class handles:
        // 1. Ensuring the AES wrapping key exists in KeyStore
        // 2. Loading the key from KeyStore
        // 3. Encrypting with AES-GCM
        // 4. Returning IV + ciphertext

        // We use the existing WrapKey pattern from AndroidKeyStoreProtection
        // by calling it through its internal mechanism
        var keyStore = Java.Security.KeyStore.GetInstance("AndroidKeyStore");
        keyStore!.Load(null);

        const string keyAlias = "behavedr_machine_key_wrapper";

        // Ensure key exists
        if (!keyStore.ContainsAlias(keyAlias))
        {
            CreateKeystoreKey(keyAlias);
        }

        // Get the key entry
        var entry = keyStore.GetEntry(keyAlias, null) as Java.Security.KeyStore.SecretKeyEntry;
        var secretKey = entry?.SecretKey;
        if (secretKey is null) return null;

        // Encrypt
        var cipher = Javax.Crypto.Cipher.GetInstance("AES/GCM/NoPadding");
        cipher!.Init(Javax.Crypto.CipherMode.EncryptMode, secretKey);

        var iv = cipher.GetIV();
        var encrypted = cipher.DoFinal(plaintext);

        if (iv is null || encrypted is null) return null;

        // Output format: [12 bytes IV] [ciphertext + GCM tag]
        var result = new byte[iv.Length + encrypted.Length];
        iv.CopyTo(result, 0);
        encrypted.CopyTo(result, iv.Length);
        return result;
    }

    /// <summary>
    /// Decrypt data using the hardware-backed Android Keystore.
    /// </summary>
    private static byte[]? DecryptWithKeystore(byte[] ciphertext)
    {
        if (ciphertext.Length < 12 + 16) return null; // IV + min ciphertext

        var keyStore = Java.Security.KeyStore.GetInstance("AndroidKeyStore");
        keyStore!.Load(null);

        const string keyAlias = "behavedr_machine_key_wrapper";

        var entry = keyStore.GetEntry(keyAlias, null) as Java.Security.KeyStore.SecretKeyEntry;
        var secretKey = entry?.SecretKey;
        if (secretKey is null) return null;

        // Parse IV (first 12 bytes)
        var iv = new byte[12];
        Array.Copy(ciphertext, 0, iv, 0, 12);

        var encryptedData = new byte[ciphertext.Length - 12];
        Array.Copy(ciphertext, 12, encryptedData, 0, encryptedData.Length);

        // Decrypt
        var cipher = Javax.Crypto.Cipher.GetInstance("AES/GCM/NoPadding");
        var gcmSpec = new Javax.Crypto.Spec.GCMParameterSpec(128, iv);
        cipher!.Init(Javax.Crypto.CipherMode.DecryptMode, secretKey, gcmSpec);

        return cipher.DoFinal(encryptedData);
    }

    /// <summary>
    /// Create the AES-256 key in Android Keystore with hardware-backing.
    /// Uses StrongBox if available (dedicated security chip), falls back to TEE.
    /// </summary>
    private static void CreateKeystoreKey(string keyAlias)
    {
        var keyGenerator = Javax.Crypto.KeyGenerator.GetInstance(
            KeyProperties.KeyAlgorithmAes, "AndroidKeyStore");

        var specBuilder = new KeyGenParameterSpec.Builder(
                keyAlias,
                KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
            .SetBlockModes(KeyProperties.BlockModeGcm)
            .SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone)
            .SetKeySize(256)
            .SetRandomizedEncryptionRequired(true);

        // Try StrongBox (available on Pixel 3+ and some other devices)
        if (Android.OS.Build.VERSION.SdkInt >= Android.OS.BuildVersionCodes.P)
        {
            try
            {
#pragma warning disable CA1416
                specBuilder.SetIsStrongBoxBacked(true);
#pragma warning restore CA1416
                keyGenerator!.Init(specBuilder.Build());
                keyGenerator.GenerateKey();
                _logger?.LogInformation("[KeystoreBridge] Created StrongBox-backed AES-256 key");
                return;
            }
            catch (Java.Security.GeneralSecurityException)
            {
                // StrongBox not available - fall back to TEE
                specBuilder = new KeyGenParameterSpec.Builder(
                        keyAlias,
                        KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
                    .SetBlockModes(KeyProperties.BlockModeGcm)
                    .SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone)
                    .SetKeySize(256)
                    .SetRandomizedEncryptionRequired(true);
            }
        }

        keyGenerator!.Init(specBuilder.Build());
        keyGenerator.GenerateKey();
        _logger?.LogInformation("[KeystoreBridge] Created TEE-backed AES-256 key");
    }
}
