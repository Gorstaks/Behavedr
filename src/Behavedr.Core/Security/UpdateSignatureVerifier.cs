namespace Behavedr.Core.Security;

using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Verifies Ed25519 (via RSA-PSS fallback on .NET) signatures on auto-update packages.
/// Uses a baked-in public key to ensure only CroatiaSecurity-signed binaries are accepted.
/// 
/// Signing workflow:
///   1. Build release zip
///   2. Sign with private key: produces .sig file (RSA-PSS SHA-256)
///   3. Upload both .zip and .sig to GitHub Releases
///   4. Agent downloads both, verifies .sig against baked-in public key before extracting
/// </summary>
public static class UpdateSignatureVerifier
{
    // RSA-4096 public key for update verification (PEM format, baked in at compile time).
    // Generate a keypair with: dotnet run --project tools (GenerateKey)
    // Sign: openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sign update-signing-key.pem -out file.sig file.zip
    // Keep the private key (update-signing-key.pem) in a secure location - NEVER commit it.
    // Rotated 2026-07-25: free RSA-4096 update key (not a commercial code-signing cert).
    // Matching private key lives only in operator secret storage / GitHub UPDATE_SIGNING_KEY.
    private const string PublicKeyPem = """
        -----BEGIN PUBLIC KEY-----
        MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAw7vJ6R8Cd9Nm5nSnefrr
        t7pXvPw8bYC3vn7n14l3S34MdhGzxOCdyU+kkCggNbNLmj8GGqex+EPt0pfEzvzj
        h+mi0doKMkHCEB5h/eu5bZn86xc2twbKbhXU5FWSh0BZMejcltAEhVCig/o5LlIv
        is0Xf/On4IIUW1KAd7/mJAkjW/4OpyyhJ7KKpttCXa6loR0atCu9JA6YAne7yrsZ
        EdA9jOV+i5EsMassQ2RLhMTm7tLoWBDFL6hu06v5KPqR0dRPrVnq/QTePpVQq0fj
        Ax4QLld8oPto1F6Bwv82Ch9U4ZE+uyzdp8uxCbdbPsOeV92bTUdq8gVH0kZOTeUQ
        4NNoYJIozA5hOtn09oy9wJKaODF+5YzV44la8roaAMgWBfUMIcmZOUWtVidbcB0W
        oo6Pe4rFbW6Pcwd5oTY0Zjff3zuN+Yxy15V6csQwV23HWZRrvdFvucthNbyCVCjd
        ZR8Yg4I3NkTzUiBbwe6/XA7FwlOYX6/2CqE4kaXKKjR893Kh7dSVXIF3LUEdBN8t
        rlNybhR6yjNrcOdZ0C8OIXrwqQK5Tt+T4b/JdMvZeYHmL6uc5+XpL0hHvqSYqqWZ
        PIr5ASAaFo77CPr02MSvQA3VQe3bA8LhFPh8mO6t7MyZtq/WysMPLPomHCo6BeAP
        uMbu9EG1q/hZqhtso8g4iT0CAwEAAQ==
        -----END PUBLIC KEY-----
        """;

    /// <summary>
    /// Verify that a file's signature is valid against the baked-in public key.
    /// </summary>
    /// <param name="filePath">Path to the file to verify.</param>
    /// <param name="signaturePath">Path to the .sig file (RSA-PSS SHA-256 signature).</param>
    /// <param name="logger">Optional logger.</param>
    /// <returns>True if signature is valid, false otherwise.</returns>
    public static bool VerifySignature(string filePath, string signaturePath, ILogger? logger = null)
    {
        logger ??= NullLogger.Instance;

        if (!File.Exists(filePath))
        {
            logger.LogError("Cannot verify signature: file not found at {Path}", filePath);
            return false;
        }

        if (!File.Exists(signaturePath))
        {
            logger.LogError("Cannot verify signature: .sig file not found at {Path}", signaturePath);
            return false;
        }

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(PublicKeyPem);

            var signatureBytes = File.ReadAllBytes(signaturePath);
            using var fileStream = File.OpenRead(filePath);

            var isValid = rsa.VerifyData(
                fileStream,
                signatureBytes,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss);

            if (isValid)
            {
                logger.LogInformation("Update signature verified successfully for {File}", Path.GetFileName(filePath));
            }
            else
            {
                logger.LogCritical("SECURITY: Update signature verification FAILED for {File} - rejecting update", Path.GetFileName(filePath));
                Telemetry.SecurityTelemetry.ReportSignatureFailure();
            }

            return isValid;
        }
        catch (CryptographicException ex)
        {
            logger.LogCritical(ex, "SECURITY: Cryptographic error during signature verification - rejecting update");
            Telemetry.SecurityTelemetry.ReportSignatureFailure();
            return false;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Signature verification failed unexpectedly");
            Telemetry.SecurityTelemetry.ReportSignatureFailure();
            return false;
        }
    }

    /// <summary>
    /// Check if the public key has been replaced from the placeholder.
    /// Returns false if the key is still the placeholder (development builds).
    /// </summary>
    public static bool IsProductionKeyConfigured() =>
        !PublicKeyPem.Contains("PLACEHOLDER", StringComparison.Ordinal);

    /// <summary>
    /// Get the baked-in public key PEM for use by other verification components (e.g., policy signing).
    /// Returns null if the production key is not configured.
    /// </summary>
    public static string? GetPublicKeyPem() =>
        IsProductionKeyConfigured() ? PublicKeyPem : null;

    /// <summary>
    /// Verify an RSA-PSS SHA-256 signature over an arbitrary payload (e.g. Android update metadata).
    /// Signature is raw bytes (typically Base64-decoded by the caller).
    /// </summary>
    public static bool VerifyPayload(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature, ILogger? logger = null)
    {
        logger ??= NullLogger.Instance;
        if (!IsProductionKeyConfigured() || payload.IsEmpty || signature.IsEmpty)
            return false;
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(PublicKeyPem);
            var ok = rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            if (!ok)
            {
                logger.LogCritical("SECURITY: payload signature verification FAILED");
                Telemetry.SecurityTelemetry.ReportSignatureFailure();
            }
            return ok;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "payload signature verification error");
            Telemetry.SecurityTelemetry.ReportSignatureFailure();
            return false;
        }
    }
}
