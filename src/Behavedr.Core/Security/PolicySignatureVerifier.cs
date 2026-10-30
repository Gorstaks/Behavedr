namespace Behavedr.Core.Security;

using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Verifies RSA-PSS SHA-256 signatures on server-issued policy updates.
///
/// Key separation (v0.2.6+):
/// Policy verification uses a <b>distinct</b> RSA-4096 public key from package
/// updates so compromise of the update signing key does not authorize policy
/// injection. Private policy key: policy-signing-key.pem (gitignored).
///
/// Signing workflow (server side):
///   1. Canonicalize policy JSON (exclude Signature field)
///   2. Sign with policy private key: RSA-PSS SHA-256, saltlen = digest
///   3. Deliver Base64 signature with the policy payload
/// </summary>
public static class PolicySignatureVerifier
{
    // Distinct RSA-4096 policy public key (v0.2.6). Private: policy-signing-key.pem (never commit).
    // Blast-radius isolation from update-signing-key material.
    private const string PublicKeyPem = """
        -----BEGIN PUBLIC KEY-----
        MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0qUtBHABZdNU0jDxqO4J
        UvYMec6CsNIzYfFS74wxkIsAivjmzmP85nAfifxmMvIULGIbP9eFvNQ11GgUClQp
        GbBNF8VkrjmmO81JD1o0oiIM8EA0RQp1479hdmFLen8WTbdj7jHTMbw7516fS8fV
        2QAcByVtrGtAkHOGmHPbWUF1rKMeWIWscfrAgxF+9QeFWAb6LxCzu1igThMiGYsc
        dTgi1O0IcjI2YZmKQIVpQZlEiSG7/QMKizYI17Psiwsxb6KRWqzW4nqv3w/Lx1St
        Pf647XjpnMB/w7Ip8W3AEnJ6I8UiPRGbh6OygyRsKrXa3+hi8J+tNWsxkC/GEY48
        VfjH4WL/aWBNlKmSbjiixbvKbxIAYBn20qAighgtygq8sa9ynj4ZW6Jy1S8HUend
        e9NNNnSr1R7Q2qKfZNyVXqVSMsRCs/2GU8ErpVcic2ulhjBrSn2eIWfmL86Eb9Ku
        ydFEMEfhDS6T0E/ybjMVZIab4RM+/AGE/DU7EPWobwUPUG79YMUlsS4bHPvvZvP9
        zQwQDWipDUrJ0JcYnKMCP4TuNfXwbfpebdldrfTmMheYuExS5B+1YuTLQzdnYqV1
        xvkIYT8r9GlLvTH2h+49LQ2Le2wbObNlbTAxFNKUZgtgv4uiGn1PcnQjXVngosvi
        WBLLP2mOEPOy/Cs3HW58K0kCAwEAAQ==
        -----END PUBLIC KEY-----
        """;

    /// <summary>
    /// Returns true when the policy public key is still shared with the update signing key.
    /// Shared keys reduce blast-radius isolation; plan a rotation ceremony.
    /// </summary>
    public static bool IsUsingSharedUpdateKey()
    {
        var update = UpdateSignatureVerifier.GetPublicKeyPem();
        if (update is null)
            return false;
        return string.Equals(
            NormalizePem(PublicKeyPem),
            NormalizePem(update),
            StringComparison.Ordinal);
    }

    public static bool IsProductionKeyConfigured() =>
        !PublicKeyPem.Contains("PLACEHOLDER", StringComparison.Ordinal);

    public static string? GetPublicKeyPem() =>
        IsProductionKeyConfigured() ? PublicKeyPem : null;

    /// <summary>
    /// Verify RSA-PSS signature over arbitrary payload bytes (canonical policy JSON).
    /// </summary>
    public static bool VerifyPayload(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature, ILogger? logger = null)
    {
        logger ??= NullLogger.Instance;

        if (!IsProductionKeyConfigured())
        {
            logger.LogWarning("Policy signing key is not configured (development mode) - accepting without verification");
            return true;
        }

        if (payload.IsEmpty || signature.IsEmpty)
        {
            logger.LogCritical("SECURITY: Empty policy payload or signature - rejecting");
            return false;
        }

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(PublicKeyPem);

            var valid = rsa.VerifyData(
                payload,
                signature,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss);

            if (!valid)
            {
                logger.LogCritical("SECURITY: Policy signature verification FAILED - rejecting policy");
                Telemetry.SecurityTelemetry.ReportSignatureFailure();
            }

            return valid;
        }
        catch (CryptographicException ex)
        {
            logger.LogCritical(ex, "SECURITY: Cryptographic error during policy signature verification");
            Telemetry.SecurityTelemetry.ReportSignatureFailure();
            return false;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Policy signature verification failed unexpectedly");
            Telemetry.SecurityTelemetry.ReportSignatureFailure();
            return false;
        }
    }

    private static string NormalizePem(string pem) =>
        pem.Replace("\r", "", StringComparison.Ordinal)
           .Replace("\n", "", StringComparison.Ordinal)
           .Replace(" ", "", StringComparison.Ordinal);
}
