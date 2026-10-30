namespace Behavedr.Core.Security;

using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Provides HMAC-SHA256 integrity protection for configuration files.
/// 
/// On first run (or after authorized config changes), call <see cref="SealConfigFile"/>
/// to compute and store an HMAC in a sidecar .hmac file.
/// 
/// On every subsequent load, call <see cref="VerifyConfigFile"/> to detect tampering.
/// Uses the machine-derived key from <see cref="ConfigProtection"/> for the HMAC key.
/// </summary>
public static class ConfigIntegrity
{
    private const string HmacExtension = ".hmac";

    /// <summary>
    /// Validate configuration values are within acceptable bounds before sealing.
    /// Prevents first-run config injection attacks where an attacker pre-places
    /// a malicious config that would then be sealed as "trusted."
    /// v0.1.3: Expanded to validate Communication and Update sections (M-8 fix).
    /// </summary>
    public static bool ValidateConfigBeforeSealing(string configPath, ILogger? logger = null)
    {
        logger ??= NullLogger.Instance;

        try
        {
            var json = File.ReadAllText(configPath);
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;

            // Validate Scoring section bounds
            if (root.TryGetProperty("Scoring", out var scoring))
            {
                if (scoring.TryGetProperty("PresidentKillThreshold", out var pkt))
                {
                    var value = pkt.GetDouble();
                    if (value is < 50.0 or > 100.0)
                    {
                        logger.LogCritical("Config validation FAILED: PresidentKillThreshold={Value} is outside [50, 100]", value);
                        return false;
                    }
                }

                if (scoring.TryGetProperty("UserTargetedMultiplier", out var utm))
                {
                    var value = utm.GetDouble();
                    if (value is <= 0.0 or > 10.0)
                    {
                        logger.LogCritical("Config validation FAILED: UserTargetedMultiplier={Value} is outside (0, 10]", value);
                        return false;
                    }
                }

                if (scoring.TryGetProperty("HighScoreAlertThreshold", out var hsat))
                {
                    var value = hsat.GetDouble();
                    if (value is < 10.0 or > 99.0)
                    {
                        logger.LogCritical("Config validation FAILED: HighScoreAlertThreshold={Value} is outside [10, 99]", value);
                        return false;
                    }
                }
            }

            // Validate Agent section bounds
            if (root.TryGetProperty("Agent", out var agent))
            {
                if (agent.TryGetProperty("MonitoringIntervalSeconds", out var mis))
                {
                    var value = mis.GetInt32();
                    if (value is < 1 or > 60)
                    {
                        logger.LogCritical("Config validation FAILED: MonitoringIntervalSeconds={Value} is outside [1, 60]", value);
                        return false;
                    }
                }

                // v0.1.3 (M-8 fix): Validate self-protection cannot be disabled in config
                if (agent.TryGetProperty("EnableSelfProtection", out var esp))
                {
                    if (!esp.GetBoolean())
                    {
                        logger.LogCritical("Config validation FAILED: EnableSelfProtection cannot be set to false");
                        return false;
                    }
                }
            }

            // v0.1.3 (M-8 fix): Validate Communication section
            if (root.TryGetProperty("Communication", out var comm))
            {
                if (comm.TryGetProperty("ServerUrl", out var serverUrl))
                {
                    var url = serverUrl.GetString() ?? "";
                    if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase) &&
                        !url.StartsWith("http://localhost", StringComparison.OrdinalIgnoreCase) &&
                        !url.StartsWith("https://localhost", StringComparison.OrdinalIgnoreCase))
                    {
                        logger.LogCritical("Config validation FAILED: ServerUrl must use HTTPS (got: {Url})", url);
                        return false;
                    }
                }

                if (comm.TryGetProperty("TimeoutSeconds", out var timeout))
                {
                    var value = timeout.GetInt32();
                    if (value is < 5 or > 120)
                    {
                        logger.LogCritical("Config validation FAILED: TimeoutSeconds={Value} is outside [5, 120]", value);
                        return false;
                    }
                }

                if (comm.TryGetProperty("HeartbeatIntervalSeconds", out var hbi))
                {
                    var value = hbi.GetInt32();
                    if (value is < 10 or > 3600)
                    {
                        logger.LogCritical("Config validation FAILED: HeartbeatIntervalSeconds={Value} is outside [10, 3600]", value);
                        return false;
                    }
                }
            }

            // v0.1.3 (M-8 fix): Validate Response section
            if (root.TryGetProperty("Response", out var response))
            {
                if (response.TryGetProperty("AlertThreshold", out var at))
                {
                    var value = at.GetDouble();
                    if (value is < 10.0 or > 100.0)
                    {
                        logger.LogCritical("Config validation FAILED: AlertThreshold={Value} is outside [10, 100]", value);
                        return false;
                    }
                }

                if (response.TryGetProperty("ResponseThreshold", out var rt))
                {
                    var value = rt.GetDouble();
                    if (value is < 20.0 or > 100.0)
                    {
                        logger.LogCritical("Config validation FAILED: ResponseThreshold={Value} is outside [20, 100]", value);
                        return false;
                    }
                }

                if (response.TryGetProperty("MaxKillsPerMinute", out var mk))
                {
                    var value = mk.GetInt32();
                    if (value is < 1 or > 60)
                    {
                        logger.LogCritical("Config validation FAILED: MaxKillsPerMinute={Value} is outside [1, 60]", value);
                        return false;
                    }
                }
            }

            logger.LogInformation("Config pre-seal validation passed");
            return true;
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Config validation failed - cannot parse config file");
            return false;
        }
    }

    /// <summary>
    /// Compute HMAC-SHA256 of a config file and store it in a sidecar file.
    /// Call this at install time or when the config is legitimately modified.
    /// </summary>
    public static void SealConfigFile(string configPath, ILogger? logger = null)
    {
        logger ??= NullLogger.Instance;

        if (!File.Exists(configPath))
        {
            logger.LogWarning("Cannot seal config: file not found at {Path}", configPath);
            return;
        }

        var hmac = ComputeHmac(configPath);
        var hmacPath = configPath + HmacExtension;
        File.WriteAllText(hmacPath, Convert.ToBase64String(hmac));

        logger.LogInformation("Config file sealed: {Path}", configPath);
    }

    /// <summary>
    /// Verify that a config file has not been tampered with since it was sealed.
    /// </summary>
    /// <param name="configPath">Path to the config file.</param>
    /// <param name="logger">Optional logger.</param>
    /// <returns>
    /// <see cref="ConfigIntegrityResult.Valid"/> if HMAC matches,
    /// <see cref="ConfigIntegrityResult.Tampered"/> if mismatch,
    /// <see cref="ConfigIntegrityResult.NotSealed"/> if no .hmac sidecar exists (first run).
    /// </returns>
    public static ConfigIntegrityResult VerifyConfigFile(string configPath, ILogger? logger = null)
    {
        logger ??= NullLogger.Instance;

        if (!File.Exists(configPath))
        {
            logger.LogWarning("Config file not found: {Path}", configPath);
            return ConfigIntegrityResult.NotSealed;
        }

        var hmacPath = configPath + HmacExtension;
        if (!File.Exists(hmacPath))
        {
            logger.LogWarning("No HMAC sidecar found for {Path} - config not yet sealed (first run?)", configPath);
            return ConfigIntegrityResult.NotSealed;
        }

        try
        {
            var storedHmacBase64 = File.ReadAllText(hmacPath).Trim();
            var storedHmac = Convert.FromBase64String(storedHmacBase64);
            var computedHmac = ComputeHmac(configPath);

            if (CryptographicOperations.FixedTimeEquals(storedHmac, computedHmac))
            {
                logger.LogDebug("Config integrity verified: {Path}", configPath);
                return ConfigIntegrityResult.Valid;
            }
            else
            {
                logger.LogCritical(
                    "SECURITY: Config file integrity check FAILED for {Path} - file may have been tampered with!",
                    configPath);
                return ConfigIntegrityResult.Tampered;
            }
        }
        catch (FormatException)
        {
            logger.LogCritical("SECURITY: HMAC sidecar file is corrupted for {Path}", configPath);
            return ConfigIntegrityResult.Tampered;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Config integrity verification failed unexpectedly for {Path}", configPath);
            return ConfigIntegrityResult.Tampered;
        }
    }

    /// <summary>
    /// Compute HMAC-SHA256 of file contents using the machine-derived key.
    /// </summary>
    private static byte[] ComputeHmac(string filePath)
    {
        var key = GetHmacKey();
        var fileBytes = File.ReadAllBytes(filePath);
        return HMACSHA256.HashData(key, fileBytes);
    }

    /// <summary>
    /// Derive an HMAC key from the machine key used by ConfigProtection.
    /// Uses HKDF to derive a separate key specifically for config integrity.
    /// V-3 FIX: Delegates to KeyProtection.GetMachineKey() to avoid duplicate key management.
    /// </summary>
    private static byte[] GetHmacKey()
    {
        var machineKey = KeyProtection.GetMachineKey();
        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            machineKey,
            outputLength: 32,
            info: Encoding.UTF8.GetBytes("behavedr-config-integrity-v1"));
    }

    /// <summary>
    /// V-3 FIX: GetMachineKeyBytes removed - now delegates to KeyProtection.GetMachineKey()
    /// via GetHmacKey() to avoid duplicate key management implementations.
    /// </summary>
}

public enum ConfigIntegrityResult
{
    /// <summary>HMAC matches - config is unmodified.</summary>
    Valid,

    /// <summary>HMAC does NOT match - config may have been tampered with.</summary>
    Tampered,

    /// <summary>No HMAC sidecar file exists (first run or not yet sealed).</summary>
    NotSealed,
}
