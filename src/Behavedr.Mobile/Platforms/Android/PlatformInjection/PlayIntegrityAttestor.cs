using Android.Content;
using Android.OS;
using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Environment = System.Environment;
using Signal = Behavedr.Core.Models.Signal;

namespace Behavedr.Mobile.PlatformInjection;

/// <summary>
/// Google Play Integrity API attestation for device integrity verification.
///
/// Play Integrity replaces SafetyNet Attestation (deprecated) and provides:
/// - Device integrity: Runs on a genuine Android device
/// - App integrity: Genuine Play-recognized app binary
/// - Account integrity: Google Play licensed user
///
/// Verdict levels:
/// - MEETS_BASIC_INTEGRITY: Device may be running custom ROM, no root concealment
/// - MEETS_DEVICE_INTEGRITY: Genuine device with locked bootloader
/// - MEETS_STRONG_INTEGRITY: Recent security patch, hardware-backed keystore
///
/// Architecture:
/// 1. Client creates a nonce (unique per request, includes timestamp)
/// 2. Client calls Play Integrity API with nonce
/// 3. Client receives encrypted+signed token
/// 4. Token is sent to Behavedr server for decryption (Google verifies)
/// 5. Server returns verdict; client generates signals based on verdict
///
/// For standalone mode (no server), we use the on-device standard API request
/// and decode the verdict labels from the token's payload.
///
/// v0.2.0 audit fix A-7: Device attestation for Android.
/// </summary>
public sealed class PlayIntegrityAttestor : IDisposable
{
    private readonly Context _context;
    private readonly ILogger _logger;
    private Timer? _attestTimer;
    private bool _disposed;
    private IntegrityVerdict? _lastVerdict;
    private DateTime _lastAttestTime = DateTime.MinValue;

    // Cloud project number for Play Integrity API
    // In production, this comes from configuration
    private readonly long _cloudProjectNumber;
    private readonly string? _serverVerifyUrl;
    private readonly bool _requireIntegrity;

    /// <summary>
    /// Last known integrity verdict (cached between attestation calls).
    /// </summary>
    public IntegrityVerdict? LastVerdict => _lastVerdict;

    /// <summary>
    /// When true (or env BEHAVEDR_REQUIRE_PLAY_INTEGRITY=1), missing API / failed
    /// basic integrity is scored as high severity fail-closed for enterprise SKUs.
    /// </summary>
    public bool RequireIntegrity => _requireIntegrity;

    public PlayIntegrityAttestor(
        Context context,
        long cloudProjectNumber = 0,
        string? serverVerifyUrl = null,
        ILogger? logger = null,
        bool? requireIntegrity = null)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _cloudProjectNumber = cloudProjectNumber;
        _serverVerifyUrl = serverVerifyUrl;
        _logger = logger ?? NullLogger.Instance;
        _requireIntegrity = requireIntegrity
            ?? string.Equals(Environment.GetEnvironmentVariable("BEHAVEDR_REQUIRE_PLAY_INTEGRITY"), "1", StringComparison.Ordinal)
            || cloudProjectNumber > 0;
    }

    /// <summary>
    /// Start periodic attestation. Performs initial check immediately,
    /// then re-attests every 4 hours to detect device state changes.
    /// </summary>
    public void Start()
    {
        // Initial attestation after 10s (let the app settle)
        _attestTimer = new Timer(OnAttestTimer, null,
            TimeSpan.FromSeconds(10), TimeSpan.FromHours(4));
        _logger.LogInformation("[PlayIntegrity] Started - attestation every 4 hours");
    }

    /// <summary>
    /// Perform an on-demand attestation and return signals.
    /// </summary>
    public async Task<IReadOnlyList<Signal>> AttestAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            // Generate nonce: SHA-256(package_name + timestamp + random)
            var nonce = GenerateNonce();

            // Attempt Play Integrity API call via reflection
            // (Avoids hard dependency on Google Play Services library)
            var token = await RequestIntegrityTokenAsync(nonce, ct);

            if (token is null)
            {
                // Fail-closed for enterprise when project number / require flag set
                if (_requireIntegrity)
                {
                    signals.Add(new Signal("play_integrity_unavailable:fail_closed", 90, 0.95));
                    _logger.LogCritical("[PlayIntegrity] REQUIRED but API unavailable - fail-closed");
                }
                else
                {
                    signals.Add(new Signal("play_integrity_unavailable", 40, 0.65));
                }
                _lastVerdict = new IntegrityVerdict(
                    false, false, false, false,
                    "API_UNAVAILABLE", DateTime.UtcNow);
                return signals;
            }

            if (_cloudProjectNumber <= 0 && _requireIntegrity)
            {
                signals.Add(new Signal("play_integrity_project_number_missing:fail_closed", 85, 0.9));
            }

            // Decode and verify token
            var verdict = await VerifyTokenAsync(token, nonce, ct);
            _lastVerdict = verdict;
            _lastAttestTime = DateTime.UtcNow;

            // Generate signals based on verdict
            if (!verdict.MeetsDeviceIntegrity)
            {
                signals.Add(new Signal("device_integrity_failed", 75, 0.88));
            }

            if (!verdict.MeetsBasicIntegrity)
            {
                signals.Add(new Signal("basic_integrity_failed", 85, 0.92));
            }

            if (!verdict.MeetsStrongIntegrity)
            {
                // Not critical - many legitimate devices don't meet strong
                signals.Add(new Signal("strong_integrity_not_met", 25, 0.5));
            }

            if (!verdict.AppRecognized)
            {
                signals.Add(new Signal("app_integrity_failed:not_recognized", 80, 0.9));
            }

            if (verdict.MeetsDeviceIntegrity && verdict.MeetsBasicIntegrity)
            {
                _logger.LogDebug("[PlayIntegrity] Device passes integrity checks");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[PlayIntegrity] Attestation failed");
            signals.Add(new Signal("play_integrity_error", 20, 0.4));
        }

        return signals;
    }

    /// <summary>
    /// Get signals from last known verdict without performing new attestation.
    /// Useful for periodic monitoring checks between full attestations.
    /// </summary>
    public IReadOnlyList<Signal> GetCachedSignals()
    {
        var signals = new List<Signal>();

        if (_lastVerdict is null)
        {
            if ((DateTime.UtcNow - _lastAttestTime).TotalHours > 8)
                signals.Add(new Signal("play_integrity_stale", 20, 0.4));
            return signals;
        }

        if (!_lastVerdict.MeetsBasicIntegrity)
            signals.Add(new Signal("device_compromised:cached_verdict", 75, 0.85));

        return signals;
    }

    private void OnAttestTimer(object? state)
    {
        if (_disposed) return;
        _ = Task.Run(async () =>
        {
            try { await AttestAsync(CancellationToken.None); }
            catch { }
        });
    }

    /// <summary>
    /// Request an integrity token from Google Play Integrity API.
    /// Uses reflection to avoid hard dependency on the Play Services library.
    /// Returns null if Play Services are not available.
    /// </summary>
    private async Task<string?> RequestIntegrityTokenAsync(byte[] nonce, CancellationToken ct)
    {
        try
        {
            // Try to use the Play Integrity API via Java interop
            // Class: com.google.android.play.core.integrity.IntegrityManagerFactory
            var factoryClass = Java.Lang.Class.ForName(
                "com.google.android.play.core.integrity.IntegrityManagerFactory");

            if (factoryClass is null)
                return null;

            // IntegrityManagerFactory.create(context)
            var createMethod = factoryClass.GetMethod("create",
                Java.Lang.Class.FromType(typeof(Context))!);
            var manager = createMethod?.Invoke(null, _context);
            if (manager is null) return null;

            // Build IntegrityTokenRequest
            var requestBuilderClass = Java.Lang.Class.ForName(
                "com.google.android.play.core.integrity.IntegrityTokenRequest$Builder");
            var builderInstance = requestBuilderClass?.GetConstructor()?.NewInstance();
            if (builderInstance is null) return null;

            // Set nonce
            var nonceBase64 = Convert.ToBase64String(nonce);
            var setNonceMethod = requestBuilderClass?.GetMethod("setNonce",
                Java.Lang.Class.FromType(typeof(Java.Lang.String))!);
            setNonceMethod?.Invoke(builderInstance, new Java.Lang.String(nonceBase64));

            // Set cloud project number if available
            if (_cloudProjectNumber > 0)
            {
                var setProjectMethod = requestBuilderClass?.GetMethod("setCloudProjectNumber",
                    Java.Lang.Long.Type!);
                setProjectMethod?.Invoke(builderInstance,
                    Java.Lang.Long.ValueOf(_cloudProjectNumber));
            }

            // Build request
            var buildMethod = requestBuilderClass?.GetMethod("build");
            var request = buildMethod?.Invoke(builderInstance);
            if (request is null) return null;

            // Call requestIntegrityToken(request) - returns Task<IntegrityTokenResponse>
            var managerClass = manager.Class;
            var requestTokenMethod = managerClass?.GetMethod("requestIntegrityToken",
                request.Class);
            var task = requestTokenMethod?.Invoke(manager, request);

            if (task is null) return null;

            // Await the Google Task (com.google.android.gms.tasks.Task)
            var token = await AwaitGoogleTaskAsync(task, ct);
            if (token is null) return null;

            // Get token string from IntegrityTokenResponse
            var getTokenMethod = token.Class?.GetMethod("token");
            var tokenValue = getTokenMethod?.Invoke(token);
            return tokenValue?.ToString();
        }
        catch (Java.Lang.ClassNotFoundException)
        {
            // Play Integrity library not bundled - expected on non-Google devices
            _logger.LogDebug("[PlayIntegrity] Play Integrity API not available (no Play Services)");
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[PlayIntegrity] Token request failed");
            return null;
        }
    }

    /// <summary>
    /// Await a Google Play Services Task object (com.google.android.gms.tasks.Task).
    /// Converts it to a .NET async Task.
    /// </summary>
    private static async Task<Java.Lang.Object?> AwaitGoogleTaskAsync(
        Java.Lang.Object googleTask, CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<Java.Lang.Object?>();

        try
        {
            // Use Tasks.await() with timeout
            var tasksClass = Java.Lang.Class.ForName("com.google.android.gms.tasks.Tasks");
            var awaitMethod = tasksClass?.GetMethod("await",
                Java.Lang.Class.ForName("com.google.android.gms.tasks.Task")!,
                Java.Lang.Long.Type!,
                Java.Lang.Class.ForName("java.util.concurrent.TimeUnit")!);

            if (awaitMethod is null)
            {
                // Fallback: spin-wait on isComplete()
                var isCompleteMethod = googleTask.Class?.GetMethod("isComplete");
                var getResultMethod = googleTask.Class?.GetMethod("getResult");

                for (int i = 0; i < 100 && !ct.IsCancellationRequested; i++)
                {
                    var complete = isCompleteMethod?.Invoke(googleTask);
                    if (complete is Java.Lang.Boolean b && b.BooleanValue())
                    {
                        return getResultMethod?.Invoke(googleTask) as Java.Lang.Object;
                    }
                    await Task.Delay(100, ct);
                }
                return null;
            }

            // Get TimeUnit.SECONDS
            var timeUnitClass = Java.Lang.Class.ForName("java.util.concurrent.TimeUnit");
            var secondsField = timeUnitClass?.GetField("SECONDS");
            var secondsUnit = secondsField?.Get(null);

            var result = awaitMethod.Invoke(null, googleTask,
                Java.Lang.Long.ValueOf(10), secondsUnit!);
            return result as Java.Lang.Object;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Verify the integrity token. In production, this should be done server-side.
    /// For standalone operation, we decode the JWT-like token payload.
    /// </summary>
    private async Task<IntegrityVerdict> VerifyTokenAsync(string token, byte[] nonce, CancellationToken ct)
    {
        // If we have a server URL, forward the token for verification
        if (!string.IsNullOrEmpty(_serverVerifyUrl))
        {
            return await VerifyWithServerAsync(token, nonce, ct);
        }

        // Standalone verification: decode token payload (not cryptographically verified
        // without Google's decryption key, but useful for on-device heuristics)
        return DecodeTokenLocally(token);
    }

    private async Task<IntegrityVerdict> VerifyWithServerAsync(string token, byte[] nonce, CancellationToken ct)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            var payload = JsonSerializer.Serialize(new
            {
                token,
                nonce = Convert.ToBase64String(nonce),
                packageName = _context.PackageName,
            });

            var response = await http.PostAsync(
                _serverVerifyUrl,
                new StringContent(payload, Encoding.UTF8, "application/json"),
                ct);

            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync(ct);
                return ParseServerVerdict(json);
            }
        }
        catch { }

        // Server verification failed - use local decode as fallback
        return DecodeTokenLocally(token);
    }

    private static IntegrityVerdict DecodeTokenLocally(string token)
    {
        // The token is a JWS - header.payload.signature
        // We can decode the payload without verification for label extraction
        try
        {
            var parts = token.Split('.');
            if (parts.Length >= 2)
            {
                var payloadB64 = parts[1].Replace('-', '+').Replace('_', '/');
                // Pad if needed
                switch (payloadB64.Length % 4)
                {
                    case 2: payloadB64 += "=="; break;
                    case 3: payloadB64 += "="; break;
                }

                var payloadJson = Encoding.UTF8.GetString(Convert.FromBase64String(payloadB64));
                using var doc = JsonDocument.Parse(payloadJson);
                var root = doc.RootElement;

                bool meetsBasic = false, meetsDevice = false, meetsStrong = false, appRecognized = false;

                if (root.TryGetProperty("deviceIntegrity", out var di) &&
                    di.TryGetProperty("deviceRecognitionVerdict", out var verdicts))
                {
                    foreach (var v in verdicts.EnumerateArray())
                    {
                        var label = v.GetString() ?? "";
                        if (label.Contains("BASIC", StringComparison.OrdinalIgnoreCase)) meetsBasic = true;
                        if (label.Contains("DEVICE", StringComparison.OrdinalIgnoreCase)) meetsDevice = true;
                        if (label.Contains("STRONG", StringComparison.OrdinalIgnoreCase)) meetsStrong = true;
                    }
                }

                if (root.TryGetProperty("appIntegrity", out var ai) &&
                    ai.TryGetProperty("appRecognitionVerdict", out var arv))
                {
                    appRecognized = arv.GetString()?.Contains("PLAY_RECOGNIZED",
                        StringComparison.OrdinalIgnoreCase) ?? false;
                }

                return new IntegrityVerdict(meetsBasic, meetsDevice, meetsStrong, appRecognized,
                    "LOCAL_DECODE", DateTime.UtcNow);
            }
        }
        catch { }

        return new IntegrityVerdict(false, false, false, false, "DECODE_FAILED", DateTime.UtcNow);
    }

    private static IntegrityVerdict ParseServerVerdict(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            return new IntegrityVerdict(
                root.TryGetProperty("meetsBasicIntegrity", out var b) && b.GetBoolean(),
                root.TryGetProperty("meetsDeviceIntegrity", out var d) && d.GetBoolean(),
                root.TryGetProperty("meetsStrongIntegrity", out var s) && s.GetBoolean(),
                root.TryGetProperty("appRecognized", out var a) && a.GetBoolean(),
                "SERVER_VERIFIED",
                DateTime.UtcNow);
        }
        catch
        {
            return new IntegrityVerdict(false, false, false, false, "SERVER_PARSE_ERROR", DateTime.UtcNow);
        }
    }

    private byte[] GenerateNonce()
    {
        // Nonce = SHA-256(packageName + timestamp + 16 random bytes)
        var data = Encoding.UTF8.GetBytes(
            $"{_context.PackageName}:{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}");
        var random = RandomNumberGenerator.GetBytes(16);
        var combined = new byte[data.Length + random.Length];
        data.CopyTo(combined, 0);
        random.CopyTo(combined, data.Length);
        return SHA256.HashData(combined);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _attestTimer?.Dispose();
    }
}

/// <summary>
/// Represents a Play Integrity API verdict result.
/// </summary>
public record IntegrityVerdict(
    bool MeetsBasicIntegrity,
    bool MeetsDeviceIntegrity,
    bool MeetsStrongIntegrity,
    bool AppRecognized,
    string VerificationMethod,
    DateTime Timestamp);
