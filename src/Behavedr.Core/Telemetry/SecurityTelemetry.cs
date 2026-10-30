namespace Behavedr.Core.Telemetry;

/// <summary>
/// Process-wide security event hooks so Core crypto/update code can emit metrics
/// without taking a hard DI dependency at call sites.
/// Wired from the agent host to <see cref="BehavedrMetrics"/>.
/// </summary>
public static class SecurityTelemetry
{
    public static Action? OnSignatureFailure { get; set; }
    public static Action? OnIsolationAction { get; set; }
    public static Action<string>? OnPlatformSoftFail { get; set; }

    public static void ReportSignatureFailure() => OnSignatureFailure?.Invoke();
    public static void ReportIsolationAction() => OnIsolationAction?.Invoke();
    public static void ReportPlatformSoftFail(string feature) => OnPlatformSoftFail?.Invoke(feature);
}
