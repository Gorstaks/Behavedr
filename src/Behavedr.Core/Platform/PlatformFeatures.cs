namespace Behavedr.Core.Platform;

/// <summary>
/// Optional platform depth toggles (0.2.9). Bound from appsettings "Platform" section
/// or environment variables. Defaults keep safe AlertOnly / soft-fail behavior.
/// </summary>
public sealed class PlatformFeatures
{
    /// <summary>Enable Linux Landlock self-restriction after monitors start.</summary>
    public bool EnableLandlock { get; set; }

    /// <summary>Linux fanotify FAN_OPEN_EXEC_PERM allowlist mode (dangerous if misconfigured).</summary>
    public bool EnableFanotifyPerm { get; set; }

    /// <summary>Prefer WFP over advfirewall on Windows isolation.</summary>
    public bool PreferWfp { get; set; } = true;

    /// <summary>macOS EndpointSecurity AUTH mode (also BEHAVEDR_ES_AUTH=1).</summary>
    public bool EnableEndpointSecurityAuth { get; set; }

    /// <summary>Android / Play Integrity fail-closed.</summary>
    public bool RequirePlayIntegrity { get; set; }

    public static PlatformFeatures Default => new();

    public static PlatformFeatures FromEnvironment(PlatformFeatures? baseConfig = null)
    {
        var b = baseConfig ?? Default;
        return new PlatformFeatures
        {
            EnableLandlock = b.EnableLandlock || EnvFlag("BEHAVEDR_LANDLOCK"),
            EnableFanotifyPerm = b.EnableFanotifyPerm || EnvFlag("BEHAVEDR_FANOTIFY_PERM"),
            PreferWfp = b.PreferWfp,
            EnableEndpointSecurityAuth = b.EnableEndpointSecurityAuth || EnvFlag("BEHAVEDR_ES_AUTH"),
            RequirePlayIntegrity = b.RequirePlayIntegrity || EnvFlag("BEHAVEDR_REQUIRE_PLAY_INTEGRITY"),
        };
    }

    private static bool EnvFlag(string name) =>
        string.Equals(Environment.GetEnvironmentVariable(name), "1", StringComparison.Ordinal);
}
