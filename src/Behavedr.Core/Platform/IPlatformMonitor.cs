namespace Behavedr.Core.Platform;

public interface IPlatformMonitor
{
    /// <summary>Human-readable platform label (Windows, Android, ...).</summary>
    string PlatformName { get; }

    bool IsSupported { get; }

    Task<IEnumerable<Models.Signal>> GetSignalsAsync(CancellationToken ct = default);
}
