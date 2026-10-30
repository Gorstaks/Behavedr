namespace Behavedr.Core.Models;

/// <summary>
/// A behavioral signal collected from a platform monitor.
/// </summary>
/// <param name="Type">Signal category (e.g., "process_injection", "file_access").</param>
/// <param name="Weight">Relative importance [0..100].</param>
/// <param name="Confidence">Detection confidence [0..1].</param>
public record Signal(string Type, double Weight, double Confidence)
{
    /// <summary>Effective contribution to the composite score.</summary>
    public double EffectiveScore => Math.Clamp(Weight, 0, 100) * Math.Clamp(Confidence, 0, 1);
}
