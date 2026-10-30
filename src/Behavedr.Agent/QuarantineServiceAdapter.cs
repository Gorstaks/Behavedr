using Behavedr.Core.Response;

namespace Behavedr.Agent;

/// <summary>
/// Adapts FileQuarantineAction (which has a private QuarantineFileAsync) to the
/// IQuarantineService interface that ChainTracer expects.
/// Since FileQuarantineAction.QuarantineFileAsync is private, this adapter uses
/// the public ExecuteAsync path with a minimal DetectionResult.
/// </summary>
internal sealed class QuarantineServiceAdapter : IQuarantineService
{
    private readonly FileQuarantineAction _action;

    public QuarantineServiceAdapter(FileQuarantineAction action)
    {
        _action = action;
    }

    public Task QuarantineAsync(string filePath, CancellationToken ct = default)
    {
        // FileQuarantineAction.ExecuteAsync expects a DetectionResult with signals
        // containing file paths. We construct a minimal one to trigger quarantine.
        var evt = Behavedr.Core.Models.DetectionEvent.Create("0", "chain_tracer", "quarantine", "ChainTracer");
        var signal = new Behavedr.Core.Models.Signal($"file_quarantine:{filePath}", 100, 1.0);
        var result = new Behavedr.Core.DetectionResult(evt, 100.0, true, [signal]);
        return _action.ExecuteAsync(result, ct);
    }
}
