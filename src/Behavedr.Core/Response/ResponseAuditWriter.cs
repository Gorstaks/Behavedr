namespace Behavedr.Core.Response;

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Behavedr.Core.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Append-only JSONL audit trail for response actions.
/// Each line is a sealed record (HMAC over payload when machine key available).
/// Path: logs/response-audit.jsonl under the agent working directory.
/// </summary>
public sealed class ResponseAuditWriter
{
    public const string RelativePath = "logs/response-audit.jsonl";
    private readonly ILogger _logger;
    private readonly object _lock = new();
    private readonly string _path;

    public ResponseAuditWriter(string? baseDirectory = null, ILogger? logger = null)
    {
        _logger = logger ?? NullLogger.Instance;
        var root = baseDirectory ?? AppContext.BaseDirectory;
        _path = Path.Combine(root, RelativePath);
    }

    public void Append(
        DetectionResult result,
        IReadOnlyList<ResponseOutcome> outcomes,
        string policyMode)
    {
        if (outcomes.Count == 0)
            return;

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);

            foreach (var outcome in outcomes)
            {
                var record = new
                {
                    ts = DateTime.UtcNow.ToString("O"),
                    policy = policyMode,
                    score = result.Score,
                    presidentKill = result.PresidentKill,
                    pid = result.Event.ProcessId,
                    process = result.Event.ProcessName,
                    behavior = result.Event.BehaviorType,
                    source = result.Event.Source,
                    action = outcome.ActionName,
                    success = outcome.Success,
                    skipped = outcome.Message.StartsWith("Skipped:", StringComparison.Ordinal),
                    message = outcome.Message,
                    signals = result.Signals.Select(s => s.Type).Take(32).ToArray(),
                };

                var payload = JsonSerializer.Serialize(record);
                var mac = ComputeMac(payload);
                var line = mac is null
                    ? payload
                    : JsonSerializer.Serialize(new { payload = record, hmac = mac });

                lock (_lock)
                {
                    File.AppendAllText(_path, line + Environment.NewLine, Encoding.UTF8);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Response audit write failed");
        }
    }

    private static string? ComputeMac(string payload)
    {
        try
        {
            var key = KeyProtection.GetMachineKey();
            if (key is not { Length: > 0 })
                return null;
            using var hmac = new HMACSHA256(key);
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
            return Convert.ToHexString(hash);
        }
        catch
        {
            return null;
        }
    }
}
