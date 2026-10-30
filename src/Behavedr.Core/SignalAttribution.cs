namespace Behavedr.Core;

using System.Text.RegularExpressions;
using Behavedr.Core.Models;

/// <summary>
/// Groups cycle signals by attributed PID. Never copies a machine-wide score onto a PID.
/// </summary>
public static class SignalAttribution
{
    private static readonly Regex PidRegex = new(@":pid:(\d+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static List<(int Pid, string ProcessName, List<Signal> Signals)> GroupByPid(IEnumerable<Signal> signals)
    {
        var byPid = new Dictionary<int, (string Name, List<Signal> Signals)>();

        foreach (var signal in signals)
        {
            var match = PidRegex.Match(signal.Type);
            if (!match.Success) continue;
            if (!int.TryParse(match.Groups[1].Value, out var pid) || pid <= 4) continue;

            var procName = InferProcessName(signal.Type);
            if (!byPid.TryGetValue(pid, out var entry))
            {
                entry = (procName, new List<Signal>());
                byPid[pid] = entry;
            }
            else if (string.IsNullOrEmpty(entry.Name) && !string.IsNullOrEmpty(procName))
            {
                entry = (procName, entry.Signals);
                byPid[pid] = entry;
            }
            entry.Signals.Add(signal);
        }

        return byPid.Select(kv => (kv.Key, kv.Value.Name, kv.Value.Signals)).ToList();
    }

    /// <summary>
    /// Composite signals are <c>composite:rule:pid:N</c> - that is not a process name.
    /// Prefer <c>type:processname:pid:N</c> when present.
    /// </summary>
    private static string InferProcessName(string type)
    {
        if (type.StartsWith("composite:", StringComparison.OrdinalIgnoreCase))
            return "";

        var parts = type.Split(':');
        if (parts.Length >= 2
            && !parts[1].Equals("pid", StringComparison.OrdinalIgnoreCase)
            && !int.TryParse(parts[1], out _))
        {
            return parts[1];
        }

        return "";
    }
}
