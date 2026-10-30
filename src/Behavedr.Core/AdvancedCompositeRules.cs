namespace Behavedr.Core;

using Behavedr.Core.Models;

/// <summary>
/// Advanced composite correlation rules - ported from Sentinel v2.0.
/// Extends BehavioralCorrelationEngine with 20+ hand-authored multi-signal composites
/// that catch specific attack patterns at high confidence (0.88-0.99).
///
/// Each rule requires 2+ distinct signal categories on the same PID within the
/// correlation window (120s). Rules are evaluated per-process and produce
/// high-confidence composite signals that trigger immediate response.
/// </summary>
public static class AdvancedCompositeRules
{
    /// <summary>
    /// Evaluate all advanced composite rules against current signal state.
    /// Returns composite signals for any matches found.
    /// </summary>
    public static List<Signal> Evaluate(
        string processId,
        HashSet<string> categories,
        Dictionary<string, int> signalCounts)
    {
        var composites = new List<Signal>();

        //  Ransomware 
        // Shadow copy deletion + bulk file encryption + persistence
        if (categories.Contains("Ransomware") &&
            (categories.Contains("Persistence") || categories.Contains("Evasion")))
        {
            composites.Add(new Signal(
                $"composite:active_ransomware_chain:pid:{processId}", 99, 0.99));
        }

        //  Injected C2 Beacon 
        // Process injection + C2 beaconing on same PID
        if (categories.Contains("Injection") && categories.Contains("C2"))
        {
            composites.Add(new Signal(
                $"composite:injected_c2_beacon:pid:{processId}", 98, 0.98));
        }

        //  Credential Dump + Exfiltration 
        if (categories.Contains("Credential") && categories.Contains("Exfil"))
        {
            composites.Add(new Signal(
                $"composite:credential_dump_exfil:pid:{processId}", 96, 0.96));
        }

        //  Credential Dump + Network 
        if (categories.Contains("Credential") && categories.Contains("Network"))
        {
            composites.Add(new Signal(
                $"composite:credential_theft_network:pid:{processId}", 95, 0.95));
        }

        //  In-Memory Implant 
        if (categories.Contains("Injection") && categories.Contains("Network"))
        {
            composites.Add(new Signal(
                $"composite:in_memory_implant:pid:{processId}", 96, 0.96));
        }

        //  Fileless Attack Chain 
        if (categories.Contains("Evasion") &&
            (categories.Contains("Network") || categories.Contains("C2")))
        {
            composites.Add(new Signal(
                $"composite:fileless_attack_chain:pid:{processId}", 95, 0.95));
        }

        //  DGA + C2 Beaconing 
        if (categories.Contains("Dns") && categories.Contains("C2"))
        {
            composites.Add(new Signal(
                $"composite:dga_c2_beaconing:pid:{processId}", 94, 0.94));
        }

        //  Covert RAT 
        // Unsigned binary + staging path + network activity
        if (categories.Contains("Unsigned") && categories.Contains("Network"))
        {
            composites.Add(new Signal(
                $"composite:covert_rat:pid:{processId}", 92, 0.92));
        }

        //  Named Pipe C2 + Network 
        if (categories.Contains("Lateral") && categories.Contains("C2"))
        {
            composites.Add(new Signal(
                $"composite:named_pipe_c2:pid:{processId}", 95, 0.95));
        }

        //  Token Theft + Lateral Movement 
        if (categories.Contains("TokenTheft") && categories.Contains("Lateral"))
        {
            composites.Add(new Signal(
                $"composite:token_theft_lateral:pid:{processId}", 93, 0.93));
        }

        //  Privilege Escalation + Network 
        if (categories.Contains("PrivilegeEscalation") && categories.Contains("Network"))
        {
            composites.Add(new Signal(
                $"composite:privesc_network:pid:{processId}", 90, 0.90));
        }

        //  LPE Campaign Scaffold 
        if (categories.Contains("PrivilegeEscalation") && categories.Contains("Persistence"))
        {
            composites.Add(new Signal(
                $"composite:lpe_campaign_scaffold:pid:{processId}", 93, 0.93));
        }

        //  Initial Access Execution Chain 
        // Download/dropper + execution + persistence
        if (categories.Contains("Network") && categories.Contains("Persistence"))
        {
            composites.Add(new Signal(
                $"composite:initial_access_chain:pid:{processId}", 92, 0.92));
        }

        //  Dropped Payload Active 
        if (categories.Contains("Unsigned") && categories.Contains("Persistence"))
        {
            composites.Add(new Signal(
                $"composite:dropped_payload:pid:{processId}", 93, 0.93));
        }

        //  Evasion + Persistence 
        if (categories.Contains("Evasion") && categories.Contains("Persistence"))
        {
            composites.Add(new Signal(
                $"composite:evasion_persistence:pid:{processId}", 91, 0.91));
        }

        //  Reverse Shell Active 
        if (categories.Contains("ReverseShell") && categories.Contains("Network"))
        {
            composites.Add(new Signal(
                $"composite:reverse_shell_active:pid:{processId}", 97, 0.97));
        }

        //  BYOVD Attack Chain 
        if (categories.Contains("BYOVD") &&
            (categories.Contains("PrivilegeEscalation") || categories.Contains("Evasion")))
        {
            composites.Add(new Signal(
                $"composite:byovd_attack_chain:pid:{processId}", 98, 0.98));
        }

        //  Surveillance + Remote Channel (Stalkerware) 
        if (categories.Contains("Surveillance") && categories.Contains("C2"))
        {
            composites.Add(new Signal(
                $"composite:surveillance_remote_channel:pid:{processId}", 94, 0.94));
        }

        //  Stalkerware Persistence 
        if (categories.Contains("Surveillance") && categories.Contains("Persistence"))
        {
            composites.Add(new Signal(
                $"composite:stalkerware_persistence:pid:{processId}", 92, 0.92));
        }

        //  Session Theft + Abuse Channel 
        if (categories.Contains("TokenTheft") && categories.Contains("C2"))
        {
            composites.Add(new Signal(
                $"composite:session_theft_abuse:pid:{processId}", 95, 0.95));
        }

        //  Remote Control Abuse Toolkit 
        if (categories.Contains("Surveillance") && categories.Contains("Lateral"))
        {
            composites.Add(new Signal(
                $"composite:remote_control_toolkit:pid:{processId}", 93, 0.93));
        }

        //  Supply Chain Runtime Attack 
        if (categories.Contains("Unsigned") && categories.Contains("PrivilegeEscalation"))
        {
            composites.Add(new Signal(
                $"composite:supply_chain_runtime:pid:{processId}", 91, 0.91));
        }

        return composites;
    }
}
