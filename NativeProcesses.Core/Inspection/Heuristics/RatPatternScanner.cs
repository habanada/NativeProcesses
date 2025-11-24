/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Microsoft.Diagnostics.Runtime;
using System;
using System.Collections.Generic;

namespace NativeProcesses.Core.Inspection.Heuristics
{
    public class RatPatternScanner
    {
        public IEnumerable<HeuristicResult> Scan(ClrHeap heap)
        {
            var results = new List<HeuristicResult>();
            bool nanoCoreFound = false;
            bool agentTeslaFound = false;
            bool confuserFound = false;

            foreach (var obj in heap.EnumerateObjects())
            {
                if (obj.Type == null || string.IsNullOrEmpty(obj.Type.Name)) continue;
                string name = obj.Type.Name;

                if (!nanoCoreFound && (name.Contains("Client.Network") || name.Contains("NanoCore")))
                {
                    results.Add(new HeuristicResult(
                        "RAT Signature: NanoCore",
                        ScanCategory.StealerArtifact,
                        ThreatScore.Critical,
                        $"Identified NanoCore RAT specific class: {name}",
                        obj.Address.ToString("X"),
                        name
                    ));
                    nanoCoreFound = true;
                }

                if (!agentTeslaFound && (
                    name.Contains("RecoveredApplication") ||
                    name.Contains("Credentials") && !name.StartsWith("System") ||
                    name.Contains("AccountGrabber")))
                {
                    results.Add(new HeuristicResult(
                        "RAT Signature: AgentTesla/Stealer",
                        ScanCategory.StealerArtifact,
                        ThreatScore.High,
                        $"Identified InfoStealer artifact: {name}",
                        obj.Address.ToString("X"),
                        name
                    ));
                    agentTeslaFound = true;
                }

                if (!confuserFound && (name.Contains("ConfusedByAttribute") || name.Contains("Confuser")))
                {
                    results.Add(new HeuristicResult(
                        "Obfuscator: ConfuserEx",
                        ScanCategory.Obfuscation,
                        ThreatScore.Medium,
                        "Process is protected by ConfuserEx obfuscator.",
                        obj.Address.ToString("X"),
                        name
                    ));
                    confuserFound = true;
                }
            }

            return results;
        }
    }
}