/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using NativeProcesses.Core.Engine;
using NativeProcesses.Core.Inspection;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NativeProcesses.Core.Inspection.Heuristics
{
    public class BehavioralAnalyzer
    {
        public List<PeAnomalyInfo> Analyze(int pid, List<BehaviorEvent> history)
        {
            var anomalies = new List<PeAnomalyInfo>();
            if (history == null || history.Count < 2) return anomalies;

            // Sortieren nach Zeit (wichtig für Sequenzen)
            var sorted = history.OrderBy(x => x.Time).ToList();

            // 1. Pattern: Reflective Injection Sequence
            // Alloc(RW) -> Protect(RX/RWX)
            // Das machen legitime Programme selten manuell (außer JIT).
            // Wir filtern JIT Events raus, um False Positives zu vermeiden.

            for (int i = 0; i < sorted.Count - 1; i++)
            {
                var evt1 = sorted[i];

                if (evt1.Type == BehaviorEventType.VirtualAlloc && evt1.Details.Contains("READWRITE"))
                {
                    // Suche nach nachfolgendem Protect auf gleicher/ähnlicher Adresse
                    for (int j = i + 1; j < sorted.Count; j++)
                    {
                        var evt2 = sorted[j];
                        // Zeitfenster: Max 2 Sekunden
                        if ((evt2.Time - evt1.Time).TotalSeconds > 2) break;

                        if (evt2.Type == BehaviorEventType.VirtualProtect &&
                            evt2.Details.Contains("EXECUTE") &&
                            Math.Abs(evt2.Address - evt1.Address) < 0x1000)
                        {
                            // Ausschluss: War das der JIT?
                            bool isJit = sorted.Any(x => x.Type == BehaviorEventType.JitCompile &&
                                                    x.Time >= evt1.Time && x.Time <= evt2.Time);

                            if (!isJit)
                            {
                                anomalies.Add(new PeAnomalyInfo
                                {
                                    ModuleName = "Behavior Analysis",
                                    AnomalyType = "Reflective Loader Pattern",
                                    Details = $"Sequence detected: Alloc(RW) -> Protect(RX) at {evt1.Address:X}. No JIT correlation found.",
                                    Severity = "Critical"
                                });
                            }
                        }
                    }
                }
            }

            // 2. Pattern: .NET JIT Spraying / Massive Dynamic Code
            int jitCount = sorted.Count(x => x.Type == BehaviorEventType.JitCompile);
            int allocExecCount = sorted.Count(x => x.Type == BehaviorEventType.VirtualAlloc && x.Details.Contains("EXECUTE"));

            if (jitCount > 50 && allocExecCount > 20)
            {
                anomalies.Add(new PeAnomalyInfo
                {
                    ModuleName = "Behavior Analysis",
                    AnomalyType = "JIT Spraying / Mass Compilation",
                    Details = $"High burst of JIT events ({jitCount}) combined with memory allocations. Potential Exploit Preparation.",
                    Severity = "High"
                });
            }

            // 3. Pattern: Suspicious Interop (P/Invoke)
            // Wenn "VirtualAlloc" via Interop gerufen wird
            foreach (var evt in sorted)
            {
                if (evt.Type == BehaviorEventType.InteropCall &&
                   (evt.Details.Contains("VirtualAlloc") || evt.Details.Contains("WriteProcessMemory")))
                {
                    anomalies.Add(new PeAnomalyInfo
                    {
                        ModuleName = "Behavior Analysis",
                        AnomalyType = "Suspicious P/Invoke",
                        Details = $"Native API call detected via .NET Interop: {evt.Details}",
                        Severity = "Medium"
                    });
                }
            }

            return anomalies;
        }
    }
}