/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Microsoft.Diagnostics.Runtime;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NativeProcesses.Core.Inspection.Heuristics
{
    public class DynamicMethodScanner
    {
        public IEnumerable<HeuristicResult> Scan(ClrRuntime runtime)
        {
            var results = new List<HeuristicResult>();

            // Wir nutzen ein HashSet, um jeden Typ nur einmal zu analysieren,
            // auch wenn es tausende Objekte dieses Typs gibt.
            var scannedTypes = new HashSet<ClrType>();

            // Zähler für Module, um "Flood" (zu viele dynamische Methoden) zu erkennen
            var moduleMethodCounts = new Dictionary<ulong, int>();
            var moduleNames = new Dictionary<ulong, string>();

            // 1. Heap scannen, um Typen zu finden
            if (runtime.Heap.CanWalkHeap)
            {
                foreach (var obj in runtime.Heap.EnumerateObjects())
                {
                    var type = obj.Type;

                    // Wenn Typ null ist oder wir ihn schon gescannt haben -> weiter
                    if (type == null || !scannedTypes.Add(type)) continue;

                    var module = type.Module;
                    if (module == null) continue;

                    // 2. Prüfen, ob das Modul dynamisch ist
                    if (module.IsDynamic)
                    {
                        // 3. Methoden des Typs scannen
                        foreach (var method in type.Methods)
                        {
                            if (IsSuspiciousDynamicMethod(method))
                            {
                                // Zählen für Statistik
                                ulong modBase = module.ImageBase;
                                if (!moduleMethodCounts.ContainsKey(modBase))
                                {
                                    moduleMethodCounts[modBase] = 0;
                                    moduleNames[modBase] = module.Name ?? "UnknownDynamic";
                                }
                                moduleMethodCounts[modBase]++;

                                // IL-Analyse: Ist der Code groß genug für eine Payload?
                                var ilInfo = method.GetILInfo();
                                if (ilInfo != null && ilInfo.Length > 100)
                                {
                                    results.Add(new HeuristicResult(
                                        "JIT/Dynamic Payload",
                                        ScanCategory.CodeInjection,
                                        ThreatScore.High,
                                        $"Dynamic method detected with significant IL body ({ilInfo.Length} bytes). Potential in-memory compilation.",
                                        ilInfo.Address.ToString("X"),
                                        method.Signature ?? "UnknownSig"
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            // 4. Flood-Erkennung auswerten
            foreach (var kvp in moduleMethodCounts)
            {
                if (kvp.Value > 50)
                {
                    results.Add(new HeuristicResult(
                        "Dynamic Code Flood",
                        ScanCategory.Obfuscation,
                        ThreatScore.Medium,
                        $"Module '{moduleNames[kvp.Key]}' contains {kvp.Value} dynamic methods. Typical for obfuscators like ConfuserEx.",
                        kvp.Key.ToString("X"),
                        "Count: " + kvp.Value
                    ));
                }
            }

            return results;
        }

        private bool IsSuspiciousDynamicMethod(ClrMethod method)
        {
            if (method.Type == null) return true;

            string typeName = method.Type.Name;
            if (string.IsNullOrEmpty(typeName)) return true;

            // Whitelist für legitime dynamische Methoden
            if (typeName == "System.Text.RegularExpressions.RegexRunner") return false;
            if (typeName.Contains("System.Linq")) return false;
            if (typeName.Contains("System.Xml.Serialization")) return false;

            return true;
        }
    }
}