/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Microsoft.Diagnostics.Runtime;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NativeProcesses.Core.Inspection.Heuristics
{
    public class DynamicMethodScanner
    {
        public IEnumerable<HeuristicResult> Scan(ClrRuntime runtime)
        {
            var results = new List<HeuristicResult>();
            var scannedTypes = new HashSet<ClrType>();

            // Cache für Flood-Detection
            var moduleMethodCounts = new Dictionary<ulong, int>();
            var moduleNames = new Dictionary<ulong, string>();

            // Wir iterieren über den Heap, um Typen zu finden (ClrMD 3.1 Workaround)
            if (runtime.Heap.CanWalkHeap)
            {
                foreach (var obj in runtime.Heap.EnumerateObjects())
                {
                    var type = obj.Type;
                    if (type == null || !scannedTypes.Add(type)) continue;

                    var module = type.Module;
                    if (module == null || !module.IsDynamic) continue;

                    foreach (var method in type.Methods)
                    {
                        if (IsSuspiciousDynamicMethod(method))
                        {
                            // Flood Stats
                            ulong modBase = module.ImageBase;
                            if (!moduleMethodCounts.ContainsKey(modBase))
                            {
                                moduleMethodCounts[modBase] = 0;
                                moduleNames[modBase] = module.Name ?? "UnknownDynamic";
                            }
                            moduleMethodCounts[modBase]++;

                            // IL DUMPING LOGIC
                            var ilBytes = IlExtractor.GetMethodIL(method);

                            // Nur relevante Größen (zu klein = Stub, zu groß = unwahrscheinlich für reinen Shellcode Wrapper)
                            if (ilBytes.Length > 16)
                            {
                                // Wir scannen direkt hier kurz auf kritische OpCodes
                                // Das ist effizienter als ein zweiter Pass im RuntimeIlScanner
                                string ilHex = BitConverter.ToString(ilBytes).Replace("-", " ");

                                // Pattern 1: Calli (Indirect Call -> Shellcode)
                                if (ContainsOpCode(ilBytes, 0x29)) // Calli
                                {
                                    results.Add(new HeuristicResult(
                                        "Dynamic Method with Calli",
                                        ScanCategory.CodeInjection,
                                        ThreatScore.Critical,
                                        $"Dynamic method executes indirect pointers (Shellcode Runner). IL Size: {ilBytes.Length}",
                                        method.NativeCode.ToString("X"),
                                        ilHex // Wir speichern den IL-Dump direkt im Artefakt!
                                    ));
                                }
                                // Pattern 2: Localloc (Stack Buffer -> Shellcode)
                                else if (ContainsSequence(ilBytes, new byte[] { 0xFE, 0x0F })) // Localloc
                                {
                                    results.Add(new HeuristicResult(
                                        "Dynamic Method with Localloc",
                                        ScanCategory.CodeInjection,
                                        ThreatScore.High,
                                        $"Dynamic method allocates stack buffer. Potential Shellcode storage.",
                                        method.NativeCode.ToString("X"),
                                        ilHex
                                    ));
                                }
                                // Pattern 3: Generic Suspicious (Large Body)
                                else if (ilBytes.Length > 100)
                                {
                                    // Wir speichern es als "High", damit man es sich ansehen kann
                                    results.Add(new HeuristicResult(
                                        "Suspicious Dynamic Payload",
                                        ScanCategory.Obfuscation,
                                        ThreatScore.Medium, // Medium, weil es auch legit sein kann (z.B. RegEx)
                                        $"Large dynamic method body ({ilBytes.Length} bytes). Potential unpacked code.",
                                        method.NativeCode.ToString("X"),
                                        ilHex
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            // Flood Detection
            foreach (var kvp in moduleMethodCounts)
            {
                if (kvp.Value > 50)
                {
                    results.Add(new HeuristicResult(
                        "Dynamic Code Flood",
                        ScanCategory.Obfuscation,
                        ThreatScore.Medium,
                        $"Module '{moduleNames[kvp.Key]}' contains {kvp.Value} dynamic methods. Typical for obfuscators.",
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

            if (typeName == "System.Text.RegularExpressions.RegexRunner") return false;
            if (typeName.Contains("System.Linq")) return false;
            if (typeName.Contains("System.Xml.Serialization")) return false;
            if (typeName.Contains("Microsoft.Extensions")) return false;

            return true;
        }

        private bool ContainsOpCode(byte[] il, byte opcode)
        {
            for (int i = 0; i < il.Length; i++) if (il[i] == opcode) return true;
            return false;
        }

        private bool ContainsSequence(byte[] buffer, byte[] pattern)
        {
            int len = pattern.Length;
            int limit = buffer.Length - len;
            for (int i = 0; i <= limit; i++)
            {
                int k = 0;
                for (; k < len; k++) if (pattern[k] != buffer[i + k]) break;
                if (k == len) return true;
            }
            return false;
        }
    }
}