/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Microsoft.Diagnostics.Runtime;
using System;
using System.Collections.Generic;

namespace NativeProcesses.Core.Inspection.Heuristics
{
    public class RuntimeIlScanner
    {
        // OpCodes
        private const byte Op_Calli = 0x29;
        private const byte Op_Stsfld = 0x80;
        private const byte Op_Prefix_FE = 0xFE;

        // FE-Prefix Codes
        private const byte Op_Localloc = 0x0F;
        private const byte Op_Ldftn = 0x06;
        private const byte Op_Cpblk = 0x17;
        private const byte Op_Initblk = 0x18;

        public IEnumerable<HeuristicResult> Scan(ClrRuntime runtime)
        {
            var results = new List<HeuristicResult>();
            var scannedTypes = new HashSet<ClrType>();

            if (runtime.Heap.CanWalkHeap)
            {
                foreach (var obj in runtime.Heap.EnumerateObjects())
                {
                    var type = obj.Type;
                    if (type == null || !scannedTypes.Add(type)) continue;

                    var module = type.Module;
                    if (module == null || !IsTargetModule(module)) continue;

                    foreach (var method in type.Methods)
                    {
                        var ilBytes = IlExtractor.GetMethodIL(method);
                        if (ilBytes.Length == 0) continue;

                        // 1. Calli (Indirect Native Call)
                        if (ContainsOpCode(ilBytes, Op_Calli))
                        {
                            results.Add(CreateResult("Unsafe IL: Indirect Call (Calli)", ThreatScore.Critical, method, "OpCode: 0x29 (Calli)"));
                        }

                        // 2. Stsfld (Static Field Write - oft für Persistence/Global State in Loadern)
                        // Alleine harmlos, aber in dynamischen Modulen verdächtig.
                        if (module.IsDynamic && ContainsOpCode(ilBytes, Op_Stsfld))
                        {
                            results.Add(CreateResult("Unsafe IL: Static Field Write (Dynamic)", ThreatScore.Medium, method, "OpCode: 0x80 (Stsfld)"));
                        }

                        // 3. FE-Prefix Opcodes scannen
                        for (int i = 0; i < ilBytes.Length - 1; i++)
                        {
                            if (ilBytes[i] == Op_Prefix_FE)
                            {
                                byte next = ilBytes[i + 1];

                                if (next == Op_Localloc)
                                {
                                    results.Add(CreateResult("Unsafe IL: Stack Allocation", ThreatScore.High, method, "OpCode: 0xFE 0x0F (Localloc)"));
                                }
                                else if (next == Op_Ldftn)
                                {
                                    results.Add(CreateResult("Unsafe IL: Function Pointer Load", ThreatScore.High, method, "OpCode: 0xFE 0x06 (Ldftn)"));
                                }
                                else if (next == Op_Cpblk || next == Op_Initblk)
                                {
                                    results.Add(CreateResult("Unsafe IL: Memory Copy/Init", ThreatScore.High, method, "OpCode: 0xFE 0x17/18 (Cpblk/Initblk)"));
                                }
                            }
                        }
                    }
                }
            }
            return results;
        }

        private bool IsTargetModule(ClrModule module)
        {
            if (module.IsDynamic) return true;
            if (module.Layout == ModuleLayout.Flat) return true;
            if (string.IsNullOrEmpty(module.Name)) return true;
            return false;
        }

        private bool ContainsOpCode(byte[] il, byte opcode)
        {
            for (int i = 0; i < il.Length; i++)
            {
                if (il[i] == opcode) return true;
            }
            return false;
        }

        private HeuristicResult CreateResult(string name, ThreatScore score, ClrMethod method, string artifact)
        {
            return new HeuristicResult(
                name,
                ScanCategory.CodeInjection,
                score,
                $"Suspicious IL instruction in '{method.Signature ?? method.Name}'",
                method.NativeCode.ToString("X"),
                artifact
            );
        }
    }
}