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
        private const byte Op_Calli = 0x29;
        private const byte Op_Localloc = 0xFE;
        private const byte Op_Ldftn = 0xFE;
        private const byte Op_Cpblk = 0xFE;

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

                        if (ContainsOpCode(ilBytes, Op_Calli))
                        {
                            results.Add(new HeuristicResult(
                                "Unsafe IL: Indirect Call",
                                ScanCategory.CodeInjection,
                                ThreatScore.Critical,
                                $"Method '{method.Name}' uses 'calli' instruction. This executes raw function pointers (Shellcode).",
                                method.NativeCode.ToString("X"),
                                "OpCode: calli"
                            ));
                        }

                        if (ContainsSequence(ilBytes, new byte[] { 0xFE, 0x0F }))
                        {
                            results.Add(new HeuristicResult(
                                "Unsafe IL: Stack Allocation",
                                ScanCategory.CodeInjection,
                                ThreatScore.High,
                                $"Method '{method.Name}' uses 'localloc'. Often used to allocate shellcode buffers on stack.",
                                method.NativeCode.ToString("X"),
                                "OpCode: localloc"
                            ));
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