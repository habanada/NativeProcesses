/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Mono.Cecil;
using Mono.Cecil.Cil;
using NativeProcesses.Core.Inspection.Heuristics;
using System.Collections.Generic;

namespace NativeProcesses.Core.Inspection.Static
{
    public class StaticIlScanner
    {
        public IEnumerable<HeuristicResult> Scan(ModuleDefinition module)
        {
            var results = new List<HeuristicResult>();

            foreach (TypeDefinition type in module.Types)
            {
                foreach (MethodDefinition method in type.Methods)
                {
                    if (!method.HasBody) continue;

                    bool hasLocalloc = false;
                    bool hasCalli = false;
                    bool hasPinnedLocal = false;

                    foreach (Instruction instr in method.Body.Instructions)
                    {
                        if (instr.OpCode == OpCodes.Localloc)
                        {
                            hasLocalloc = true;
                        }
                        else if (instr.OpCode == OpCodes.Calli)
                        {
                            hasCalli = true;
                        }
                    }

                    foreach (var variable in method.Body.Variables)
                    {
                        if (variable.IsPinned) hasPinnedLocal = true;
                    }

                    if (hasLocalloc)
                    {
                        results.Add(new HeuristicResult(
                            "Stack Buffer Allocation",
                            ScanCategory.CodeInjection,
                            ThreatScore.Medium,
                            $"Method '{method.Name}' uses 'localloc'. Often used for shellcode buffers on stack.",
                            type.Name,
                            "OpCode: localloc"
                        ));
                    }

                    if (hasCalli)
                    {
                        results.Add(new HeuristicResult(
                            "Indirect Call (Calli)",
                            ScanCategory.CodeInjection,
                            ThreatScore.High,
                            $"Method '{method.Name}' uses 'calli' to execute unmanaged pointers. Typical for shellcode execution.",
                            type.Name,
                            "OpCode: calli"
                        ));
                    }

                    if (hasPinnedLocal && hasLocalloc)
                    {
                        results.Add(new HeuristicResult(
                            "Pinned Stack Buffer",
                            ScanCategory.CodeInjection,
                            ThreatScore.High,
                            $"Method '{method.Name}' pins local variables and allocates stack memory. Suspicious combination.",
                            type.Name,
                            "Pinned + Localloc"
                        ));
                    }
                }
            }

            return results;
        }
    }
}