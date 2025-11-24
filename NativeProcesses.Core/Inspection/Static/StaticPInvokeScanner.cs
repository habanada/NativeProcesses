/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Mono.Cecil;
using NativeProcesses.Core.Inspection.Heuristics;
using System;
using System.Collections.Generic;

namespace NativeProcesses.Core.Inspection.Static
{
    public class StaticPInvokeScanner
    {
        private static readonly HashSet<string> SuspiciousApis = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
            "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
            "NtMapViewOfSection", "NtUnmapViewOfSection", "RtlMoveMemory",
            "SetThreadContext", "GetThreadContext", "ResumeThread",
            "LoadLibrary", "GetProcAddress", "FreeConsole", "AllocConsole",
            "Wow64SetThreadContext", "QueueUserAPC", "SamIConnect"
        };

        public IEnumerable<HeuristicResult> Scan(ModuleDefinition module)
        {
            var results = new List<HeuristicResult>();

            if (!module.HasTypes) return results;

            foreach (TypeDefinition type in module.Types)
            {
                if (!type.HasMethods) continue;

                foreach (MethodDefinition method in type.Methods)
                {
                    if (!method.IsPInvokeImpl || method.PInvokeInfo == null) continue;

                    string moduleRef = method.PInvokeInfo.Module.Name;
                    string entryPoint = method.PInvokeInfo.EntryPoint ?? method.Name;

                    if (SuspiciousApis.Contains(entryPoint))
                    {
                        ThreatScore score = ThreatScore.High;
                        if (entryPoint.StartsWith("Virtual") || entryPoint == "WriteProcessMemory") score = ThreatScore.Critical;

                        results.Add(new HeuristicResult(
                            "Risky P/Invoke Detected",
                            ScanCategory.CodeInjection,
                            score,
                            $"Native API import detected: {entryPoint} (from {moduleRef}). Typical for Loaders/Injectors.",
                            "Static Import",
                            entryPoint
                        ));
                    }
                }
            }

            return results;
        }
    }
}