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
    public class AssemblyScanner
    {
        public IEnumerable<HeuristicResult> Scan(ClrRuntime runtime)
        {
            var results = new List<HeuristicResult>();

            foreach (var module in runtime.EnumerateModules())
            {
                if (module.Layout == ModuleLayout.Flat && !module.IsDynamic)
                {
                    results.Add(new HeuristicResult(
                        "Floating Assembly",
                        ScanCategory.CodeInjection,
                        ThreatScore.Critical,
                        $"Module loaded from memory (Reflective Load/Assembly.Load). Base: 0x{module.ImageBase:X}",
                        module.ImageBase.ToString("X"),
                        module.Name ?? "Unknown"
                    ));
                }

                if (module.IsDynamic)
                {
                    if (IsSuspiciousDynamic(module.Name))
                    {
                        results.Add(new HeuristicResult(
                            "Suspicious Dynamic Module",
                            ScanCategory.CodeInjection,
                            ThreatScore.High,
                            "Dynamic Code Generation detected (Reflection.Emit / DynamicMethod). Often used by unpackers.",
                            module.ImageBase.ToString("X"),
                            module.Name
                        ));
                    }
                }

                if (IsObfuscatedName(module.Name))
                {
                    results.Add(new HeuristicResult(
                        "Obfuscated Module Name",
                        ScanCategory.Obfuscation,
                        ThreatScore.Medium,
                        "Module name appears randomized or obfuscated.",
                        module.ImageBase.ToString("X"),
                        module.Name
                    ));
                }
            }
            return results;
        }

        private bool IsSuspiciousDynamic(string name)
        {
            if (string.IsNullOrEmpty(name)) return true;
            if (name.Contains("Anonymously Hosted DynamicMethods")) return false;
            if (name.Contains("System.Xml")) return false;
            if (name.Contains("Workflow")) return false;
            return true;
        }

        private bool IsObfuscatedName(string name)
        {
            if (string.IsNullOrEmpty(name)) return false;
            string filename = System.IO.Path.GetFileName(name);

            if (filename.Length < 5 && !filename.EndsWith(".dll") && !filename.EndsWith(".exe"))
                return true;

            foreach (char c in filename)
            {
                if (c < 32 || (c > 126 && c < 160)) return true;
            }
            return false;
        }
    }
}