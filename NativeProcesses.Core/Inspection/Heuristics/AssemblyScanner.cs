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
                // 1. Floating Assembly (Memory Load)
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

                // 2. Dynamic Module Analysis
                if (module.IsDynamic)
                {
                    if (IsSuspiciousDynamic(module.Name))
                    {
                        results.Add(new HeuristicResult(
                            "Suspicious Dynamic Module",
                            ScanCategory.CodeInjection,
                            ThreatScore.High,
                            "Dynamic Code Generation detected (Reflection.Emit).",
                            module.ImageBase.ToString("X"),
                            module.Name
                        ));
                    }
                }

                // 3. Name Obfuscation
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

                // 4. NEU: Abnormal Metadata / Missing PDB
                // Wir prüfen nur Nicht-Dynamische Module, die nicht von Microsoft sind (System.* hat oft PDBs, aber nicht immer im Speicher sichtbar)
                if (!module.IsDynamic && !IsSystemModule(module.Name))
                {
                    // PDB (Program Database) Info checken
                    if (module.Pdb == null)
                    {
                        // Ein User-Modul OHNE PDB-Info ist verdächtig (Stripped Malware)
                        results.Add(new HeuristicResult(
                            "Missing PDB Information",
                            ScanCategory.Obfuscation,
                            ThreatScore.Low,
                            "Module has no Debug Information (PDB). Often stripped by malware authors.",
                            module.ImageBase.ToString("X"),
                            "No PDB"
                        ));
                    }
                    else
                    {
                        // Check auf Mismatch: PDB Pfad vs. Modul Name (grobe Heuristik)
                        // Malware nutzt oft geklaute PDB Pfade ("C:\Users\Builder\Desktop\Project1.pdb")
                        string pdbPath = module.Pdb.Path;
                        if (pdbPath.Contains("Users") && (pdbPath.Contains("Desktop") || pdbPath.Contains("Temp")))
                        {
                            results.Add(new HeuristicResult(
                               "Suspicious PDB Path",
                               ScanCategory.General,
                               ThreatScore.Low,
                               $"PDB path indicates compilation on user desktop/temp: '{pdbPath}'",
                               module.ImageBase.ToString("X"),
                               pdbPath
                           ));
                        }
                    }
                }
            }
            return results;
        }

        private bool IsSystemModule(string name)
        {
            if (string.IsNullOrEmpty(name)) return false;
            if (name.StartsWith("System.") || name.StartsWith("Microsoft.") || name.Contains("mscorlib")) return true;
            if (name.Contains("\\Windows\\Microsoft.NET")) return true;
            return false;
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

            // Kurze, zufällige Namen oder unaussprechbare Zeichen
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