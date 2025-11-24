/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Mono.Cecil;
using NativeProcesses.Core.Inspection.Heuristics;
using System.Collections.Generic;

namespace NativeProcesses.Core.Inspection.Static
{
    public class StaticResourceScanner
    {
        public IEnumerable<HeuristicResult> Scan(ModuleDefinition module)
        {
            var results = new List<HeuristicResult>();

            if (!module.HasResources) return results;

            foreach (Resource resource in module.Resources)
            {
                if (resource.ResourceType != ResourceType.Embedded) continue;

                var embedded = (EmbeddedResource)resource;
                byte[] data = embedded.GetResourceData();

                if (data.Length > 1024)
                {
                    double entropy = EntropyCalculator.Calculate(data, data.Length);

                    if (entropy > 7.0)
                    {
                        results.Add(new HeuristicResult(
                            "High Entropy Resource",
                            ScanCategory.Obfuscation,
                            ThreatScore.High,
                            $"Embedded resource '{resource.Name}' has high entropy ({entropy:F2}). Likely encrypted payload or compressed DLL.",
                            "Resource",
                            $"Size: {data.Length}, Entropy: {entropy:F2}"
                        ));
                    }

                    if (data.Length > 2 && data[0] == 0x4D && data[1] == 0x5A)
                    {
                        results.Add(new HeuristicResult(
                            "Embedded PE File",
                            ScanCategory.CodeInjection,
                            ThreatScore.Critical,
                            $"Resource '{resource.Name}' contains a PE Header (MZ). This is a dropper/loader.",
                            "Resource",
                            "MZ Signature detected"
                        ));
                    }
                }
            }

            return results;
        }
    }
}