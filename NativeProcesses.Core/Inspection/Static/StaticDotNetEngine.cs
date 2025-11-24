/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Mono.Cecil;
using NativeProcesses.Core.Engine;
using NativeProcesses.Core.Inspection.Heuristics;
using System;
using System.Collections.Generic;
using System.IO;

namespace NativeProcesses.Core.Inspection.Static
{
    public class StaticDotNetEngine
    {
        private readonly IEngineLogger _logger;

        public StaticDotNetEngine(IEngineLogger logger)
        {
            _logger = logger;
        }

        public List<PeAnomalyInfo> ScanFile(string filePath)
        {
            var anomalies = new List<PeAnomalyInfo>();
            var allHeuristics = new List<HeuristicResult>();

            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return anomalies;

            try
            {
                using (var assembly = AssemblyDefinition.ReadAssembly(filePath))
                {
                    foreach (var module in assembly.Modules)
                    {
                        var pinvokeScanner = new StaticPInvokeScanner();
                        allHeuristics.AddRange(pinvokeScanner.Scan(module));

                        var ilScanner = new StaticIlScanner();
                        allHeuristics.AddRange(ilScanner.Scan(module));

                        var resScanner = new StaticResourceScanner();
                        allHeuristics.AddRange(resScanner.Scan(module));
                    }
                }

                foreach (var h in allHeuristics)
                {
                    string severity = "Low";
                    if (h.Score >= ThreatScore.Critical) severity = "Critical";
                    else if (h.Score >= ThreatScore.High) severity = "High";
                    else if (h.Score >= ThreatScore.Medium) severity = "Medium";

                    anomalies.Add(new PeAnomalyInfo
                    {
                        ModuleName = Path.GetFileName(filePath),
                        AnomalyType = $"Static: {h.RuleName} ({h.Category})",
                        Details = h.Description,
                        Severity = severity,
                        Address = 0,
                        Size = 0
                    });
                }
            }
            catch (BadImageFormatException)
            {
                // Keine .NET Assembly (Native PE)
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, $"Static scan failed for {filePath}", ex);
            }

            return anomalies;
        }
    }
}