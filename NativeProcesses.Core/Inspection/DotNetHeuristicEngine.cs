/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Microsoft.Diagnostics.Runtime;
using NativeProcesses.Core.Engine;
using NativeProcesses.Core.Inspection.Heuristics;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NativeProcesses.Core.Inspection
{
    public class DotNetHeuristicEngine
    {
        private readonly IEngineLogger _logger;

        public DotNetHeuristicEngine(IEngineLogger logger)
        {
            _logger = logger;
        }

        public List<PeAnomalyInfo> RunScan(ClrRuntime runtime)
        {
            var anomalies = new List<PeAnomalyInfo>();
            var allHeuristics = new List<HeuristicResult>();

            try
            {
                // 1. Assembly Scan (Modules)
                var asmScanner = new AssemblyScanner();
                allHeuristics.AddRange(asmScanner.Scan(runtime));

                if (runtime.Heap.CanWalkHeap)
                {
                    // 2. Byte Array Scan (Shellcode/PEs)
                    var byteScanner = new ByteArrayScanner();
                    allHeuristics.AddRange(byteScanner.Scan(runtime.Heap));

                    // 3. String Scan (IOCs)
                    var stringScanner = new StringScanner();
                    allHeuristics.AddRange(stringScanner.Scan(runtime.Heap));

                    // 4. Crypto Scan (Keys/Algorithms)
                    var cryptoScanner = new CryptoScanner();
                    allHeuristics.AddRange(cryptoScanner.Scan(runtime.Heap));

                    // 5. RAT Pattern Scan (Known Malware Classes)
                    var ratScanner = new RatPatternScanner();
                    allHeuristics.AddRange(ratScanner.Scan(runtime.Heap));

                    // 6. Hot Spot Scanner
                    var hotSpotScanner = new HotSpotScanner();
                    allHeuristics.AddRange(hotSpotScanner.Scan(runtime));
                    // 7. Dynamic Method Analysis (JIT)
                    var dynamicScanner = new DynamicMethodScanner();
                    allHeuristics.AddRange(dynamicScanner.Scan(runtime));

                    // 8. Runtime IL Analysis (OpCodes)
                    var ilScanner = new RuntimeIlScanner();
                    allHeuristics.AddRange(ilScanner.Scan(runtime));

                    // --- LEVEL 5: ML Classification (KORRIGIERT) ---

                    // Wir übergeben jetzt 'allHeuristics' als Kontext!
                    // Der Extractor holt sich die echte Entropie aus den ByteArrayScanner-Ergebnissen.
                    var featureExtractor = MlFeatureExtractor.Extract(runtime, allHeuristics);

                    var classifier = new MalwareClassifier();
                    float probability = classifier.PredictMalwareProbability(featureExtractor);

                    if (probability > 0.75f)
                    {
                        string severity = probability > 0.9f ? "Critical" : "High";

                        // Details generieren basierend auf den Features, die angeschlagen haben
                        string reason = "";
                        if (featureExtractor.MaxEntropy > 7.0) reason += "Crypto/Packed content, ";
                        if (featureExtractor.FloatingAssemblyCount > 0) reason += "Hidden Assemblies, ";
                        if (featureExtractor.DynamicMethodCount > 0) reason += "Dynamic Code, ";

                        anomalies.Add(new PeAnomalyInfo
                        {
                            ModuleName = "ML Engine",
                            AnomalyType = "AI/ML Detection",
                            Details = $"Heuristic Model predicts Malware ({reason.TrimEnd(',', ' ')}). Confidence: {(probability * 100):F1}%",
                            Severity = severity,
                            Address = 0,
                            Size = 0
                        });
                    }


                    // ... (vor FeatureExtractor) ...

                }

                // Konvertierung in das generische PeAnomalyInfo Format für die UI
                foreach (var h in allHeuristics)
                {
                    string severity = "Low";
                    if (h.Score >= ThreatScore.Critical) severity = "Critical";
                    else if (h.Score >= ThreatScore.High) severity = "High";
                    else if (h.Score >= ThreatScore.Medium) severity = "Medium";
                    long addr = 0;
                    try { addr = Convert.ToInt64(h.AddressInfo, 16); } catch { }

                    anomalies.Add(new PeAnomalyInfo
                    {
                        ModuleName = ".NET Heuristics",
                        AnomalyType = $"{h.RuleName} ({h.Category})",
                        Details = $"{h.Description} [Artifact: {h.Artifact}]",
                        Severity = severity,
                        Address = addr, // <--- NEU
                        Size = 0 // Größe kennen wir hier oft nicht exakt ohne erneuten Lookup, ist aber für Dump optional (wir lesen Header oder raten)
                    });
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, "DotNetHeuristicEngine scan failed.", ex);
            }

            return anomalies;
        }
    }
}