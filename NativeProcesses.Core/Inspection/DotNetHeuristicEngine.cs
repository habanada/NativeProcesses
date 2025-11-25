/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Microsoft.Diagnostics.Runtime;
using NativeProcesses.Core.Engine;
using NativeProcesses.Core.Inspection.Heuristics;
using NativeProcesses.Core.Models;
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

        // NEU: Parameter List<VirtualMemoryRegion>
        public List<PeAnomalyInfo> RunScan(ClrRuntime runtime, List<VirtualMemoryRegion> memoryRegions = null)
        {
            var anomalies = new List<PeAnomalyInfo>();
            var allHeuristics = new List<HeuristicResult>();

            try
            {
                var asmScanner = new AssemblyScanner();
                allHeuristics.AddRange(asmScanner.Scan(runtime));

                if (runtime.Heap.CanWalkHeap)
                {
                    var byteScanner = new ByteArrayScanner();
                    // NEU: Wir geben die Regionen weiter
                    allHeuristics.AddRange(byteScanner.Scan(runtime.Heap, memoryRegions));

                    var stringScanner = new StringScanner();
                    allHeuristics.AddRange(stringScanner.Scan(runtime.Heap));

                    var cryptoScanner = new CryptoScanner();
                    allHeuristics.AddRange(cryptoScanner.Scan(runtime.Heap));

                    var ratScanner = new RatPatternScanner();
                    allHeuristics.AddRange(ratScanner.Scan(runtime.Heap));

                    var hotSpotScanner = new HotSpotScanner();
                    allHeuristics.AddRange(hotSpotScanner.Scan(runtime));


                    // 8. Runtime IL Analysis (OpCodes Signaturen)
                    var ilScanner = new RuntimeIlScanner();
                    allHeuristics.AddRange(ilScanner.Scan(runtime));

                    // 9. Managed Injector Analysis (Pattern Matching on Types)
                    var injectorScanner = new ManagedInjectorScanner();
                    allHeuristics.AddRange(injectorScanner.Scan(runtime));

                    // 10. Advanced IL Metrics (Behavior/Graph Proxies) ---
                    var advIlScanner = new AdvancedIlScanner();
                    allHeuristics.AddRange(advIlScanner.Scan(runtime));

                    // --- NEU: 11. JIT Hook Scanner (MethodTable Spoofing & Hooks) ---
                    var jitScanner = new JitHookScanner();
                    allHeuristics.AddRange(jitScanner.Scan(runtime, memoryRegions));

                    // 12. Assembly Mismatch / RunPE Detection
                    var mismatchScanner = new AssemblyMismatchScanner();
                    allHeuristics.AddRange(mismatchScanner.Scan(runtime));

                    var featureExtractor = MlFeatureExtractor.Extract(runtime, allHeuristics);
                    
                    var classifier = new MalwareClassifier();
                    float probability = classifier.PredictMalwareProbability(featureExtractor);

                    if (probability > 0.75f)
                    {
                        string severity = probability > 0.9f ? "Critical" : "High";
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
                }

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
                        Address = addr,
                        Size = 0
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