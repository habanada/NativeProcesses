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
    public class AdvancedIlScanner
    {
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
                    if (module == null) continue;

                    if (!module.IsDynamic && !string.IsNullOrEmpty(module.Name) && module.Name.StartsWith("System")) continue;

                    foreach (var method in type.Methods)
                    {
                        var ilBytes = IlExtractor.GetMethodIL(method);
                        if (ilBytes.Length < 10) continue;

                        AnalyzeOpcodeDistribution(method, ilBytes, results);
                        AnalyzeControlFlow(method, ilBytes, results);
                        AnalyzeBehavioralPatterns(method, ilBytes, results);
                    }
                }
            }
            return results;
        }

        private void AnalyzeOpcodeDistribution(ClrMethod method, byte[] il, List<HeuristicResult> results)
        {
            int xorCount = 0;
            int nopCount = 0;
            int callCount = 0;

            for (int i = 0; i < il.Length; i++)
            {
                byte op = il[i];
                if (op == 0x61 || op == 0x62) xorCount++;
                if (op == 0x00) nopCount++;
                if (op == 0x28 || op == 0x29 || op == 0x6F) callCount++;
            }

            double xorDensity = (double)xorCount / il.Length;
            if (xorDensity > 0.05 && il.Length > 50)
            {
                results.Add(new HeuristicResult(
                    "IL: High XOR Density",
                    ScanCategory.Obfuscation,
                    ThreatScore.High,
                    $"Method body contains heavy XOR operations ({xorDensity * 100:F1}%). Likely a decryption loop.",
                    method.NativeCode.ToString("X"),
                    method.Signature ?? "Unknown"
                ));
            }

            if ((double)nopCount / il.Length > 0.3)
            {
                results.Add(new HeuristicResult(
                    "IL: NOP Sled / Padding",
                    ScanCategory.CodeInjection,
                    ThreatScore.Medium,
                    "Method contains excessive NOP instructions. Potential injection artifact.",
                    method.NativeCode.ToString("X"),
                    $"NOPs: {nopCount}"
                ));
            }
        }

        private void AnalyzeControlFlow(ClrMethod method, byte[] il, List<HeuristicResult> results)
        {
            int branchCount = 0;
            int switchCount = 0;
            int exceptionHandlers = 0;

            for (int i = 0; i < il.Length; i++)
            {
                byte op = il[i];
                if ((op >= 0x2B && op <= 0x2F) || (op >= 0x38 && op <= 0x44)) branchCount++;
                if (op == 0x45) switchCount++;

                // Endfilter (FE 11) / Leave (DD) / Rethrow (FE 1A) -> Indikatoren für Exception Flow
                if (op == 0xDD) exceptionHandlers++;
                if (op == 0xFE && i + 1 < il.Length)
                {
                    byte next = il[i + 1];
                    if (next == 0x11 || next == 0x1A) exceptionHandlers++;
                }
            }

            double branchDensity = (double)branchCount / il.Length;

            if (switchCount > 2 || (branchDensity > 0.25 && il.Length > 100))
            {
                results.Add(new HeuristicResult(
                    "IL: Control Flow Flattening",
                    ScanCategory.Obfuscation,
                    ThreatScore.Medium,
                    $"Method shows signs of obfuscation (High Branching/Switching). Density: {branchDensity * 100:F1}%, Switches: {switchCount}.",
                    method.NativeCode.ToString("X"),
                    method.Signature ?? "Unknown"
                ));
            }

            if (exceptionHandlers > 5)
            {
                results.Add(new HeuristicResult(
                    "IL: Abnormal Exception Handling",
                    ScanCategory.Obfuscation,
                    ThreatScore.High,
                    $"High usage of Exception Handlers ({exceptionHandlers}) for Control Flow. ConfuserEx Anti-Tamper pattern.",
                    method.NativeCode.ToString("X"),
                    "Anti-Tamper"
                ));
            }
        }

        // NEU: Semantic Pattern Matching
        private void AnalyzeBehavioralPatterns(ClrMethod method, byte[] il, List<HeuristicResult> results)
        {
            // Pattern 1: Decryption Loop (Array Load + XOR + Array Store)
            // Ldelem (90-9E) ... Xor (61) ... Stelem (9C-A2)
            // Wir suchen nach dieser Sequenz in nahem Abstand (Cluster)

            bool hasArrayLoad = false;
            bool hasXor = false;
            bool hasArrayStore = false;

            int windowSize = 20; // OpCodes im Fenster

            for (int i = 0; i < il.Length - windowSize; i++)
            {
                hasArrayLoad = false; hasXor = false; hasArrayStore = false;

                for (int j = 0; j < windowSize; j++)
                {
                    byte op = il[i + j];
                    if (op >= 0x90 && op <= 0x9E) hasArrayLoad = true;
                    if (op == 0x61) hasXor = true;
                    if (op >= 0x9C && op <= 0xA2) hasArrayStore = true;
                }

                if (hasArrayLoad && hasXor && hasArrayStore)
                {
                    results.Add(new HeuristicResult(
                        "IL: Decryption Loop Pattern",
                        ScanCategory.CodeInjection,
                        ThreatScore.Critical,
                        "Method contains 'Load Array -> XOR -> Store Array' sequence. Confirmed Runtime Decrypter.",
                        method.NativeCode.ToString("X"),
                        "Decryption Loop"
                    ));
                    break; // Ein Treffer reicht
                }
            }

            // Pattern 2: Method Proxying (P/Invoke Wrapper Hiding)
            // Ldarg ... Call/Calli ... Ret
            // Kurze Methoden, die sofort Callen und Returnen
            if (il.Length < 30)
            {
                bool hasLoadArg = false;
                bool hasCall = false;
                bool hasRet = false;

                foreach (byte op in il)
                {
                    if ((op >= 0x02 && op <= 0x05) || op == 0x0E) hasLoadArg = true; // Ldarg
                    if (op == 0x28 || op == 0x29) hasCall = true; // Call / Calli
                    if (op == 0x2A) hasRet = true; // Ret
                }

                if (hasLoadArg && hasCall && hasRet)
                {
                    // Schwacher Indikator alleine, aber in Kombination mit DynamicMethod verdächtig
                    if (method.Type.Module.IsDynamic)
                    {
                        results.Add(new HeuristicResult(
                            "IL: Dynamic P/Invoke Wrapper",
                            ScanCategory.CodeInjection,
                            ThreatScore.High,
                            "Small dynamic method wrapping a call. Potential P/Invoke Hiding stub.",
                            method.NativeCode.ToString("X"),
                            "Proxy Stub"
                        ));
                    }
                }
            }

            // Pattern 3: Runtime Type Handle usage (GetTypeFromHandle)
            // Ldtoken (D0) ... Call (GetTypeFromHandle)
            // Oft genutzt um Reflection zur Laufzeit vorzubereiten
            int tokenLoadCount = 0;
            foreach (byte op in il) if (op == 0xD0) tokenLoadCount++;

            if (tokenLoadCount > 10)
            {
                results.Add(new HeuristicResult(
                   "IL: Massive Token Loading",
                   ScanCategory.Obfuscation,
                   ThreatScore.Medium,
                   $"Method resolves many Metadata Tokens ({tokenLoadCount}). Virtualization/Obfuscation artifact.",
                   method.NativeCode.ToString("X"),
                   "Ldtoken Spam"
               ));
            }
        }
    }
}