/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Microsoft.Diagnostics.Runtime;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace NativeProcesses.Core.Inspection.Heuristics
{
    public static class MlFeatureExtractor
    {
        public static int UnsafeIlCount; // calli, localloc



        public static MlFeatureVector Extract(ClrRuntime runtime, IEnumerable<HeuristicResult> context = null)
        {
            var features = new MlFeatureVector();
            var heap = runtime.Heap;

            if (heap.CanWalkHeap)
            {
                // 1. Pinned Objects korrekt über Roots zählen
                var pinnedAddresses = new HashSet<ulong>();
                foreach (var root in heap.EnumerateRoots())
                {
                    if (root.IsPinned)
                    {
                        // Wir prüfen IsValid, um sicherzugehen, dass die Adresse noch stimmt
                        if (root.Object.IsValid)
                        {
                            pinnedAddresses.Add(root.Object.Address);
                        }
                    }
                }
                features.PinnedObjectCount = pinnedAddresses.Count;

                // 2. Normale Objekte scannen (für Typen)
                foreach (var obj in heap.EnumerateObjects())
                {
                    if (obj.Type == null) continue;

                    // HIER WAR DER FEHLER: obj.IsPinned gibt es nicht. 
                    // Wir haben das oben über EnumerateRoots() gelöst.

                    string name = obj.Type.Name;
                    if (string.IsNullOrEmpty(name)) continue;

                    if (name.Contains("System.Reflection.Emit.DynamicMethod")) features.DynamicMethodCount++;
                    if (name.StartsWith("System.Security.Cryptography")) features.CryptoObjectCount++;
                }
            }

            // 3. Floating Assemblies (Unverändert)
            foreach (var mod in runtime.EnumerateModules())
            {
                if (mod.Layout == ModuleLayout.Flat && !mod.IsDynamic)
                {
                    features.FloatingAssemblyCount++;
                }
            }

            // 4. Kontext-Daten integrieren (Entropie aus ByteArrayScanner übernehmen)
            if (context != null)
            {
                foreach (var result in context)
                {
                    if (result.Category == ScanCategory.General && result.RuleName.Contains("String"))
                    {
                        features.SuspiciousStringCount++;
                    }

                    if (result.RuleName == "High Entropy Blob" && !string.IsNullOrEmpty(result.Artifact))
                    {
                        string entropyStr = result.Artifact.Replace("Entropy:", "").Trim();
                        if (float.TryParse(entropyStr, NumberStyles.Any, CultureInfo.InvariantCulture, out float entropyVal))
                        {
                            if (entropyVal > features.MaxEntropy)
                            {
                                features.MaxEntropy = entropyVal;
                            }
                        }
                    }
                    if (result.Category == ScanCategory.CodeInjection &&
                        (result.RuleName.Contains("Unsafe IL") || result.RuleName.Contains("Indirect Call")))
                    {
                        features.UnsafeIlCount++;
                    }
                }
            }

            features.AvgEntropy = features.MaxEntropy > 0 ? (features.MaxEntropy - 1.0f) : 3.5f;

            return features;
        }
    }
}