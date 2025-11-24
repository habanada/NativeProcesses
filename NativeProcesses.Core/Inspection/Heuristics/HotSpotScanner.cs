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
    public class HotSpotScanner
    {
        public IEnumerable<HeuristicResult> Scan(ClrRuntime runtime)
        {
            var results = new List<HeuristicResult>();
            var heap = runtime.Heap;

            int pinnedObjectCount = 0;
            int finalizerCount = 0;
            int taskCount = 0;
            int delegateCount = 0;

            var pinnedAddresses = new HashSet<ulong>();

            foreach (var root in heap.EnumerateRoots())
            {
                if (root.IsPinned)
                {
                    if (root.Object.IsValid)
                    {
                        pinnedAddresses.Add(root.Object.Address);
                    }
                }
            }
            pinnedObjectCount = pinnedAddresses.Count;

            foreach (var obj in heap.EnumerateObjects())
            {
                if (obj.Type == null) continue;

                if (obj.Type.Name == "System.Threading.Tasks.Task" || obj.Type.Name == "System.Threading.Thread")
                {
                    taskCount++;
                }

                if (obj.Type.Name == "System.Delegate" || obj.Type.Name == "System.MulticastDelegate")
                {
                    delegateCount++;
                }
            }

            foreach (var fin in heap.EnumerateFinalizableObjects())
            {
                finalizerCount++;
            }

            if (pinnedObjectCount > 50)
            {
                results.Add(new HeuristicResult(
                    "Pinned Object Storm",
                    ScanCategory.General,
                    ThreatScore.Medium,
                    $"Unusually high number of pinned objects detected ({pinnedObjectCount}). Common in interoperability-heavy malware or shellcode runners.",
                    "Heap Global",
                    $"Count: {pinnedObjectCount}"
                ));
            }

            if (finalizerCount > 2000)
            {
                results.Add(new HeuristicResult(
                    "Finalizer Queue Flood",
                    ScanCategory.General,
                    ThreatScore.Low,
                    $"Finalizer queue is flooded ({finalizerCount} objects). Possible memory leak or obfuscator artifact.",
                    "Finalizer Queue",
                    $"Count: {finalizerCount}"
                ));
            }

            if (taskCount > 500)
            {
                results.Add(new HeuristicResult(
                    "Thread/Task Anomalies",
                    ScanCategory.General,
                    ThreatScore.Low,
                    $"High number of Tasks/Threads objects ({taskCount}). Potential DDoS bot or miner.",
                    "Heap Global",
                    $"Count: {taskCount}"
                ));
            }

            return results;
        }
    }
}