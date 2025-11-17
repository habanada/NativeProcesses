/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using NativeProcesses.Core.Engine;
using NativeProcesses.Core.Models;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using NativeProcesses.Core.Inspection;
using System.Runtime.InteropServices;
using NativeProcesses.Core.Models;
using System.Linq;
using NativeProcesses.Core.Inspection;
using System.IO;
using System.Collections.Generic;

namespace NativeProcesses.Core.Native
{
    [Flags]
    public enum ScanFlags
    {
        None = 0,
        Anomalies = 1,         // Header Stomping, Phantom Sections (PeAnomalyScanner)
        InlineHooks = 2,       // .text Sektions-Vergleich (Inline Hooks)
        IatHooks = 4,          // Import Address Table Hooks
        SuspiciousThreads = 8, // Threads ohne legitimes Modul
        SuspiciousMemory = 16, // RWX Speicher / Shellcode Pattern
        HiddenPeHeaders = 32,  // PE Header im privaten Speicher
        All = Anomalies | InlineHooks | IatHooks | SuspiciousThreads | SuspiciousMemory | HiddenPeHeaders
    }
    public static class ProcessManager
    {
        public enum PriorityClass : uint
        {
            Idle = 0x00000040,
            BelowNormal = 0x00004000,
            Normal = 0x00000020,
            AboveNormal = 0x00008000,
            High = 0x00000080,
            RealTime = 0x00000100
        }


        public static Task<bool> DumpProcessMemoryRegionAsync(int pid, IntPtr baseAddress, long regionSize, string outputFilePath, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                var access = ProcessAccessFlags.VmRead;
                byte[] memoryBuffer;

                try
                {
                    using (var proc = new ManagedProcess(pid, access))
                    {
                        memoryBuffer = proc.ReadMemory(baseAddress, (int)regionSize);
                    }
                }
                catch (Exception ex)
                {
                    logger?.Log(LogLevel.Error, $"DumpProcessMemoryRegion: Failed to read memory from PID {pid} at {baseAddress.ToString("X")}.", ex);
                    return false;
                }

                try
                {
                    File.WriteAllBytes(outputFilePath, memoryBuffer);
                    logger?.Log(LogLevel.Info, $"DumpProcessMemoryRegion: Successfully dumped {memoryBuffer.Length} bytes from PID {pid} to {outputFilePath}.");
                    return true;
                }
                catch (Exception ex)
                {
                    logger?.Log(LogLevel.Error, $"DumpProcessMemoryRegion: Failed to write dump file to {outputFilePath}.", ex);
                    return false;
                }
            });
        }
        public static Task<bool> IsProcessCriticalAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                // Erfordert nur minimale Rechte
                var access = ProcessAccessFlags.QueryLimitedInformation;
                try
                {
                    using (var proc = new ManagedProcess(pid, access))
                    {
                        return proc.IsCriticalProcess();
                    }
                }
                catch (Exception ex)
                {
                    logger?.Log(LogLevel.Debug, $"Failed to check critical status for PID {pid}.", ex);
                    // Bei Fehler (z.B. Access Denied) als "nicht kritisch" annehmen
                    return false;
                }
            });
        }
        public static Task<List<HiddenProcessInfo>> ScanForHiddenProcessesAsync(IEngineLogger logger = null, int maxPid = 65536)
        {
            return Task.Run(() =>
            {
                var results = new List<HiddenProcessInfo>();
                var lister = new NativeProcessLister(logger);
                HashSet<int> officialPids;
                HashSet<int> threadPids;

                try
                {
                    officialPids = new HashSet<int>(lister.GetProcesses().Select(p => p.Pid));
                }
                catch (Exception ex)
                {
                    logger?.Log(LogLevel.Error, "ScanForHiddenProcesses: Failed to get official process list (View A).", ex);
                    return results;
                }

                try
                {
                    threadPids = lister.GetPidsFromThreadView();
                }
                catch (Exception ex)
                {
                    logger?.Log(LogLevel.Error, "ScanForHiddenProcesses: Failed to get thread list (View B).", ex);
                    threadPids = new HashSet<int>();
                }

                var access = ProcessAccessFlags.QueryLimitedInformation | ProcessAccessFlags.VmRead;

                // 3. Vergleiche Ansicht A vs. Ansicht B
                foreach (int pid in threadPids)
                {
                    if (officialPids.Contains(pid))
                    {
                        continue;
                    }

                    // --- HIER IST DER FIX FÜR "NIX AUSSER PID" ---
                    if (pid == 0)
                    {
                        results.Add(new HiddenProcessInfo { Pid = 0, Name = "System Idle Process", ExePath = "[Kernel]", DetectionMethod = "Thread List Discrepancy" });
                        continue;
                    }
                    if (pid == 4)
                    {
                        results.Add(new HiddenProcessInfo { Pid = 4, Name = "System", ExePath = "[Kernel]", DetectionMethod = "Thread List Discrepancy" });
                        continue;
                    }

                    try
                    {
                        using (var proc = new ManagedProcess(pid, access))
                        {
                            string name = "[Unknown]";
                            string path = "[Access Denied]";
                            try
                            {
                                path = proc.GetExePath();
                                name = System.IO.Path.GetFileName(path);
                            }
                            catch { }

                            results.Add(new HiddenProcessInfo
                            {
                                Pid = pid,
                                Name = name,
                                ExePath = path,
                                DetectionMethod = "Thread List Discrepancy"
                            });
                        }
                    }
                    catch (System.ComponentModel.Win32Exception) { }
                }

                // 4. Starte Ansicht C (PID Brute-Force-Scan)
                for (int pid = 4; pid <= maxPid; pid += 4)
                {
                    if (officialPids.Contains(pid) || threadPids.Contains(pid))
                    {
                        continue;
                    }

                    try
                    {
                        using (var proc = new ManagedProcess(pid, access))
                        {
                            string name = "[Unknown]";
                            string path = "[Access Denied]";
                            try
                            {
                                path = proc.GetExePath();
                                name = System.IO.Path.GetFileName(path);
                            }
                            catch { }

                            results.Add(new HiddenProcessInfo
                            {
                                Pid = pid,
                                Name = name,
                                ExePath = path,
                                DetectionMethod = "PID Brute-Force Scan"
                            });
                        }
                    }
                    catch (System.ComponentModel.Win32Exception) { }
                }
                return results;
            });
        }        //public static Task<List<HiddenProcessInfo>> ScanForHiddenProcessesAsync(IEngineLogger logger = null, int maxPid = 65536)
                 //{
                 //    return Task.Run(() =>
                 //    {
                 //        var results = new List<HiddenProcessInfo>();
                 //        var lister = new NativeProcessLister(logger);
                 //        HashSet<int> officialPids;

        //        try
        //        {
        //            officialPids = new HashSet<int>(lister.GetProcesses().Select(p => p.Pid));
        //        }
        //        catch (Exception ex)
        //        {
        //            logger?.Log(LogLevel.Error, "ScanForHiddenProcesses: Failed to get official process list.", ex);
        //            return results;
        //        }

        //        var access = ProcessAccessFlags.QueryLimitedInformation | ProcessAccessFlags.VmRead;

        //        for (int pid = 4; pid <= maxPid; pid += 4)
        //        {
        //            if (officialPids.Contains(pid))
        //            {
        //                continue;
        //            }

        //            try
        //            {
        //                using (var proc = new ManagedProcess(pid, access))
        //                {
        //                    string name = "[Unknown]";
        //                    string path = "[Access Denied]";
        //                    try
        //                    {
        //                        path = proc.GetExePath();
        //                        name = System.IO.Path.GetFileName(path);
        //                    }
        //                    catch (Exception ex)
        //                    {
        //                        logger?.Log(LogLevel.Debug, $"ScanForHiddenProcesses: Found hidden PID {pid} but failed to get details.", ex);
        //                    }

        //                    results.Add(new HiddenProcessInfo
        //                    {
        //                        Pid = pid,
        //                        Name = name,
        //                        ExePath = path,
        //                        DetectionMethod = "PID Brute-Force Scan"
        //                    });
        //                }
        //            }
        //            catch (System.ComponentModel.Win32Exception)
        //            {
        //            }
        //            catch (Exception ex)
        //            {
        //                logger?.Log(LogLevel.Debug, $"ScanForHiddenProcesses: Unexpected error on PID {pid}.", ex);
        //            }
        //        }
        //        return results;
        //    });
        //}
        //public static Task<HookDetectionResult> ScanProcessForHooksAsync(FullProcessInfo processInfo, IEngineLogger logger = null)
        //{
        //    return Task.Run(async () =>
        //    {
        //        int pid = processInfo.Pid;
        //        var result = new HookDetectionResult(pid);
        //        var inspector = new SecurityInspector(logger);
        //        var access = ProcessAccessFlags.QueryInformation | ProcessAccessFlags.VmRead | ProcessAccessFlags.QueryLimitedInformation;
        //        List<ProcessModuleInfo> modules;
        //        List<VirtualMemoryRegion> regions;
        //        try
        //        {
        //            modules = await GetModulesAsync(pid, logger);
        //            regions = await GetVirtualMemoryRegionsAsync(pid, logger);
        //        }
        //        catch (Exception ex)
        //        {
        //            result.Errors.Add($"Failed to list modules or memory regions: {ex.Message}");
        //            return result;
        //        }
        //        var ntdllModule = modules.FirstOrDefault(m => m.BaseDllName.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase));
        //        if (ntdllModule == null)
        //        {
        //            result.Errors.Add("Failed to find ntdll.dll in the process.");
        //            return result;
        //        }
        //        using (var proc = new ManagedProcess(pid, access))
        //        {
        //            foreach (var mod in modules)
        //            {
        //                if (string.IsNullOrEmpty(mod.FullDllName) || mod.FullDllName.StartsWith("["))
        //                {
        //                    continue;
        //                }
        //                try
        //                {
        //                    var inlineHooks = inspector.CheckForInlineHooks(proc, mod.DllBase, mod.FullDllName, modules, regions);
        //                    if (inlineHooks.Count > 0)
        //                    {
        //                        result.InlineHooks.AddRange(inlineHooks);
        //                    }
        //                }
        //                catch (Exception ex)
        //                {
        //                    result.Errors.Add($"Error scanning {mod.BaseDllName} for inline hooks: {ex.Message}");
        //                }
        //                try
        //                {
        //                    var iatHooks = inspector.CheckIatHooks(proc, mod.DllBase, mod.BaseDllName, ntdllModule.DllBase, modules);
        //                    if (iatHooks.Count > 0)
        //                    {
        //                        result.IatHooks.AddRange(iatHooks);
        //                    }
        //                }
        //                catch (Exception ex)
        //                {
        //                    result.Errors.Add($"Error scanning {mod.BaseDllName} for IAT hooks: {ex.Message}");
        //                }
        //            }

        //            // 3. Prüfe auf verdächtige Threads (Shellcode)
        //            try
        //            {
        //                var suspiciousThreads = inspector.CheckForSuspiciousThreads(processInfo.Threads, modules, regions);
        //                if (suspiciousThreads.Count > 0)
        //                {
        //                    result.SuspiciousThreads.AddRange(suspiciousThreads);
        //                }
        //            }
        //            catch (Exception ex)
        //            {
        //                result.Errors.Add($"Error scanning for suspicious threads: {ex.Message}");
        //            }
        //            // 4. NEU: Prüfe auf verdächtige Speicherregionen (RWX/RX)
        //            try
        //            {
        //                var suspiciousRegions = inspector.CheckForSuspiciousMemoryRegions(regions);
        //                if (suspiciousRegions.Count > 0)
        //                {
        //                    result.SuspiciousMemoryRegions.AddRange(suspiciousRegions);
        //                }
        //            }
        //            catch (Exception ex)
        //            {
        //                result.Errors.Add($"Error scanning for suspicious memory regions: {ex.Message}");
        //            }
        //            // 5. NEU: Prüfe auf ruhenden Shellcode (PE-Header im Daten-Speicher)
        //            try
        //            {
        //                var peHeaders = inspector.CheckDataRegionsForPeHeaders(proc, regions);
        //                if (peHeaders.Count > 0)
        //                {
        //                    result.FoundPeHeaders.AddRange(peHeaders);
        //                }
        //            }
        //            catch (Exception ex)
        //            {
        //                result.Errors.Add($"Error scanning data regions for PE headers: {ex.Message}");
        //            }
        //        }
        //        return result;
        //    });
        //}
        public static async Task<HookDetectionResult> ScanProcessForHooksAsync(FullProcessInfo processInfo, ScanFlags flags = ScanFlags.All, IEngineLogger logger = null)
        {
            int pid = processInfo.Pid;
            var result = new HookDetectionResult(pid);

            // Thread-Safe Collections für Ergebnisse
            var iatHooks = new System.Collections.Concurrent.ConcurrentBag<SecurityInspector.IatHookInfo>();
            var inlineHooks = new System.Collections.Concurrent.ConcurrentBag<SecurityInspector.InlineHookInfo>();
            var anomalies = new System.Collections.Concurrent.ConcurrentBag<PeAnomalyInfo>();
            var errors = new System.Collections.Concurrent.ConcurrentBag<string>();

            // Collections für sequentiell gesammelte Daten
            var foundPeHeaders = new List<FoundPeHeaderInfo>();
            var suspiciousThreads = new List<SecurityInspector.SuspiciousThreadInfo>();
            var suspiciousRegions = new List<SecurityInspector.SuspiciousMemoryRegionInfo>();

            var signatureCache = new System.Collections.Concurrent.ConcurrentDictionary<string, ProcessSignatureInfo>();
            var trustedSigners = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Microsoft Windows",
                "Microsoft Corporation"
            };

            var access = ProcessAccessFlags.QueryInformation | ProcessAccessFlags.VmRead | ProcessAccessFlags.QueryLimitedInformation;

            List<ProcessModuleInfo> modules;
            List<VirtualMemoryRegion> regions;

            // 1. Metadaten laden (Timeout 5s)
            try
            {
                var dataTask = Task.Run(async () =>
                {
                    var m = await GetModulesAsync(pid, logger);
                    var r = await GetVirtualMemoryRegionsAsync(pid, logger);
                    return (m, r);
                });

                if (await Task.WhenAny(dataTask, Task.Delay(5000)) != dataTask)
                {
                    result.Errors.Add("Timeout fetching modules/memory regions.");
                    return result;
                }

                (modules, regions) = await dataTask;
            }
            catch (Exception ex)
            {
                result.Errors.Add($"Failed to list modules or memory regions: {ex.Message}");
                return result;
            }

            var ntdllModule = modules.FirstOrDefault(m => m.BaseDllName.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase));
            if (ntdllModule == null && flags.HasFlag(ScanFlags.IatHooks))
            {
                result.Errors.Add("Failed to find ntdll.dll (required for IAT scan).");
            }

            // 2. Scan im Hintergrund
            await Task.Run(() =>
            {
                try
                {
                    using (var proc = new ManagedProcess(pid, access))
                    {
                        // --- FIX: NTDLL Exports EINMAL laden (für den schnellen IAT Scan) ---
                        Dictionary<string, IntPtr> ntdllExports = new Dictionary<string, IntPtr>();
                        if (flags.HasFlag(ScanFlags.IatHooks) && ntdllModule != null)
                        {
                            try
                            {
                                var preInspector = new SecurityInspector(logger);
                                ntdllExports = preInspector.BuildExportMap(proc, ntdllModule.DllBase);
                            }
                            catch (Exception ex)
                            {
                                errors.Add($"Failed to build ntdll export map: {ex.Message}");
                            }
                        }

                        // PARALLEL SCAN (Module-basiert)
                        if (flags.HasFlag(ScanFlags.Anomalies) || flags.HasFlag(ScanFlags.InlineHooks) || flags.HasFlag(ScanFlags.IatHooks))
                        {
                            var parallelOptions = new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount };

                            Parallel.ForEach(modules, parallelOptions, mod =>
                            {
                                if (string.IsNullOrEmpty(mod.FullDllName) || mod.FullDllName.StartsWith("[")) return;

                                try
                                {
                                    var inspector = new SecurityInspector(logger);
                                    var anomalyScanner = new PeAnomalyScanner(logger);

                                    // 1. Anomalies (Header Stomping etc.)
                                    if (flags.HasFlag(ScanFlags.Anomalies))
                                    {
                                        try
                                        {
                                            var modsAnomalies = anomalyScanner.ScanModule(proc, mod);
                                            foreach (var a in modsAnomalies) anomalies.Add(a);
                                        }
                                        catch { }
                                    }

                                    // 2. Inline Hooks
                                    if (flags.HasFlag(ScanFlags.InlineHooks))
                                    {
                                        try
                                        {
                                            var hooks = inspector.CheckForInlineHooks(proc, mod.DllBase, mod.FullDllName, modules, regions);
                                            foreach (var hook in hooks)
                                            {
                                                // Filter: Private/Unknown ist immer böse
                                                if (hook.TargetModule.StartsWith("PRIVATE_MEMORY") || hook.TargetModule == "UNKNOWN_REGION")
                                                {
                                                    inlineHooks.Add(hook);
                                                    continue;
                                                }

                                                // Filter: Signatur prüfen (Cached)
                                                var sig = signatureCache.GetOrAdd(hook.TargetModule, (target) =>
                                                {
                                                    var targetMod = modules.FirstOrDefault(m => m.BaseDllName.Equals(target, StringComparison.OrdinalIgnoreCase));
                                                    if (targetMod != null && !string.IsNullOrEmpty(targetMod.FullDllName))
                                                        return SignatureVerifier.Verify(targetMod.FullDllName);
                                                    return null;
                                                });

                                                if (sig == null || !trustedSigners.Contains(sig.SignerName))
                                                {
                                                    inlineHooks.Add(hook);
                                                }
                                            }
                                        }
                                        catch (Exception ex) { errors.Add($"Inline hook error {mod.BaseDllName}: {ex.Message}"); }
                                    }

                                    // 3. IAT Hooks (HIER WAR DER FEHLER: Wir übergeben jetzt 'ntdllExports')
                                    if (flags.HasFlag(ScanFlags.IatHooks) && ntdllModule != null && ntdllExports.Count > 0)
                                    {
                                        try
                                        {
                                            // FIX: Parameter ist jetzt 'ntdllExports' (Dictionary), nicht mehr 'ntdllModule.DllBase' (IntPtr)
                                            var hooks = inspector.CheckIatHooks(proc, mod.DllBase, mod.BaseDllName, ntdllExports, modules, regions);

                                            foreach (var hook in hooks)
                                            {
                                                if (hook.TargetModule.StartsWith("PRIVATE_MEMORY") || hook.TargetModule == "UNKNOWN_REGION")
                                                {
                                                    iatHooks.Add(hook);
                                                    continue;
                                                }
                                                var sig = signatureCache.GetOrAdd(hook.TargetModule, (target) =>
                                                {
                                                    var targetMod = modules.FirstOrDefault(m => m.BaseDllName.Equals(target, StringComparison.OrdinalIgnoreCase));
                                                    if (targetMod != null && !string.IsNullOrEmpty(targetMod.FullDllName))
                                                        return SignatureVerifier.Verify(targetMod.FullDllName);
                                                    return null;
                                                });
                                                if (sig == null || !trustedSigners.Contains(sig.SignerName))
                                                {
                                                    iatHooks.Add(hook);
                                                }
                                            }
                                        }
                                        catch (Exception ex) { errors.Add($"IAT hook error {mod.BaseDllName}: {ex.Message}"); }
                                    }
                                }
                                catch { }
                            });
                        }

                        // SEQUENTIELLE SCANS (Thread/Memory)
                        var inspectorMain = new SecurityInspector(logger);

                        if (flags.HasFlag(ScanFlags.SuspiciousThreads))
                        {
                            try
                            {
                                suspiciousThreads.AddRange(inspectorMain.CheckForSuspiciousThreads(processInfo.Threads, modules, regions));
                            }
                            catch { }
                        }

                        if (flags.HasFlag(ScanFlags.SuspiciousMemory))
                        {
                            try
                            {
                                suspiciousRegions.AddRange(inspectorMain.CheckForSuspiciousMemoryRegions(regions));
                            }
                            catch { }
                        }

                        if (flags.HasFlag(ScanFlags.HiddenPeHeaders))
                        {
                            try
                            {
                                foundPeHeaders.AddRange(inspectorMain.CheckDataRegionsForPeHeaders(proc, regions));
                            }
                            catch { }
                        }
                    }
                }
                catch (Exception ex)
                {
                    result.Errors.Add($"Fatal error during scan logic: {ex.Message}");
                }
            });

            // Ergebnisse übertragen
            result.IatHooks = iatHooks.ToList();
            result.InlineHooks = inlineHooks.ToList();
            result.Anomalies = anomalies.ToList();
            result.SuspiciousThreads = suspiciousThreads;
            result.SuspiciousMemoryRegions = suspiciousRegions;
            result.FoundPeHeaders = foundPeHeaders;
            result.Errors = errors.ToList();

            return result;
        }
        //public static Task<HookDetectionResult> ScanProcessForHooksAsync_nonparallel(FullProcessInfo processInfo, IEngineLogger logger = null)
        //    {
        //        return Task.Run(async () =>
        //        {
        //            int pid = processInfo.Pid;
        //            var result = new HookDetectionResult(pid);
        //            var inspector = new SecurityInspector(logger);
        //            var access = ProcessAccessFlags.QueryInformation | ProcessAccessFlags.VmRead | ProcessAccessFlags.QueryLimitedInformation;
        //            var anomalyScanner = new PeAnomalyScanner(logger);

        //            List<ProcessModuleInfo> modules;
        //            List<VirtualMemoryRegion> regions;

        //            try
        //            {
        //                modules = await GetModulesAsync(pid, logger);
        //                regions = await GetVirtualMemoryRegionsAsync(pid, logger);
        //            }
        //            catch (Exception ex)
        //            {
        //                result.Errors.Add($"Failed to list modules or memory regions: {ex.Message}");
        //                return result;
        //            }

        //            var ntdllModule = modules.FirstOrDefault(m => m.BaseDllName.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase));
        //            if (ntdllModule == null)
        //            {
        //                result.Errors.Add("Failed to find ntdll.dll in the process.");
        //                return result;
        //            }

        //            // --- START DER MIGNORE-LOGIK (SCHRITT 20.1) ---

        //            // Der Cache, um zu vermeiden, dass "defender.dll" 100x verifiziert wird
        //            var signatureCache = new Dictionary<string, ProcessSignatureInfo>();

        //            // Unsere "Allow-List". Wir vertrauen nur Microsoft.
        //            var trustedSigners = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        //            {
        //                "Microsoft Windows",
        //                "Microsoft Corporation"
        //            };

        //            using (var proc = new ManagedProcess(pid, access))
        //            {
        //                // --- 1. Inline-Hooks Scannen & Filtern ---
        //                foreach (var mod in modules)
        //                {
        //                    if (string.IsNullOrEmpty(mod.FullDllName) || mod.FullDllName.StartsWith("[")) continue;

        //                    try
        //                    {
        //                        var allInlineHooks = inspector.CheckForInlineHooks(proc, mod.DllBase, mod.FullDllName, modules, regions);
        //                        foreach (var hook in allInlineHooks)
        //                        {
        //                            try
        //                            {
        //                                var anomalies = anomalyScanner.ScanModule(proc, mod);
        //                                result.Anomalies.AddRange(anomalies);
        //                            }
        //                            catch (Exception ex)
        //                            {
        //                                logger?.Log(LogLevel.Debug, $"Anomaly scan error for {mod.BaseDllName}", ex);
        //                            }

        //                            // Shellcode  / Unbekannt wird SOFORT gemeldet
        //                            if (hook.TargetModule.StartsWith("PRIVATE_MEMORY") || hook.TargetModule == "UNKNOWN_REGION")
        //                            {
        //                                result.InlineHooks.Add(hook);
        //                                continue;
        //                            }

        //                            // Es ist ein Hook  auf ein Modul (z.B. "defender.dll"). Prüfe die Signatur.
        //                            if (!signatureCache.TryGetValue(hook.TargetModule, out ProcessSignatureInfo sig))
        //                            {
        //                                var targetMod = modules.FirstOrDefault(m => m.BaseDllName.Equals(hook.TargetModule, StringComparison.OrdinalIgnoreCase));
        //                                if (targetMod != null && !string.IsNullOrEmpty(targetMod.FullDllName))
        //                                {
        //                                    sig = SignatureVerifier.Verify(targetMod.FullDllName);
        //                                    signatureCache[hook.TargetModule] = sig;
        //                                }
        //                            }

        //                            // Filter-Anwendung: Melde es NUR, wenn der Signierer NICHT vertrauenswürdig ist.
        //                            if (sig == null || !trustedSigners.Contains(sig.SignerName))
        //                            {
        //                                result.InlineHooks.Add(hook);
        //                            }
        //                        }
        //                    }
        //                    catch (Exception ex)
        //                    {
        //                        result.Errors.Add($"Error scanning {mod.BaseDllName} for inline hooks: {ex.Message}");
        //                    }

        //                    // --- 2. IAT-Hooks Scannen & Filtern ---
        //                    try
        //                    {
        //                        var allIatHooks = inspector.CheckIatHooks(proc, mod.DllBase, mod.BaseDllName, ntdllModule.DllBase, modules, regions);
        //                        foreach (var hook in allIatHooks)
        //                        {
        //                            // IAT-Hooks  können nicht auf privaten Speicher zeigen (das wäre Shellcode ).
        //                            // Wir müssen nur das Ziel-Modul verifizieren.
        //                            if (hook.TargetModule.StartsWith("PRIVATE_MEMORY") || hook.TargetModule == "UNKNOWN_REGION")
        //                            {
        //                                result.IatHooks.Add(hook);
        //                                continue;
        //                            }

        //                            if (!signatureCache.TryGetValue(hook.TargetModule, out ProcessSignatureInfo sig))
        //                            {
        //                                var targetMod = modules.FirstOrDefault(m => m.BaseDllName.Equals(hook.TargetModule, StringComparison.OrdinalIgnoreCase));
        //                                if (targetMod != null && !string.IsNullOrEmpty(targetMod.FullDllName))
        //                                {
        //                                    sig = SignatureVerifier.Verify(targetMod.FullDllName);
        //                                    signatureCache[hook.TargetModule] = sig;
        //                                }
        //                            }

        //                            if (sig == null || !trustedSigners.Contains(sig.SignerName))
        //                            {
        //                                result.IatHooks.Add(hook);
        //                            }
        //                        }
        //                    }
        //                    catch (Exception ex)
        //                    {
        //                        result.Errors.Add($"Error scanning {mod.BaseDllName} for IAT hooks: {ex.Message}");
        //                    }
        //                }

        //                // --- 3. Suspicious Threads (Immer melden) ---
        //                try
        //                {
        //                    var suspiciousThreads = inspector.CheckForSuspiciousThreads(processInfo.Threads, modules, regions);
        //                    if (suspiciousThreads.Count > 0)
        //                    {
        //                        result.SuspiciousThreads.AddRange(suspiciousThreads);
        //                    }
        //                }
        //                catch (Exception ex)
        //                {
        //                    result.Errors.Add($"Error scanning for suspicious threads: {ex.Message}");
        //                }

        //                // --- 4. Suspicious Memory Regions (Immer melden) ---
        //                try
        //                {
        //                    var suspiciousRegions = inspector.CheckForSuspiciousMemoryRegions(regions);
        //                    if (suspiciousRegions.Count > 0)
        //                    {
        //                        result.SuspiciousMemoryRegions.AddRange(suspiciousRegions);
        //                    }
        //                }
        //                catch (Exception ex)
        //                {
        //                    result.Errors.Add($"Error scanning for suspicious memory regions: {ex.Message}");
        //                }

        //                // --- 5. Data Scan / PE Headers (Immer melden) ---
        //                try
        //                {
        //                    var peHeaders = inspector.CheckDataRegionsForPeHeaders(proc, regions);
        //                    if (peHeaders.Count > 0)
        //                    {
        //                        result.FoundPeHeaders.AddRange(peHeaders);
        //                    }
        //                }
        //                catch (Exception ex)
        //                {
        //                    result.Errors.Add($"Error scanning data regions for PE headers: {ex.Message}");
        //                }
        //            }
        //            return result;
        //        });
        //    }
        public static Task<List<PeAnomalyInfo>> ScanProcessForAnomaliesAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(async () =>
            {
                var results = new List<PeAnomalyInfo>();
                var scanner = new PeAnomalyScanner(logger);

                // Wir benötigen vollen Lesezugriff
                var access = ProcessAccessFlags.QueryInformation | ProcessAccessFlags.VmRead;

                try
                {
                    // Module holen
                    var modules = await GetModulesAsync(pid, logger);

                    using (var proc = new ManagedProcess(pid, access))
                    {
                        foreach (var mod in modules)
                        {
                            // System-Module oder leere Pfade überspringen wir ggf. nicht, 
                            // da Malware sich oft als solche tarnt. Aber [Unknown] überspringen wir.
                            if (string.IsNullOrEmpty(mod.FullDllName) || mod.FullDllName.StartsWith("["))
                                continue;

                            var modAnomalies = scanner.ScanModule(proc, mod);
                            results.AddRange(modAnomalies);
                        }
                    }
                }
                catch (Exception ex)
                {
                    logger?.Log(LogLevel.Error, $"ScanProcessForAnomaliesAsync failed for PID {pid}.", ex);
                }

                return results;
            });
        }
        public static bool TrimWorkingSet(int pid)
        {
            try
            {
                var access = ProcessAccessFlags.SetQuota | ProcessAccessFlags.QueryInformation;
                using (var proc = new ManagedProcess(pid, access))
                {
                    proc.TrimWorkingSet();
                    return true;
                }
            }
            catch (Win32Exception)
            {
                return false;
            }
        }

        public static bool SetAffinity(int pid, IntPtr affinityMask)
        {
            try
            {
                var access = ProcessAccessFlags.SetInformation | ProcessAccessFlags.QueryLimitedInformation;
                using (var proc = new ManagedProcess(pid, access))
                {
                    proc.SetAffinity(affinityMask);
                    return true;
                }
            }
            catch (Win32Exception)
            {
                return false;
            }
        }

        public static bool SetPriorityBoostDisabled(int pid, bool isDisabled)
        {
            try
            {
                var access = ProcessAccessFlags.SetInformation | ProcessAccessFlags.QueryLimitedInformation;
                using (var proc = new ManagedProcess(pid, access))
                {
                    proc.SetPriorityBoostDisabled(isDisabled);
                    return true;
                }
            }
            catch (Win32Exception)
            {
                return false;
            }
        }

        public static bool SetIoPriority(int pid, IoPriorityHint priority)
        {
            try
            {
                var access = ProcessAccessFlags.SetInformation;
                using (var proc = new ManagedProcess(pid, access))
                {
                    proc.SetIoPriority(priority);
                    return true;
                }
            }
            catch (Win32Exception)
            {
                return false;
            }
        }

        public static bool SetEcoMode(int pid, bool isEnabled)
        {
            try
            {
                var access = ProcessAccessFlags.SetInformation;
                using (var proc = new ManagedProcess(pid, access))
                {
                    proc.SetEcoMode(isEnabled);
                    return true;
                }
            }
            catch (Win32Exception)
            {
                return false;
            }
        }

        public static Task<List<Models.NetworkConnectionInfo>> GetNetworkConnectionsAsync(IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                return NetworkManager.GetNetworkConnections();
            });
        }
        public static Task<List<Models.WindowInfo>> GetWindowsAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                return WindowManager.GetWindowsForProcess(pid);
            });
        }
        public static Task<List<Models.DotNetAppDomainInfo>> GetDotNetAppDomainsAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                return DotNetInspector.GetAppDomainInfo(pid);
            });
        }
        public static Task<List<Models.DotNetStringDuplicateInfo>> GetDotNetAllHeapStringsAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                return DotNetInspector.GetAllHeapStrings(pid);
            });
        }
        public static Task<List<Models.DotNetStringDuplicateInfo>> GetDotNetStringDuplicatesAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                return DotNetInspector.GetStringDuplicateStats(pid);
            });
        }
        public static Task<List<Models.DotNetGcRootPathInfo>> GetDotNetGcRootPathAsync(int pid, ulong targetObject, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                return DotNetInspector.GetGcRootPath(pid, targetObject);
            });
        }
        public static Task<Models.DotNetThreadPoolInfo> GetDotNetThreadPoolAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                return DotNetInspector.GetThreadPoolInfo(pid);
            });
        }
        public static Task<List<Models.DotNetFinalizerInfo>> GetDotNetFinalizerQueueAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                return DotNetInspector.GetFinalizerInfo(pid);
            });
        }
        public static Task<List<Models.DotNetLockInfo>> GetDotNetLockingInfoAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                return DotNetInspector.GetLockingInfo(pid);
            });
        }
        public static Task<List<Models.DotNetStackFrame>> GetDotNetThreadStackAsync(int pid, int osThreadId, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                return DotNetInspector.GetManagedStack(pid, osThreadId);
            });
        }
        public static Task<List<Models.DotNetRootInfo>> GetDotNetGcRootsAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                return DotNetInspector.GetGcRoots(pid);
            });
        }
        public static Task<List<Models.DotNetExceptionInfo>> GetDotNetHeapExceptionsAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                return DotNetInspector.GetHeapExceptions(pid);
            });
        }
        public static Task<List<Models.DotNetHeapStat>> GetDotNetHeapStatsAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                return DotNetInspector.GetHeapStats(pid);
            });
        }
        public static Task<Models.ExtendedThreadInfo> GetExtendedThreadInfoAsync(int threadId, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                var access = ManagedThread.ThreadAccessFlags.QueryInformation;
                using (var thread = new ManagedThread(threadId, access))
                {
                    thread.GetExtendedPriorities(out var ioPriority, out var memPriority);
                    return new Models.ExtendedThreadInfo
                    {
                        ThreadId = threadId,
                        IoPriority = ioPriority,
                        MemoryPriority = memPriority
                    };
                }
            });
        }
        public static Task<List<ProcessModuleInfo>> GetModulesAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                var access = ProcessAccessFlags.QueryInformation |
                             ProcessAccessFlags.VmRead |
                             ProcessAccessFlags.QueryLimitedInformation;

                using (var proc = new ManagedProcess(pid, access))
                {
                    return proc.GetLoadedModules(logger);
                }
            });
        }
        public static Task<List<NativeHandleInfo>> GetHandlesAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                var access = ProcessAccessFlags.DuplicateHandle;

                access |= ProcessAccessFlags.QueryInformation | ProcessAccessFlags.QueryLimitedInformation;

                using (var proc = new ManagedProcess(pid, access))
                {
                    return proc.GetOpenHandles(logger);
                }
            });
        }
        public static Task<List<NativeHandleInfo>> GetOpenFilesAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(async () =>
            {
                try
                {
                    // 1. Wir rufen die vorhandene Methode auf, um alle Handles zu holen
                    var allHandles = await GetHandlesAsync(pid, logger);

                    // 2. Wir filtern die Liste, bevor wir sie zurückgeben
                    var fileHandles = allHandles
                        .Where(h => h.TypeName.Equals("File", StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    return fileHandles;
                }
                catch (Exception ex)
                {
                    logger?.Log(LogLevel.Error, $"GetOpenFilesAsync failed for PID {pid}.", ex);
                    return new List<NativeHandleInfo>();
                }
            });
        }
        public static Task<List<NativeHandleInfo>> GetHandlesByTypeAsync(int pid, string typeNameFilter, IEngineLogger logger = null)
        {
            return Task.Run(async () =>
            {
                if (string.IsNullOrEmpty(typeNameFilter))
                {
                    return await GetHandlesAsync(pid, logger);
                }

                try
                {
                    var allHandles = await GetHandlesAsync(pid, logger);

                    var filteredHandles = allHandles
                        .Where(h => h.TypeName.Equals(typeNameFilter, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    return filteredHandles;
                }
                catch (Exception ex)
                {
                    logger?.Log(LogLevel.Error, $"GetHandlesByTypeAsync failed for PID {pid} (Filter: {typeNameFilter}).", ex);
                    return new List<NativeHandleInfo>();
                }
            });
        }
        public static Task<List<Models.VirtualMemoryRegion>> GetVirtualMemoryRegionsAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                var access = ProcessAccessFlags.QueryInformation;

                using (var proc = new ManagedProcess(pid, access))
                {
                    return proc.GetVirtualMemoryRegions();
                }
            });
        }
        public static bool Kill(int pid)
        {
            try
            {
                using (var proc = new ManagedProcess(pid, ProcessAccessFlags.Terminate))
                {
                    proc.Kill();
                    return true;
                }
            }
            catch (Win32Exception)
            {
                return false;
            }
        }
        public static bool HardKill(int pid)
        {
            try
            {
                var access = ProcessAccessFlags.SetQuota | ProcessAccessFlags.Terminate;
                using (var proc = new ManagedProcess(pid, access))
                {
                    proc.HardKillUsingJob();
                    return true;
                }
            }
            catch (Win32Exception)
            {
                return false;
            }
        }
        public static bool InjectionKill(int pid)
        {
            try
            {
                var access = ProcessAccessFlags.CreateThread |
                             ProcessAccessFlags.VmOperation |
                             ProcessAccessFlags.VmWrite |
                             ProcessAccessFlags.QueryInformation;

                using (var proc = new ManagedProcess(pid, access))
                {
                    proc.KillByThreadInjection();
                    return true;
                }
            }
            catch (Win32Exception)
            {
                return false;
            }
        }
        public static bool SetPriority(int pid, PriorityClass priority)
        {
            try
            {
                using (var proc = new ManagedProcess(pid, ProcessAccessFlags.SetInformation))
                {
                    proc.SetPriority(priority);
                    return true;
                }
            }
            catch (Win32Exception)
            {
                return false;
            }
        }
        public static bool Suspend(int pid)
        {
            try
            {
                using (var proc = new ManagedProcess(pid, ProcessAccessFlags.SuspendResume))
                {
                    proc.Suspend();
                    return true;
                }
            }
            catch (Win32Exception)
            {
                return false;
            }
        }
        public static bool Resume(int pid)
        {
            try
            {
                using (var proc = new ManagedProcess(pid, ProcessAccessFlags.SuspendResume))
                {
                    proc.Resume();
                    return true;
                }
            }
            catch (Win32Exception)
            {
                return false;
            }
        }
    }
}
