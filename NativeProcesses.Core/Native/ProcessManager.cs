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
using System.Linq;
using System.IO;
using System.Collections.Concurrent;

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
        DotNetMalware = 64,    // AgentTesla/NanoCore Scan
        All = Anomalies | InlineHooks | IatHooks | SuspiciousThreads | SuspiciousMemory | HiddenPeHeaders | DotNetMalware
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

        // --- Memory Dumping ---

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

        // --- Critical Process Check ---

        public static Task<bool> IsProcessCriticalAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
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
                    return false;
                }
            });
        }

        // --- Hidden Process Scan ---

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

                foreach (int pid in threadPids)
                {
                    if (officialPids.Contains(pid)) continue;
                    if (pid == 0 || pid == 4) continue;

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
                    catch (Win32Exception) { }
                }

                for (int pid = 4; pid <= maxPid; pid += 4)
                {
                    if (officialPids.Contains(pid) || threadPids.Contains(pid)) continue;

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
                    catch (Win32Exception) { }
                }
                return results;
            });
        }

        // --- Main Hook & Anomaly Scan ---

        public static async Task<HookDetectionResult> ScanProcessForHooksAsync(FullProcessInfo processInfo, ScanFlags flags = ScanFlags.All, IEngineLogger logger = null)
        {
            int pid = processInfo.Pid;
            var result = new HookDetectionResult(pid);

            // Thread-Safe Collections für parallele Ergebnisse
            var iatHooks = new ConcurrentBag<SecurityInspector.IatHookInfo>();
            var inlineHooks = new ConcurrentBag<SecurityInspector.InlineHookInfo>();
            var anomalies = new ConcurrentBag<PeAnomalyInfo>();
            var errors = new ConcurrentBag<string>();

            var foundPeHeaders = new List<FoundPeHeaderInfo>();
            var suspiciousThreads = new List<SecurityInspector.SuspiciousThreadInfo>();
            var suspiciousRegions = new List<SecurityInspector.SuspiciousMemoryRegionInfo>();

            // Rechte für Snapshot & Scan
            var access = ProcessAccessFlags.QueryInformation |
                         ProcessAccessFlags.VmRead |
                         ProcessAccessFlags.DuplicateHandle |
                         ProcessAccessFlags.CreateProcess;

            try
            {
                // A. Datenvorbereitung (Async I/O)
                List<ProcessModuleInfo> modules;
                List<VirtualMemoryRegion> regions;

                var dataTask = Task.Run(async () =>
                {
                    var m = await GetModulesAsync(pid, logger);
                    var r = await GetVirtualMemoryRegionsAsync(pid, logger);
                    return (m, r);
                });

                if (await Task.WhenAny(dataTask, Task.Delay(15000)) != dataTask)
                {
                    result.Errors.Add("Timeout fetching modules/memory regions. Process might be hung or protected.");
                    return result;
                }

                (modules, regions) = await dataTask;

                var ntdllModule = modules.FirstOrDefault(m => m.BaseDllName.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase));
                if (ntdllModule == null && flags.HasFlag(ScanFlags.IatHooks))
                {
                    result.Errors.Add("Critical: ntdll.dll not found in target process. Hook scan might be incomplete.");
                }

                // B. Haupt-Scan (CPU-Intensive Tasks im ThreadPool)
                await Task.Run(() =>
                {
                    ProcessSnapshot snapshot = null;
                    ManagedProcess procToScan = null;
                    bool isSnapshot = false;

                    try
                    {
                        // 1. Versuch: PSS Snapshot (Stealth & Konsistenz)
                        try
                        {
                            using (var liveProc = new ManagedProcess(pid, access))
                            {
                                snapshot = new ProcessSnapshot(liveProc, logger);
                                if (snapshot.CloneProcessHandle != IntPtr.Zero)
                                {
                                    procToScan = new ManagedProcess(snapshot.CloneProcessHandle, false);
                                    isSnapshot = true;
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            logger?.Log(LogLevel.Debug, $"PSS Snapshot failed for PID {pid} (Fallback to live scan): {ex.Message}");
                        }

                        // 2. Fallback: Live Scan
                        if (procToScan == null)
                        {
                            procToScan = new ManagedProcess(pid, ProcessAccessFlags.QueryInformation | ProcessAccessFlags.VmRead);
                        }

                        using (procToScan)
                        {
                            // 3. Vorbereitung für IAT Scan (Export-Tabelle von NTDLL parsen)
                            Dictionary<string, IntPtr> ntdllExports = new Dictionary<string, IntPtr>();
                            if (flags.HasFlag(ScanFlags.IatHooks) && ntdllModule != null)
                            {
                                try
                                {
                                    var preInspector = new SecurityInspector(logger);
                                    ntdllExports = preInspector.BuildExportMap(procToScan, ntdllModule.DllBase);
                                }
                                catch (Exception ex) { errors.Add($"Failed to build ntdll export map: {ex.Message}"); }
                            }

                            // 4. VAD Scan (Phantom Module / Unbacked Code)
                            if (flags.HasFlag(ScanFlags.Anomalies) || flags.HasFlag(ScanFlags.SuspiciousMemory))
                            {
                                try
                                {
                                    var vadScanner = new VadScanner(logger);
                                    var phantoms = vadScanner.ScanForPhantoms(procToScan, modules, regions);

                                    foreach (var phantom in phantoms)
                                    {
                                        anomalies.Add(new PeAnomalyInfo
                                        {
                                            ModuleName = string.IsNullOrEmpty(phantom.NtPath) ? $"Unbacked_0x{phantom.BaseAddress.ToString("X")}" : phantom.NtPath,
                                            AnomalyType = phantom.DetectionMethod,
                                            Details = phantom.Details ?? $"Found executable region at 0x{phantom.BaseAddress.ToString("X")} not in PEB.",
                                            Severity = "Critical"
                                        });
                                    }
                                }
                                catch (Exception ex)
                                {
                                    logger?.Log(LogLevel.Error, "VAD Scan failed.", ex);
                                }
                            }

                            // 5. Paralleler Modul-Scan (IAT & Inline Hooks)
                            if (flags.HasFlag(ScanFlags.Anomalies) || flags.HasFlag(ScanFlags.InlineHooks) || flags.HasFlag(ScanFlags.IatHooks))
                            {
                                var parallelOptions = new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount };

                                Parallel.ForEach(modules, parallelOptions, mod =>
                                {
                                    if (string.IsNullOrEmpty(mod.FullDllName) || mod.FullDllName.StartsWith("[")) return;

                                    var inspector = new SecurityInspector(logger);
                                    var anomalyScanner = new PeAnomalyScanner(logger);

                                    // 5a. Anomalien (Header Stomping, Overloading)
                                    if (flags.HasFlag(ScanFlags.Anomalies))
                                    {
                                        try
                                        {
                                            var overloadResults = inspector.CheckForModuleOverloading(procToScan, new List<ProcessModuleInfo> { mod });
                                            foreach (var overload in overloadResults)
                                            {
                                                anomalies.Add(new PeAnomalyInfo
                                                {
                                                    ModuleName = mod.BaseDllName,
                                                    AnomalyType = "Module Overloading / Doppelgänging",
                                                    Details = overload,
                                                    Severity = "Critical"
                                                });
                                            }

                                            var modsAnomalies = anomalyScanner.ScanModule(procToScan, mod);
                                            foreach (var a in modsAnomalies) anomalies.Add(a);

                                            var permissionAnomalies = inspector.CheckSectionPermissionMismatch(procToScan, mod, regions);
                                            foreach (var a in permissionAnomalies) anomalies.Add(a);
                                        }
                                        catch { }
                                    }

                                    // 5b. Inline Hooks
                                    if (flags.HasFlag(ScanFlags.InlineHooks))
                                    {
                                        try
                                        {
                                            var hooks = inspector.CheckForInlineHooks(procToScan, mod.DllBase, mod.FullDllName, modules, regions);
                                            foreach (var hook in hooks)
                                            {
                                                // Whitelist-Check: Wenn SecurityInspector sagt "IsSafe", ignorieren wir es
                                                if (hook.IsSafe) continue;

                                                // Target auflösen für bessere Logs
                                                hook.TargetModule = inspector.ResolveTargetAddress(hook.TargetAddress, procToScan, modules, regions);
                                                inlineHooks.Add(hook);
                                            }
                                        }
                                        catch (Exception ex) { errors.Add($"Inline hook error {mod.BaseDllName}: {ex.Message}"); }
                                    }

                                    // 5c. IAT Hooks
                                    if (flags.HasFlag(ScanFlags.IatHooks) && ntdllModule != null && ntdllExports.Count > 0)
                                    {
                                        try
                                        {
                                            var hooks = inspector.CheckIatHooks(procToScan, mod.DllBase, mod.BaseDllName, ntdllExports, modules, regions);
                                            foreach (var hook in hooks)
                                            {
                                                // Whitelist-Check
                                                if (hook.IsSafe) continue;

                                                hook.TargetModule = inspector.ResolveTargetAddress(hook.ActualAddress, procToScan, modules, regions);
                                                iatHooks.Add(hook);
                                            }
                                        }
                                        catch (Exception ex) { errors.Add($"IAT hook error {mod.BaseDllName}: {ex.Message}"); }
                                    }
                                });
                            }

                            // 6. Sequentielle Scans (Threads, Memory, .NET)
                            var inspectorMain = new SecurityInspector(logger);

                            if (flags.HasFlag(ScanFlags.Anomalies))
                            {
                                try
                                {
                                    var parentInspector = new ParentProcessInspector(logger);
                                    var spoofingResult = parentInspector.CheckForParentSpoofing(pid, procToScan);
                                    if (spoofingResult != null) anomalies.Add(spoofingResult);
                                }
                                catch { }
                            }

                            if (flags.HasFlag(ScanFlags.SuspiciousThreads))
                            {
                                try { suspiciousThreads.AddRange(inspectorMain.CheckForSuspiciousThreads(processInfo.Threads, modules, regions)); } catch { }
                            }

                            if (flags.HasFlag(ScanFlags.SuspiciousMemory))
                            {
                                try { suspiciousRegions.AddRange(inspectorMain.CheckForSuspiciousMemoryRegions(regions)); } catch { }
                            }

                            if (flags.HasFlag(ScanFlags.HiddenPeHeaders))
                            {
                                try { foundPeHeaders.AddRange(inspectorMain.CheckDataRegionsForPeHeaders(procToScan, regions)); } catch { }
                            }

                            if (flags.HasFlag(ScanFlags.DotNetMalware) && isSnapshot)
                            {
                                try
                                {
                                    bool isDotNet = modules.Any(m => m.BaseDllName.Equals("clr.dll", StringComparison.OrdinalIgnoreCase) ||
                                                                     m.BaseDllName.Equals("coreclr.dll", StringComparison.OrdinalIgnoreCase));

                                    if (isDotNet)
                                    {
                                        var dotNetScanner = new DotNetMalwareScanner(logger);
                                        var dotNetResults = dotNetScanner.Scan(pid);
                                        foreach (var finding in dotNetResults) anomalies.Add(finding);
                                    }
                                }
                                catch (Exception ex)
                                {
                                    logger?.Log(LogLevel.Debug, ".NET Scan failed", ex);
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        errors.Add($"Fatal scan error: {ex.Message}");
                    }
                    finally
                    {
                        snapshot?.Dispose();
                    }
                });
            }
            catch (Exception ex)
            {
                result.Errors.Add($"Initialization error: {ex.Message}");
            }

            result.IatHooks = iatHooks.ToList();
            result.InlineHooks = inlineHooks.ToList();
            result.Anomalies = anomalies.ToList();
            result.SuspiciousThreads = suspiciousThreads;
            result.SuspiciousMemoryRegions = suspiciousRegions;
            result.FoundPeHeaders = foundPeHeaders;
            result.Errors = errors.ToList();

            return result;
        }

        public static Task<List<PeAnomalyInfo>> ScanProcessForAnomaliesAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(async () =>
            {
                var results = new List<PeAnomalyInfo>();
                var scanner = new PeAnomalyScanner(logger);
                var access = ProcessAccessFlags.QueryInformation | ProcessAccessFlags.VmRead;

                try
                {
                    var modules = await GetModulesAsync(pid, logger);
                    using (var proc = new ManagedProcess(pid, access))
                    {
                        foreach (var mod in modules)
                        {
                            if (string.IsNullOrEmpty(mod.FullDllName) || mod.FullDllName.StartsWith("[")) continue;
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

        // --- Management Helper Methods ---

        public static bool TrimWorkingSet(int pid)
        {
            try
            {
                using (var proc = new ManagedProcess(pid, ProcessAccessFlags.SetQuota | ProcessAccessFlags.QueryInformation))
                {
                    proc.TrimWorkingSet();
                    return true;
                }
            }
            catch { return false; }
        }

        public static bool SetAffinity(int pid, IntPtr affinityMask)
        {
            try
            {
                using (var proc = new ManagedProcess(pid, ProcessAccessFlags.SetInformation | ProcessAccessFlags.QueryLimitedInformation))
                {
                    proc.SetAffinity(affinityMask);
                    return true;
                }
            }
            catch { return false; }
        }

        public static bool SetPriorityBoostDisabled(int pid, bool isDisabled)
        {
            try
            {
                using (var proc = new ManagedProcess(pid, ProcessAccessFlags.SetInformation | ProcessAccessFlags.QueryLimitedInformation))
                {
                    proc.SetPriorityBoostDisabled(isDisabled);
                    return true;
                }
            }
            catch { return false; }
        }

        public static bool SetIoPriority(int pid, IoPriorityHint priority)
        {
            try
            {
                using (var proc = new ManagedProcess(pid, ProcessAccessFlags.SetInformation))
                {
                    proc.SetIoPriority(priority);
                    return true;
                }
            }
            catch { return false; }
        }

        public static bool SetEcoMode(int pid, bool isEnabled)
        {
            try
            {
                using (var proc = new ManagedProcess(pid, ProcessAccessFlags.SetInformation))
                {
                    proc.SetEcoMode(isEnabled);
                    return true;
                }
            }
            catch { return false; }
        }

        // --- Info Getter Methods ---

        public static Task<List<Models.NetworkConnectionInfo>> GetNetworkConnectionsAsync(IEngineLogger logger = null)
        {
            return Task.Run(() => NetworkManager.GetNetworkConnections());
        }

        public static Task<List<Models.WindowInfo>> GetWindowsAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() => WindowManager.GetWindowsForProcess(pid));
        }

        public static Task<List<Models.DotNetAppDomainInfo>> GetDotNetAppDomainsAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() => DotNetInspector.GetAppDomainInfo(pid));
        }

        public static Task<List<Models.DotNetStringDuplicateInfo>> GetDotNetAllHeapStringsAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() => DotNetInspector.GetAllHeapStrings(pid));
        }

        public static Task<List<Models.DotNetStringDuplicateInfo>> GetDotNetStringDuplicatesAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() => DotNetInspector.GetStringDuplicateStats(pid));
        }

        public static Task<List<Models.DotNetGcRootPathInfo>> GetDotNetGcRootPathAsync(int pid, ulong targetObject, IEngineLogger logger = null)
        {
            return Task.Run(() => DotNetInspector.GetGcRootPath(pid, targetObject));
        }

        public static Task<Models.DotNetThreadPoolInfo> GetDotNetThreadPoolAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() => DotNetInspector.GetThreadPoolInfo(pid));
        }

        public static Task<List<Models.DotNetFinalizerInfo>> GetDotNetFinalizerQueueAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() => DotNetInspector.GetFinalizerInfo(pid));
        }

        public static Task<List<Models.DotNetLockInfo>> GetDotNetLockingInfoAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() => DotNetInspector.GetLockingInfo(pid));
        }

        public static Task<List<Models.DotNetStackFrame>> GetDotNetThreadStackAsync(int pid, int osThreadId, IEngineLogger logger = null)
        {
            return Task.Run(() => DotNetInspector.GetManagedStack(pid, osThreadId));
        }

        public static Task<List<Models.DotNetRootInfo>> GetDotNetGcRootsAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() => DotNetInspector.GetGcRoots(pid));
        }

        public static Task<List<Models.DotNetExceptionInfo>> GetDotNetHeapExceptionsAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() => DotNetInspector.GetHeapExceptions(pid));
        }

        public static Task<List<Models.DotNetHeapStat>> GetDotNetHeapStatsAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() => DotNetInspector.GetHeapStats(pid));
        }

        public static Task<Models.ExtendedThreadInfo> GetExtendedThreadInfoAsync(int threadId, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                using (var thread = new ManagedThread(threadId, ManagedThread.ThreadAccessFlags.QueryInformation))
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

        // Helper for Process/Module Data
        public static Task<List<ProcessModuleInfo>> GetModulesAsync(ManagedProcess proc, IEngineLogger logger = null)
        {
            return Task.Run(() => proc.GetLoadedModules(logger));
        }

        public static Task<List<VirtualMemoryRegion>> GetVirtualMemoryRegionsAsync(ManagedProcess proc, IEngineLogger logger = null)
        {
            return Task.Run(() => proc.GetVirtualMemoryRegions());
        }

        public static Task<List<ProcessModuleInfo>> GetModulesAsync(int pid, IEngineLogger logger = null)
        {
            return Task.Run(() =>
            {
                var access = ProcessAccessFlags.QueryInformation | ProcessAccessFlags.VmRead | ProcessAccessFlags.QueryLimitedInformation;
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
                var access = ProcessAccessFlags.DuplicateHandle | ProcessAccessFlags.QueryInformation | ProcessAccessFlags.QueryLimitedInformation;
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
                    var allHandles = await GetHandlesAsync(pid, logger);
                    return allHandles.Where(h => h.TypeName.Equals("File", StringComparison.OrdinalIgnoreCase)).ToList();
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
                if (string.IsNullOrEmpty(typeNameFilter)) return await GetHandlesAsync(pid, logger);
                try
                {
                    var allHandles = await GetHandlesAsync(pid, logger);
                    return allHandles.Where(h => h.TypeName.Equals(typeNameFilter, StringComparison.OrdinalIgnoreCase)).ToList();
                }
                catch (Exception ex)
                {
                    logger?.Log(LogLevel.Error, $"GetHandlesByTypeAsync failed for PID {pid}.", ex);
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

        // --- Process Control Methods ---

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
            catch { return false; }
        }

        public static bool HardKill(int pid)
        {
            try
            {
                using (var proc = new ManagedProcess(pid, ProcessAccessFlags.SetQuota | ProcessAccessFlags.Terminate))
                {
                    proc.HardKillUsingJob();
                    return true;
                }
            }
            catch { return false; }
        }

        public static bool InjectionKill(int pid)
        {
            try
            {
                using (var proc = new ManagedProcess(pid, ProcessAccessFlags.CreateThread | ProcessAccessFlags.VmOperation | ProcessAccessFlags.VmWrite | ProcessAccessFlags.QueryInformation))
                {
                    proc.KillByThreadInjection();
                    return true;
                }
            }
            catch { return false; }
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
            catch { return false; }
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
            catch { return false; }
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
            catch { return false; }
        }
    }

    public class HookDetectionResult
    {
        public int ProcessId { get; internal set; }
        public List<SecurityInspector.IatHookInfo> IatHooks { get; internal set; }
        public List<SecurityInspector.InlineHookInfo> InlineHooks { get; internal set; }
        public List<SecurityInspector.SuspiciousThreadInfo> SuspiciousThreads { get; internal set; }
        public List<SecurityInspector.SuspiciousMemoryRegionInfo> SuspiciousMemoryRegions { get; internal set; }
        public List<FoundPeHeaderInfo> FoundPeHeaders { get; internal set; }
        public List<string> Errors { get; internal set; }
        public List<PeAnomalyInfo> Anomalies { get; internal set; }

        public bool IsHooked
        {
            get
            {
                return (IatHooks.Count > 0) || (InlineHooks.Count > 0) ||
                       (SuspiciousThreads.Count > 0) || (SuspiciousMemoryRegions.Count > 0) ||
                       (FoundPeHeaders.Count > 0) || (Anomalies.Count > 0);
            }
        }

        internal HookDetectionResult(int pid)
        {
            ProcessId = pid;
            IatHooks = new List<SecurityInspector.IatHookInfo>();
            InlineHooks = new List<SecurityInspector.InlineHookInfo>();
            SuspiciousThreads = new List<SecurityInspector.SuspiciousThreadInfo>();
            SuspiciousMemoryRegions = new List<SecurityInspector.SuspiciousMemoryRegionInfo>();
            Anomalies = new List<PeAnomalyInfo>();
            Errors = new List<string>();
            FoundPeHeaders = new List<FoundPeHeaderInfo>();
        }
    }
}