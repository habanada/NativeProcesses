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

namespace NativeProcesses.Core.Native
{
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



        public static Task<HookDetectionResult> ScanProcessForHooksAsync(FullProcessInfo processInfo, IEngineLogger logger = null)
        {
            return Task.Run(async () =>
            {
                int pid = processInfo.Pid;
                var result = new HookDetectionResult(pid);
                var inspector = new SecurityInspector(logger);
                var access = ProcessAccessFlags.QueryInformation | ProcessAccessFlags.VmRead | ProcessAccessFlags.QueryLimitedInformation;
                List<ProcessModuleInfo> modules;
                List<VirtualMemoryRegion> regions;
                try
                {
                    modules = await GetModulesAsync(pid, logger);
                    regions = await GetVirtualMemoryRegionsAsync(pid, logger);
                }
                catch (Exception ex)
                {
                    result.Errors.Add($"Failed to list modules or memory regions: {ex.Message}");
                    return result;
                }
                var ntdllModule = modules.FirstOrDefault(m => m.BaseDllName.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase));
                if (ntdllModule == null)
                {
                    result.Errors.Add("Failed to find ntdll.dll in the process.");
                    return result;
                }
                using (var proc = new ManagedProcess(pid, access))
                {
                    foreach (var mod in modules)
                    {
                        if (string.IsNullOrEmpty(mod.FullDllName) || mod.FullDllName.StartsWith("["))
                        {
                            continue;
                        }
                        try
                        {
                            var inlineHooks = inspector.CheckForInlineHooks(proc, mod.DllBase, mod.FullDllName);
                            if (inlineHooks.Count > 0)
                            {
                                result.InlineHooks.AddRange(inlineHooks);
                            }
                        }
                        catch (Exception ex)
                        {
                            result.Errors.Add($"Error scanning {mod.BaseDllName} for inline hooks: {ex.Message}");
                        }
                        try
                        {
                            var iatHooks = inspector.CheckIatHooks(proc, mod.DllBase, mod.BaseDllName, ntdllModule.DllBase, modules);
                            if (iatHooks.Count > 0)
                            {
                                result.IatHooks.AddRange(iatHooks);
                            }
                        }
                        catch (Exception ex)
                        {
                            result.Errors.Add($"Error scanning {mod.BaseDllName} for IAT hooks: {ex.Message}");
                        }
                    }

                    // 3. Prüfe auf verdächtige Threads (Shellcode)
                    try
                    {
                        var suspiciousThreads = inspector.CheckForSuspiciousThreads(processInfo.Threads, modules, regions);
                        if (suspiciousThreads.Count > 0)
                        {
                            result.SuspiciousThreads.AddRange(suspiciousThreads);
                        }
                    }
                    catch (Exception ex)
                    {
                        result.Errors.Add($"Error scanning for suspicious threads: {ex.Message}");
                    }
                    // 4. NEU: Prüfe auf verdächtige Speicherregionen (RWX/RX)
                    try
                    {
                        var suspiciousRegions = inspector.CheckForSuspiciousMemoryRegions(regions);
                        if (suspiciousRegions.Count > 0)
                        {
                            result.SuspiciousMemoryRegions.AddRange(suspiciousRegions);
                        }
                    }
                    catch (Exception ex)
                    {
                        result.Errors.Add($"Error scanning for suspicious memory regions: {ex.Message}");
                    }

                }
                return result;
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
