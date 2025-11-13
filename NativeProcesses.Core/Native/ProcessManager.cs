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
