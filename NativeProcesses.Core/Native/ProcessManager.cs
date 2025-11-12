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
