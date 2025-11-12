/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using NativeProcesses.Core.Native;
using System.Collections.Generic;
using System.Runtime.InteropServices;
namespace NativeProcesses.Core
{
    [StructLayout(LayoutKind.Sequential)]
    public struct NativeProcessInfo
    {
        public int Pid;
        public string Name;
        public int BasePriority;
        public uint NumberOfThreads;
        public uint HandleCount;
        public uint SessionId;
        public long CreateTime;
        public long UserTime;
        public long KernelTime;
        public long WorkingSetSize;
        public long PeakWorkingSetSize;
        public long PrivatePageCount;
        public long PagefileUsage;

        public uint PageFaultCount;
        public long PagedPoolUsage;
        public long NonPagedPoolUsage;

        public long ReadOperationCount;
        public long WriteOperationCount;
        public long OtherOperationCount;
        public long ReadTransferCount;
        public long WriteTransferCount;
        public long OtherTransferCount;

        public List<NativeProcessLister.SYSTEM_THREAD_INFORMATION> Threads;
    }
}
