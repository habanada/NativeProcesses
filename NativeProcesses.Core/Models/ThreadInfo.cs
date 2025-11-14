/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/

using System;
using static NativeProcesses.Core.Native.NativeProcessLister;

namespace NativeProcesses.Core
{
    public class ThreadInfo
    {
        public int ThreadId { get; private set; }
        public int BasePriority { get; set; }
        public long KernelTime { get; set; }
        public long UserTime { get; set; }
        public IntPtr StartAddress { get; private set; }
        public ThreadInfo()
        {
        }
        public ThreadInfo(SYSTEM_THREAD_INFORMATION rawInfo)
        {
            this.ThreadId = (int)rawInfo.ClientId.UniqueThread;
            this.BasePriority = rawInfo.BasePriority;
            this.KernelTime = rawInfo.KernelTime;
            this.UserTime = rawInfo.UserTime;
            this.StartAddress = rawInfo.StartAddress;
        }

        public ThreadInfo CreateSnapshot()
        {
            return (ThreadInfo)this.MemberwiseClone();
        }
        public void ApplyUpdate(ThreadInfo source)
        {
            this.BasePriority = source.BasePriority;
            this.KernelTime = source.KernelTime;
            this.UserTime = source.UserTime;
            this.StartAddress = source.StartAddress;
        }
    }
}