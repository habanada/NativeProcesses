/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/

using static NativeProcesses.Core.NativeProcessLister;

namespace NativeProcesses.Core
{
    public class ThreadInfo
    {
        public int ThreadId { get; private set; }
        public int BasePriority { get; private set; }
        public long KernelTime { get; private set; }
        public long UserTime { get; private set; }
        public ThreadInfo()
        {
        }
        public ThreadInfo(SYSTEM_THREAD_INFORMATION rawInfo)
        {
            this.ThreadId = (int)rawInfo.ClientId.UniqueThread;
            this.BasePriority = rawInfo.BasePriority;
            this.KernelTime = rawInfo.KernelTime;
            this.UserTime = rawInfo.UserTime;
        }

        public ThreadInfo CreateSnapshot()
        {
            return (ThreadInfo)this.MemberwiseClone();
        }
    }
}