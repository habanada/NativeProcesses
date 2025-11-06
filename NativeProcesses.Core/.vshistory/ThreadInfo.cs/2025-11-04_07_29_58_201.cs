using static NativeProcesses.NativeProcessLister;

namespace NativeProcesses.Core
{
    public class ThreadInfo
    {
        public int ThreadId { get; private set; }
        public int BasePriority { get; private set; }
        public long KernelTime { get; private set; }
        public long UserTime { get; private set; }

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