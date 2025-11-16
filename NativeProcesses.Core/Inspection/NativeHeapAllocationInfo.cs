using System;

namespace NativeProcesses.Core.Inspection
{
    public class NativeHeapAllocationInfo
    {
        public int ProcessId { get; set; }
        public int ThreadId { get; set; }
        public DateTime TimeStamp { get; set; }
        public string EventName { get; set; }
        public IntPtr BaseAddress { get; set; }
        public long Size { get; set; }
        public string Type { get; set; }
        public string Protection { get; set; }
    }
}