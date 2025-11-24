using System;
using System.Collections.Generic;

namespace NativeProcesses.Core.Models
{
    public enum ThreadScanStatus
    {
        Clean,
        SuspiciousStart,        // Startadresse in Shellcode/Unbacked
        SuspiciousStack,        // Callstack zeigt in Shellcode
        SuspiciousReturn,       // Return Address auf Stack ist Shellcode
        SleepingBeacon          // Thread schläft in Shellcode
    }

    public class ThreadScanReport
    {
        public int ThreadId { get; set; }
        public ThreadScanStatus Status { get; set; } = ThreadScanStatus.Clean;
        public IntPtr StartAddress { get; set; }
        public string StartAddressSymbol { get; set; }
        public string StartAddressModule { get; set; } // "kernel32.dll" oder "Unbacked"
        public List<string> StackTrace { get; set; } = new List<string>();
        public string Details { get; set; }
    }
}