using System;
namespace NativeProcesses.Core.Inspection
{
    public class FoundPeHeaderInfo
    {
        public IntPtr BaseAddress;
        public long RegionSize;
        public string RegionType;
        public string RegionProtection;
        public string Status; // z.B. "PE Header found at offset 0"
    }
}