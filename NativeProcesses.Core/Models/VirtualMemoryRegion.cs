using System;
using static NativeProcesses.Core.Native.ManagedProcess;

namespace NativeProcesses.Core.Models
{
    public class VirtualMemoryRegion
    {
        public IntPtr BaseAddress { get; set; }
        public IntPtr AllocationBase { get; set; }
        public long RegionSize { get; set; }
        public string State { get; set; }
        public string Type { get; set; }
        public string Protection { get; set; }
        public string AllocationProtection { get; set; }

        public VirtualMemoryRegion(IntPtr baseAddress, IntPtr allocationBase, long regionSize, uint state, uint type, uint protect, uint allocProtect)
        {
            this.BaseAddress = baseAddress;
            this.AllocationBase = allocationBase;
            this.RegionSize = regionSize;
            this.State = FormatState(state);
            this.Type = FormatType(type);
            this.Protection = FormatProtect(protect);
            this.AllocationProtection = FormatProtect(allocProtect);
        }

        private static string FormatState(uint state)
        {
            if ((state & (uint)MemoryState.MEM_COMMIT) != 0) return "Commit";
            if ((state & (uint)MemoryState.MEM_RESERVE) != 0) return "Reserve";
            if ((state & (uint)MemoryState.MEM_FREE) != 0) return "Free";
            return "0x" + state.ToString("X");
        }

        private static string FormatType(uint type)
        {
            if ((type & (uint)MemoryType.MEM_PRIVATE) != 0) return "Private";
            if ((type & (uint)MemoryType.MEM_MAPPED) != 0) return "Mapped";
            if ((type & (uint)MemoryType.MEM_IMAGE) != 0) return "Image";
            return "0x" + type.ToString("X");
        }

        private static string FormatProtect(uint protect)
        {
            if (protect == 0) return "---";
            string p = ((MemoryProtect)protect).ToString().Replace("PAGE_", "").Replace(", ", " | ");
            return p;
        }
    }
}