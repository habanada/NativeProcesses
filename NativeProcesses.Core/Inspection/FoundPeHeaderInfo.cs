/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
namespace NativeProcesses.Core.Inspection
{
    public class FoundPeHeaderInfo
    {
        public IntPtr BaseAddress { get; set; }
        public long RegionSize { get; set; }
        public string RegionType { get; set; }
        public string RegionProtection { get; set; }
        public string Status { get; set; } // z.B. "PE Header found at offset 0"
        public bool RequiresHeaderReconstruction { get; set; }
        public byte[] SuggestedHeaderFix { get; set; }
    }
}