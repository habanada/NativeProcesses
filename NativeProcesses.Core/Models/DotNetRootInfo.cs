/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System.Collections.Generic;

namespace NativeProcesses.Core.Models
{
    public class DotNetRootInfo
    {
        public string RootType { get; set; }
        public string Name { get; set; }
        public ulong Address { get; set; }
        public bool IsPinned { get; set; }

        public List<DotNetHeapStat> ReferencedObjects { get; set; }

        public DotNetRootInfo()
        {
            this.ReferencedObjects = new List<DotNetHeapStat>();
        }
    }
}