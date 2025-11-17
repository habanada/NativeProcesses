/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NativeProcesses.Core.Models
{
    public struct NativeHandleInfo
    {
        public int ProcessId { get; set; }
        public ushort HandleValue { get; set; }
        public string TypeName { get; set; }
        public string Name { get; set; }
        public byte ObjectTypeIndex { get; set; }
        public uint GrantedAccess { get; set; }
    }
}
