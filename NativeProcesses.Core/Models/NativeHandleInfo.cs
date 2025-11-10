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
