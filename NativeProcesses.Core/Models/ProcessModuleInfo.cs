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
    public class ProcessModuleInfo
    {
        public string BaseDllName { get; set; }
        public string FullDllName { get; set; }
        public IntPtr DllBase { get; set; }
        public uint SizeOfImage { get; set; }
        public IntPtr EntryPoint { get; set; }

        public ProcessModuleInfo Clone()
        {
            return (ProcessModuleInfo)this.MemberwiseClone();
        }
    }
}
