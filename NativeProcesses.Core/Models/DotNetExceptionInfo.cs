/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;

namespace NativeProcesses.Core.Models
{
    public class DotNetExceptionInfo
    {
        public ulong Address { get; set; }
        public string TypeName { get; set; }
        public string Message { get; set; }
        public int HResult { get; set; }
        public ulong InnerExceptionAddress { get; set; }
    }
}