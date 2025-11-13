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