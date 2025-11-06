using System.Runtime.InteropServices;

namespace NativeProcesses.Core
{
    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessIoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }
}