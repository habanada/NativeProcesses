using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static NativeProcesses.Core.Native.ActivationContext;

namespace NativeProcesses.Core.Native
{
    public static class Kernel32
    {
        #region P/Invoke Definitions
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateActCtx(ref ACTCTX pActCtx);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ActivateActCtx(IntPtr hActCtx, out IntPtr lpCookie);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DeactivateActCtx(uint dwFlags, IntPtr ulCookie);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void ReleaseActCtx(IntPtr hActCtx);
        [DllImport("kernel32.dll")]
        public static extern bool RtlAddFunctionTable(IntPtr FunctionTable, uint EntryCount, ulong BaseAddress);

        [DllImport("kernel32.dll")]
        public static extern bool RtlDeleteFunctionTable(IntPtr FunctionTable);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);


        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint MEM_RELEASE = 0x8000;

        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_EXECUTE_READ = 0x20;

        // DLL Main Reasons
        public const uint DLL_PROCESS_ATTACH = 1;
        public const uint DLL_THREAD_ATTACH = 2;
        public const uint DLL_THREAD_DETACH = 3;
        public const uint DLL_PROCESS_DETACH = 0;
        #endregion

    }
}
