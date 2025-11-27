using System;
using System.Runtime.InteropServices;

namespace NativeProcesses.Core.Native
{
    public static class ActivationContext
    {
        [Flags]
        public enum ACTCTX_FLAG : uint
        {
            PROCESSOR_ARCHITECTURE_VALID = 0x001,
            LANGID_VALID = 0x002,
            ASSEMBLY_DIRECTORY_VALID = 0x004,
            RESOURCE_NAME_VALID = 0x008,
            SET_PROCESS_DEFAULT = 0x010,
            APPLICATION_NAME_VALID = 0x020,
            SOURCE_IS_ASSEMBLYREF_CHAIN = 0x040,
            HMODULE_VALID = 0x080
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct ACTCTX
        {
            public int cbSize;
            public uint dwFlags;
            public string lpSource;
            public ushort wProcessorArchitecture;
            public ushort wLangId;
            public string lpAssemblyDirectory;
            public IntPtr lpResourceName;
            public string lpApplicationName;
            public IntPtr hModule;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateActCtx(ref ACTCTX pActCtx);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ActivateActCtx(IntPtr hActCtx, out IntPtr lpCookie);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DeactivateActCtx(uint dwFlags, IntPtr ulCookie);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void ReleaseActCtx(IntPtr hActCtx);

        // FIX für CS0283: static readonly statt const für IntPtr
        public static readonly IntPtr INVALID_HANDLE_VALUE = (IntPtr)(-1);
    }
}