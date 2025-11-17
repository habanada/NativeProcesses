/*
   NativeProcesses Framework  |
   © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Runtime.InteropServices;

namespace NativeProcesses.Core.Native
{
    internal static class PssDefines
    {
        [Flags]
        public enum PSS_CAPTURE_FLAGS : uint
        {
            PSS_CAPTURE_NONE = 0x00000000,
            PSS_CAPTURE_VA_CLONE = 0x00000001,
            PSS_CAPTURE_RESERVED_00000002 = 0x00000002,
            PSS_CAPTURE_HANDLES = 0x00000004,
            PSS_CAPTURE_HANDLE_NAME_INFORMATION = 0x00000008,
            PSS_CAPTURE_HANDLE_BASIC_INFORMATION = 0x00000010,
            PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION = 0x00000020,
            PSS_CAPTURE_HANDLE_TRACE = 0x00000040,
            PSS_CAPTURE_THREADS = 0x00000080,
            PSS_CAPTURE_THREAD_CONTEXT = 0x00000100,
            PSS_CAPTURE_THREAD_CONTEXT_EXTENDED = 0x00000200,
            PSS_CAPTURE_RESERVED_00000400 = 0x00000400,
            PSS_CAPTURE_VA_SPACE = 0x00000800,
            PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION = 0x00001000,
            PSS_CAPTURE_IPT_TRACE = 0x00002000,
            PSS_CAPTURE_DIAGNOSTIC_INFORMATION = 0x00004000, // Windows 11 specific?

            PSS_CREATE_BREAKAWAY_OPTIONAL = 0x04000000,
            PSS_CREATE_BREAKAWAY = 0x08000000,
            PSS_CREATE_FORCE_BREAKAWAY = 0x10000000,
            PSS_CREATE_USE_VM_ALLOCATIONS = 0x20000000,
            PSS_CREATE_MEASURE_PERFORMANCE = 0x40000000,
            PSS_CREATE_RELEASE_SECTION = 0x80000000
        }

        public enum PSS_QUERY_INFORMATION_CLASS
        {
            PssQueryProcessInformation = 0,
            PssQueryVaCloneInformation = 1,
            PssQueryAuxiliaryPageInformation = 2,
            PssQueryVaSpaceInformation = 3,
            PssQueryHandleInformation = 4,
            PssQueryThreadInformation = 5,
            PssQueryHandleTraceInformation = 6,
            PssQueryPerformanceCounters = 7
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PSS_VA_CLONE_INFORMATION
        {
            public IntPtr VaCloneHandle;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int PssCaptureSnapshot(
            IntPtr ProcessHandle,
            PSS_CAPTURE_FLAGS CaptureFlags,
            int ThreadContextFlags,
            out IntPtr SnapshotHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int PssFreeSnapshot(
            IntPtr ProcessHandle,
            IntPtr SnapshotHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int PssQuerySnapshot(
            IntPtr SnapshotHandle,
            PSS_QUERY_INFORMATION_CLASS InformationClass,
            IntPtr Buffer,
            int BufferLength);
    }
}