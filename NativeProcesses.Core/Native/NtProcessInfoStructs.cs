using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NativeProcesses.Core.Native
{
    internal static class NtProcessInfoStructs
    {
        internal const int ProcessBasicInformation = 0;
        internal const int ProcessWow64Information = 26;

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION_64
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr Reserved3;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION_32
        {
            public IntPtr Reserved1;
            public uint PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr Reserved3;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PEB_64
        {
            public byte Reserved1_0;
            public byte Reserved1_1;
            public byte BeingDebugged;
            public byte Reserved1_2;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr Ldr;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PEB_32
        {
            public byte Reserved1_0;
            public byte Reserved1_1;
            public byte BeingDebugged;
            public byte Reserved1_2;
            public uint Reserved2_0;
            public uint Reserved2_1;
            public uint Ldr;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PEB_LDR_DATA_64
        {
            public uint Length;
            public byte Initialized;
            public IntPtr SsHandle;
            public LIST_ENTRY_64 InLoadOrderModuleList;
            public LIST_ENTRY_64 InMemoryOrderModuleList;
            public LIST_ENTRY_64 InInitializationOrderModuleList;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PEB_LDR_DATA_32
        {
            public uint Length;
            public byte Initialized;
            public uint SsHandle;
            public LIST_ENTRY_32 InLoadOrderModuleList;
            public LIST_ENTRY_32 InMemoryOrderModuleList;
            public LIST_ENTRY_32 InInitializationOrderModuleList;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct LIST_ENTRY_64
        {
            public IntPtr Flink;
            public IntPtr Blink;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct LIST_ENTRY_32
        {
            public uint Flink;
            public uint Blink;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct LDR_DATA_TABLE_ENTRY_64
        {
            public LIST_ENTRY_64 InLoadOrderLinks;
            public LIST_ENTRY_64 InMemoryOrderLinks;
            public LIST_ENTRY_64 InInitializationOrderLinks;
            public IntPtr DllBase;
            public IntPtr EntryPoint;
            public uint SizeOfImage;
            public UNICODE_STRING_64 FullDllName;
            public UNICODE_STRING_64 BaseDllName;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct LDR_DATA_TABLE_ENTRY_32
        {
            public LIST_ENTRY_32 InLoadOrderLinks;
            public LIST_ENTRY_32 InMemoryOrderLinks;
            public LIST_ENTRY_32 InInitializationOrderLinks;
            public uint DllBase;
            public uint EntryPoint;
            public uint SizeOfImage;
            public UNICODE_STRING_32 FullDllName;
            public UNICODE_STRING_32 BaseDllName;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct UNICODE_STRING_64
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct UNICODE_STRING_32
        {
            public ushort Length;
            public ushort MaximumLength;
            public uint Buffer;
        }
    }
}
