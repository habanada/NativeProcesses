/*
   NativeProcesses Framework  |
   © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Runtime.InteropServices;

namespace NativeProcesses.Core.Native
{
    internal static class NtProcessInfoStructs
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING_32
        {
            public ushort Length;
            public ushort MaximumLength;
            public uint Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING_64
        {
            public ushort Length;
            public ushort MaximumLength;
            public ulong Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LIST_ENTRY
        {
            public IntPtr Flink;
            public IntPtr Blink;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LIST_ENTRY_32
        {
            public uint Flink;
            public uint Blink;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LIST_ENTRY_64
        {
            public ulong Flink;
            public ulong Blink;
        }

        // --- Process Basic Information ---

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION_32
        {
            public uint ExitStatus;
            public uint PebBaseAddress;
            public uint AffinityMask;
            public uint BasePriority;
            public uint UniqueProcessId;
            public uint InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION_64
        {
            public ulong ExitStatus;
            public ulong PebBaseAddress;
            public ulong AffinityMask;
            public ulong BasePriority;
            public ulong UniqueProcessId;
            public ulong InheritedFromUniqueProcessId;
        }

        // --- PEB (Process Environment Block) ---

        // Gekürzte Version, konzentriert auf Loader-Daten (LDR) und Process Parameters
        [StructLayout(LayoutKind.Sequential)]
        public struct PEB_PARTIAL
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] InheritedAddressSpace;
            public byte BeingDebugged;
            public byte BitField;
            public IntPtr Mutant;
            public IntPtr ImageBaseAddress;
            public IntPtr Ldr; // Zeigt auf PEB_LDR_DATA
            public IntPtr ProcessParameters; // Zeigt auf RTL_USER_PROCESS_PARAMETERS
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PEB_32_PARTIAL
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] InheritedAddressSpace;
            public byte BeingDebugged;
            public byte BitField;
            public uint Mutant;
            public uint ImageBaseAddress;
            public uint Ldr;
            public uint ProcessParameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PEB_64_PARTIAL
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] InheritedAddressSpace;
            public byte BeingDebugged;
            public byte BitField;
            public ulong Mutant;
            public ulong ImageBaseAddress;
            public ulong Ldr;
            public ulong ProcessParameters;
        }

        // --- RTL User Process Parameters (für Spoofing Checks) ---

        [StructLayout(LayoutKind.Sequential)]
        public struct RTL_USER_PROCESS_PARAMETERS_PARTIAL
        {
            public uint MaximumLength;
            public uint Length;
            public uint Flags;
            public uint DebugFlags;
            public IntPtr ConsoleHandle;
            public uint ConsoleFlags;
            public IntPtr StandardInput;
            public IntPtr StandardOutput;
            public IntPtr StandardError;
            public UNICODE_STRING CurrentDirectory;
            public IntPtr CurrentDirectoryHandle;
            public UNICODE_STRING DllPath;
            public UNICODE_STRING ImagePathName; // Wichtig für Spoofing-Check
            public UNICODE_STRING CommandLine;   // Wichtig für Spoofing-Check
        }

        // --- LDR Data (Loader Data Table) ---

        [StructLayout(LayoutKind.Sequential)]
        public struct PEB_LDR_DATA
        {
            public uint Length;
            public byte Initialized;
            public IntPtr SsHandle;
            public LIST_ENTRY InLoadOrderModuleList;
            public LIST_ENTRY InMemoryOrderModuleList;
            public LIST_ENTRY InInitializationOrderModuleList;
            public IntPtr EntryInProgress;
            public byte ShutdownInProgress;
            public IntPtr ShutdownThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PEB_LDR_DATA_32
        {
            public uint Length;
            public byte Initialized;
            public uint SsHandle;
            public LIST_ENTRY_32 InLoadOrderModuleList;
            public LIST_ENTRY_32 InMemoryOrderModuleList;
            public LIST_ENTRY_32 InInitializationOrderModuleList;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PEB_LDR_DATA_64
        {
            public uint Length;
            public byte Initialized;
            public ulong SsHandle;
            public LIST_ENTRY_64 InLoadOrderModuleList;
            public LIST_ENTRY_64 InMemoryOrderModuleList;
            public LIST_ENTRY_64 InInitializationOrderModuleList;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LDR_DATA_TABLE_ENTRY
        {
            public LIST_ENTRY InLoadOrderLinks;
            public LIST_ENTRY InMemoryOrderLinks;
            public LIST_ENTRY InInitializationOrderLinks;
            public IntPtr DllBase;
            public IntPtr EntryPoint;
            public uint SizeOfImage;
            public UNICODE_STRING FullDllName;
            public UNICODE_STRING BaseDllName;
            public uint Flags;
            public ushort LoadCount;
            public ushort TlsIndex;
            public LIST_ENTRY HashLinks;
            public uint TimeDateStamp;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LDR_DATA_TABLE_ENTRY_32
        {
            public LIST_ENTRY_32 InLoadOrderLinks;
            public LIST_ENTRY_32 InMemoryOrderLinks;
            public LIST_ENTRY_32 InInitializationOrderLinks;
            public uint DllBase;
            public uint EntryPoint;
            public uint SizeOfImage;
            public UNICODE_STRING_32 FullDllName;
            public UNICODE_STRING_32 BaseDllName;
            public uint Flags;
            public ushort LoadCount;
            public ushort TlsIndex;
            public LIST_ENTRY_32 HashLinks;
            public uint TimeDateStamp;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LDR_DATA_TABLE_ENTRY_64
        {
            public LIST_ENTRY_64 InLoadOrderLinks;
            public LIST_ENTRY_64 InMemoryOrderLinks;
            public LIST_ENTRY_64 InInitializationOrderLinks;
            public ulong DllBase;
            public ulong EntryPoint;
            public uint SizeOfImage;
            public UNICODE_STRING_64 FullDllName;
            public UNICODE_STRING_64 BaseDllName;
            public uint Flags;
            public ushort LoadCount;
            public ushort TlsIndex;
            public LIST_ENTRY_64 HashLinks;
            public uint TimeDateStamp;
        }

        // --- Memory Information ---

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION_EX
        {
            public MEMORY_BASIC_INFORMATION BasicInfo;
            public uint PartitionId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        // --- Thread Information (TEB) ---

        [StructLayout(LayoutKind.Sequential)]
        public struct TEB_PARTIAL
        {
            public NT_TIB Tib;
            public IntPtr EnvironmentPointer;
            public CLIENT_ID ClientId;
            public IntPtr ActiveRpcHandle;
            public IntPtr ThreadLocalStoragePointer;
            public IntPtr ProcessEnvironmentBlock; // Zeigt zurück auf PEB
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NT_TIB
        {
            public IntPtr ExceptionList;
            public IntPtr StackBase;    // Wichtig für Stack-Walks
            public IntPtr StackLimit;   // Wichtig für Stack-Walks
            public IntPtr SubSystemTib;
            public IntPtr FiberData; // oder Version
            public IntPtr ArbitraryUserPointer;
            public IntPtr Self;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }
    }
}