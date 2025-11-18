/*
   NativeProcesses Framework  |
   © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Runtime.InteropServices;

namespace NativeProcesses.Core.Native
{
    internal static class NativeDefinitions
    {
        public static class NtStatus
        {
            public const uint STATUS_SUCCESS = 0x00000000;
            public const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
            public const uint STATUS_BUFFER_OVERFLOW = 0x80000005;
            public const uint STATUS_BUFFER_TOO_SMALL = 0xC0000023;
            public const uint STATUS_ACCESS_DENIED = 0xC0000022;
            public const uint STATUS_NOT_FOUND = 0xC0000225;
            public const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;
            public const uint STATUS_NO_MORE_ENTRIES = 0x8000001A;
            public const uint STATUS_UNSUCCESSFUL = 0xC0000001;
            public const uint STATUS_NOT_IMPLEMENTED = 0xC0000002;
            public const uint STATUS_INVALID_INFO_CLASS = 0xC0000003;
            public const uint STATUS_INVALID_PARAMETER = 0xC000000D;
            public const uint STATUS_PARTIAL_COPY = 0x8000000D;
        }

        public static class SystemInformationClass
        {
            public const int SystemBasicInformation = 0;
            public const int SystemProcessorInformation = 1;
            public const int SystemPerformanceInformation = 2;
            public const int SystemTimeOfDayInformation = 3;
            public const int SystemProcessInformation = 5;
            public const int SystemProcessorPerformanceInformation = 8;
            public const int SystemModuleInformation = 11;
            public const int SystemHandleInformation = 16;
            public const int SystemInterruptInformation = 23;
            public const int SystemExceptionInformation = 33;
            public const int SystemRegistryQuotaInformation = 37;
            public const int SystemLookasideInformation = 45;
            public const int SystemThreadInformation = 51; // SystemExtendedThreadInformation
            public const int SystemExtendedHandleInformation = 64;
            public const int SystemBootEntropyInformation = 0x75;
            public const int SystemKernelDebuggerInformation = 35;
            public const int SystemCurrentTimeZoneInformation = 44;
            public const int SystemCodeIntegrityInformation = 103;
            public const int SystemPolicyInformation = 134;
        }

        public static class ProcessInformationClass
        {
            public const int ProcessBasicInformation = 0;
            public const int ProcessQuotaLimits = 1;
            public const int ProcessIoCounters = 2;
            public const int ProcessVmCounters = 3;
            public const int ProcessTimes = 4;
            public const int ProcessBasePriority = 5;
            public const int ProcessRaisePriority = 6;
            public const int ProcessDebugPort = 7;
            public const int ProcessExceptionPort = 8;
            public const int ProcessAccessToken = 9;
            public const int ProcessLdtInformation = 10;
            public const int ProcessLdtSize = 11;
            public const int ProcessDefaultHardErrorMode = 12;
            public const int ProcessIoPortHandlers = 13;
            public const int ProcessPooledUsageAndLimits = 14;
            public const int ProcessWorkingSetWatch = 15;
            public const int ProcessUserModeIOPL = 16;
            public const int ProcessEnableAlignmentFaultFixup = 17;
            public const int ProcessPriorityClass = 18;
            public const int ProcessWx86Information = 19;
            public const int ProcessHandleCount = 20;
            public const int ProcessAffinityMask = 21;
            public const int ProcessPriorityBoost = 22;
            public const int ProcessDeviceMap = 23;
            public const int ProcessSessionInformation = 24;
            public const int ProcessForegroundInformation = 25;
            public const int ProcessWow64Information = 26;
            public const int ProcessImageFileName = 27;
            public const int ProcessLUIDDeviceMapsEnabled = 28;
            public const int ProcessBreakOnTermination = 29;
            public const int ProcessDebugObjectHandle = 30;
            public const int ProcessDebugFlags = 31;
            public const int ProcessHandleTracing = 32;
            public const int ProcessIoPriority = 33;
            public const int ProcessExecuteFlags = 34;
            public const int ProcessTlsInformation = 35;
            public const int ProcessCookie = 36;
            public const int ProcessImageInformation = 37;
            public const int ProcessCycleTime = 38;
            public const int ProcessPagePriority = 39;
            public const int ProcessInstrumentationCallback = 40;
            public const int ProcessThreadStackAllocation = 41;
            public const int ProcessWorkingSetWatchEx = 42;
            public const int ProcessImageFileNameWin32 = 43;
            public const int ProcessImageFileMapping = 44;
            public const int ProcessAffinityUpdateMode = 45;
            public const int ProcessMemoryAllocationMode = 46;
            public const int ProcessGroupInformation = 47;
            public const int ProcessTokenVirtualizationEnabled = 48;
            public const int ProcessConsoleHostProcess = 49;
            public const int ProcessWindowInformation = 50;
            public const int ProcessPowerThrottlingState = 51;
            public const int ProcessProtectionInformation = 61;
        }

        public static class ThreadInformationClass
        {
            public const int ThreadBasicInformation = 0;
            public const int ThreadTimes = 1;
            public const int ThreadPriority = 2;
            public const int ThreadBasePriority = 3;
            public const int ThreadAffinityMask = 4;
            public const int ThreadImpersonationToken = 5;
            public const int ThreadDescriptorTableEntry = 6;
            public const int ThreadEnableAlignmentFaultFixup = 7;
            public const int ThreadEventPair_Reusable = 8;
            public const int ThreadQuerySetWin32StartAddress = 9;
            public const int ThreadZeroTlsCell = 10;
            public const int ThreadPerformanceCount = 11;
            public const int ThreadAmILastThread = 12;
            public const int ThreadIdealProcessor = 13;
            public const int ThreadPriorityBoost = 14;
            public const int ThreadSetTlsArrayAddress = 15;
            public const int ThreadIsIoPending = 16;
            public const int ThreadHideFromDebugger = 17;
            public const int ThreadBreakOnTermination = 18;
            public const int ThreadSwitchLegacyState = 19;
            public const int ThreadIsTerminated = 20;
            public const int ThreadLastSystemCall = 21;
            public const int ThreadIoPriority = 22;
            public const int ThreadCycleTime = 23;
            public const int ThreadPagePriority = 24;
            public const int ThreadActualBasePriority = 25;
            public const int ThreadTebInformation = 26;
            public const int ThreadCSwitchMon = 27;
        }

        public static class ObjectInformationClass
        {
            public const int ObjectBasicInformation = 0;
            public const int ObjectNameInformation = 1;
            public const int ObjectTypeInformation = 2;
            public const int ObjectTypesInformation = 3;
            public const int ObjectHandleFlagInformation = 4;
            public const int ObjectSessionInformation = 5;
            public const int ObjectSessionObjectInformation = 6;
        }

        public static class MemoryInformationClass
        {
            public const int MemoryBasicInformation = 0;
            public const int MemoryWorkingSetInformation = 1;
            public const int MemoryMappedFilenameInformation = 2;
            public const int MemoryRegionInformation = 3;
            public const int MemoryWorkingSetExInformation = 4;
            public const int MemorySharedCommitInformation = 5;
            public const int MemoryImageInformation = 6;
            public const int MemoryRegionInformationEx = 7;
            public const int MemoryPrivilegedBasicInformation = 8;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct MEMORY_MAPPED_FILENAME_INFORMATION
        {
            public NtProcessInfoStructs.UNICODE_STRING Name;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)] // Puffer für den Namen
            public string NameBuffer;
        }

        // Detaillierte Image-Infos vom Kernel
        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_IMAGE_INFORMATION
        {
            public IntPtr ImageBase;
            public IntPtr SizeOfImage;
            public uint ImageFlags;
        }

        public static class SectionInformationClass
        {
            public const int SectionBasicInformation = 0;
            public const int SectionImageInformation = 1;
            public const int SectionRelocationInformation = 2;
        }

        public static class SecurityEntities
        {
            public const string SeDebugPrivilege = "SeDebugPrivilege";
            public const string SeShutdownPrivilege = "SeShutdownPrivilege";
            public const string SeChangeNotifyPrivilege = "SeChangeNotifyPrivilege";
            public const string SeUndockPrivilege = "SeUndockPrivilege";
            public const string SeIncreaseWorkingSetPrivilege = "SeIncreaseWorkingSetPrivilege";
            public const string SeTimeZonePrivilege = "SeTimeZonePrivilege";
            public const string SeLoadDriverPrivilege = "SeLoadDriverPrivilege";
            public const string SeSystemEnvironmentPrivilege = "SeSystemEnvironmentPrivilege";
            public const string SeManageVolumePrivilege = "SeManageVolumePrivilege";
            public const string SeImpersonatePrivilege = "SeImpersonatePrivilege";
            public const string SeCreateGlobalPrivilege = "SeCreateGlobalPrivilege";
            public const string SeTcbPrivilege = "SeTcbPrivilege";
            public const string SeBackupPrivilege = "SeBackupPrivilege";
            public const string SeRestorePrivilege = "SeRestorePrivilege";
            public const string SeSecurityPrivilege = "SeSecurityPrivilege";
            public const string SeTakeOwnershipPrivilege = "SeTakeOwnershipPrivilege";
            public const string SeSystemProfilePrivilege = "SeSystemProfilePrivilege";
            public const string SeSystemtimePrivilege = "SeSystemtimePrivilege";
            public const string SeProfileSingleProcessPrivilege = "SeProfileSingleProcessPrivilege";
            public const string SeIncreaseBasePriorityPrivilege = "SeIncreaseBasePriorityPrivilege";
            public const string SeCreatePagefilePrivilege = "SeCreatePagefilePrivilege";
            public const string SeCreatePermanentPrivilege = "SeCreatePermanentPrivilege";
            public const string SeAuditPrivilege = "SeAuditPrivilege";
            public const string SeSystemEnvironment = "SeSystemEnvironmentPrivilege";
            public const string SeMachineAccountPrivilege = "SeMachineAccountPrivilege";
        }

        public static class GdiObjectType
        {
            public const int GDI_OBJECT_TYPE_REGION = 0x04;
            public const int GDI_OBJECT_TYPE_BITMAP = 0x05;
            public const int GDI_OBJECT_TYPE_FONT = 0x0A;
            public const int GDI_OBJECT_TYPE_BRUSH = 0x10;
            public const int GDI_OBJECT_TYPE_PEN = 0x30;
        }

        public static class UserObjectType
        {
            public const int otWindow = 1;
            public const int otMenu = 2;
            public const int otCursorIcon = 3;
        }

        public static class DbgHelp
        {
            [Flags]
            public enum MiniDumpType : int
            {
                // Wir brauchen Full Memory für .NET Heap Analyse!
                MiniDumpWithFullMemory = 0x00000002,
                MiniDumpWithHandleData = 0x00000004,
                MiniDumpWithUnloadedModules = 0x00000020,
                MiniDumpWithProcessThreadData = 0x00000100,
                MiniDumpWithFullMemoryInfo = 0x00000800,
                MiniDumpWithThreadInfo = 0x00001000,
                MiniDumpWithTokenInformation = 0x00040000
            }

            [DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
            public static extern bool MiniDumpWriteDump(
                IntPtr hProcess,
                uint processId,
                IntPtr hFile,
                MiniDumpType dumpType,
                IntPtr exceptionParam,
                IntPtr userStreamParam,
                IntPtr callbackParam);
        }

    }
}