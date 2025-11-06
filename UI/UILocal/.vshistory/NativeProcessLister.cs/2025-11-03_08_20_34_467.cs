using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace NativeProcesses
{
    public class NativeProcessLister
    {
        private const int SystemProcessInformation = 5;
        private const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
        private const uint STATUS_SUCCESS = 0x00000000;
        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_PROCESS_INFORMATION
        {
            public uint NextEntryOffset;
            public uint NumberOfThreads;
            public long WorkingSetPrivateSize;
            public uint HardFaultCount;
            public uint NumberOfThreadsHighWatermark;
            public ulong CycleTime;
            public long CreateTime;
            public long UserTime;
            public long KernelTime;
            public UNICODE_STRING ImageName;
            public int BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
            public uint HandleCount;
            public uint SessionId;
            public IntPtr UniqueProcessNameMapping;
            public IntPtr PeakVirtualSize;
            public IntPtr VirtualSize;
            public uint PageFaultCount;
            public IntPtr PeakWorkingSetSize;
            public IntPtr WorkingSetSize;
            public IntPtr QuotaPeakPagedPoolUsage;
            public IntPtr QuotaPagedPoolUsage;
            public IntPtr QuotaPeakNonPagedPoolUsage;
            public IntPtr QuotaNonPagedPoolUsage;
            public IntPtr PagefileUsage;
            public IntPtr PeakPagefileUsage;
            public IntPtr PrivatePageCount;
            public long ReadOperationCount;
            public long WriteOperationCount;
            public long OtherOperationCount;
            public long ReadTransferCount;
            public long WriteTransferCount;
            public long OtherTransferCount;
        }
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQuerySystemInformation(
            int SystemInformationClass,
            IntPtr SystemInformation,
            uint SystemInformationLength,
            out uint ReturnLength);
        public List<NativeProcessInfo> GetProcesses()
        {
            var processes = new List<NativeProcessInfo>();
            uint returnLength = 0;
            uint status;
            IntPtr buffer = IntPtr.Zero;
            uint bufferSize = 0;
            try
            {
                do
                {
                    if (buffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(buffer);
                    }
                    bufferSize = bufferSize == 0 ? 1024 * 1024 : bufferSize * 2;
                    buffer = Marshal.AllocHGlobal((int)bufferSize);
                    status = NtQuerySystemInformation(
                        SystemProcessInformation,
                        buffer,
                        bufferSize,
                        out returnLength);
                    if (status == STATUS_INFO_LENGTH_MISMATCH)
                    {
                        bufferSize = returnLength;
                    }
                } while (status == STATUS_INFO_LENGTH_MISMATCH);
                if (status != STATUS_SUCCESS)
                {
                    throw new Win32Exception("NtQuerySystemInformation failed with status: " + status);
                }
                IntPtr currentPtr = buffer;
                while (true)
                {
                    SYSTEM_PROCESS_INFORMATION procInfo =
                        (SYSTEM_PROCESS_INFORMATION)Marshal.PtrToStructure(
                            currentPtr,
                            typeof(SYSTEM_PROCESS_INFORMATION));
                    string name = "System";
                    if (procInfo.ImageName.Buffer != IntPtr.Zero)
                    {
                        name = Marshal.PtrToStringUni(procInfo.ImageName.Buffer, procInfo.ImageName.Length / 2);
                    }
                    if (string.IsNullOrEmpty(name))
                    {
                        name = "System";
                    }
                    processes.Add(new NativeProcessInfo
                    {
                        Pid = (int)procInfo.UniqueProcessId,
                        Name = name,
                        BasePriority = procInfo.BasePriority,
                        NumberOfThreads = procInfo.NumberOfThreads,
                        HandleCount = procInfo.HandleCount,
                        SessionId = procInfo.SessionId,
                        CreateTime = procInfo.CreateTime,
                        UserTime = procInfo.UserTime,
                        KernelTime = procInfo.KernelTime,
                        WorkingSetSize = (long)procInfo.WorkingSetSize,
                        PeakWorkingSetSize = (long)procInfo.PeakWorkingSetSize,
                        PrivatePageCount = (long)procInfo.PrivatePageCount,
                        PagefileUsage = (long)procInfo.PagefileUsage
                    });
                    if (procInfo.NextEntryOffset == 0)
                    {
                        break;
                    }
                    currentPtr = (IntPtr)(currentPtr.ToInt64() + procInfo.NextEntryOffset);
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            return processes;
        }
    }
}
