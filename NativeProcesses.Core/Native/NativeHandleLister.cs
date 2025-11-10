using NativeProcesses.Core.Engine;
using NativeProcesses.Core.Models;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NativeProcesses.Core.Native
{
    public class NativeHandleLister
    {
        private IEngineLogger _logger;

        private const int SystemHandleInformation = 16;
        private const int ObjectNameInformation = 1;
        private const int ObjectTypeInformation = 2;

        private const uint STATUS_SUCCESS = 0x00000000;
        private const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
        private const uint STATUS_BUFFER_OVERFLOW = 0x80000005;

        private const uint PROCESS_DUP_HANDLE = 0x0040;
        private const uint DUPLICATE_SAME_ACCESS = 0x00000002;

        #region P/Invoke Ntdll
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQuerySystemInformation(
            int SystemInformationClass,
            IntPtr SystemInformation,
            uint SystemInformationLength,
            out uint ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryObject(
            IntPtr Handle,
            int ObjectInformationClass,
            IntPtr ObjectInformation,
            uint ObjectInformationLength,
            out uint ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtDuplicateObject(
            IntPtr SourceProcessHandle,
            IntPtr SourceHandle,
            IntPtr TargetProcessHandle,
            out IntPtr TargetHandle,
            uint DesiredAccess,
            uint HandleAttributes,
            uint Options);
        #endregion

        #region P/Invoke Kernel32
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();
        #endregion

        #region Structs
        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_HANDLE_ENTRY
        {
            public ushort ProcessId;
            public ushort CreatorBackTraceIndex;
            public byte ObjectTypeIndex;
            public byte HandleAttributes;
            public ushort HandleValue;
            public IntPtr Object;
            public uint GrantedAccess;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct OBJECT_TYPE_INFORMATION
        {
            public UNICODE_STRING TypeName;
            public uint TotalNumberOfObjects;
            public uint TotalNumberOfHandles;
            public uint TotalPagedPoolUsage;
            public uint TotalNonPagedPoolUsage;
            public uint TotalNamePoolUsage;
            public uint TotalHandleTableUsage;
            public uint HighWaterNumberOfObjects;
            public uint HighWaterNumberOfHandles;
            public uint HighWaterPagedPoolUsage;
            public uint HighWaterNonPagedPoolUsage;
            public uint HighWaterNamePoolUsage;
            public uint HighWaterHandleTableUsage;
            public uint InvalidAttributes;
            public GENERIC_MAPPING GenericMapping;
            public uint ValidAccessMask;
            public byte SecurityRequired;
            public byte MaintainHandleCount;
            public ushort MaintainTypeList;
            public int PoolType;
            public uint DefaultPagedPoolCharge;
            public uint DefaultNonPagedPoolCharge;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct GENERIC_MAPPING
        {
            public int GenericRead;
            public int GenericWrite;
            public int GenericExecute;
            public int GenericAll;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct OBJECT_NAME_INFORMATION
        {
            public UNICODE_STRING Name;
        }
        #endregion

        public NativeHandleLister(IEngineLogger logger)
        {
            _logger = logger;
        }

        public List<NativeHandleInfo> GetProcessHandles(int pid)
        {
            var handles = new List<NativeHandleInfo>();
            IntPtr targetProcessHandle = IntPtr.Zero;
            IntPtr buffer = IntPtr.Zero;
            uint bufferSize = 0x10000;

            try
            {
                const uint PROCESS_QUERY_INFORMATION = 0x0400;

                targetProcessHandle = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, false, pid);
                if (targetProcessHandle == IntPtr.Zero)
                {
                    _logger?.Log(LogLevel.Warning, $"Failed to open process {pid} for handle enumeration.", new Win32Exception(Marshal.GetLastWin32Error()));
                    return handles;
                }

                IntPtr currentProcessHandle = GetCurrentProcess();
                buffer = Marshal.AllocHGlobal((int)bufferSize);

                while (true)
                {
                    uint status = NtQuerySystemInformation(
                        SystemHandleInformation,
                        buffer,
                        bufferSize,
                        out uint returnLength);

                    if (status == STATUS_SUCCESS)
                    {
                        break;
                    }
                    else if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_OVERFLOW)
                    {
                        Marshal.FreeHGlobal(buffer);
                        bufferSize = returnLength + 0x2000;
                        if (bufferSize < returnLength)
                        {
                            _logger?.Log(LogLevel.Error, "NtQuerySystemInformation(Handles) buffer size overflow.", null);
                            return handles;
                        }
                        buffer = Marshal.AllocHGlobal((int)bufferSize);
                    }
                    else
                    {
                        _logger?.Log(LogLevel.Error, $"NtQuerySystemInformation(Handles) failed.", new Win32Exception($"Status: 0x{status:X}"));
                        return handles;
                    }
                }

                long handleCount = Marshal.ReadIntPtr(buffer).ToInt64();
                IntPtr handleArrayPtr = IntPtr.Add(buffer, IntPtr.Size);
                int handleEntrySize = Marshal.SizeOf(typeof(SYSTEM_HANDLE_ENTRY));

                for (long i = 0; i < handleCount; i++)
                {
                    IntPtr handleEntryPtr = IntPtr.Add(handleArrayPtr, (int)(i * handleEntrySize));
                    SYSTEM_HANDLE_ENTRY entry = (SYSTEM_HANDLE_ENTRY)Marshal.PtrToStructure(handleEntryPtr, typeof(SYSTEM_HANDLE_ENTRY));

                    if (entry.ProcessId != pid)
                    {
                        continue;
                    }

                    IntPtr duplicatedHandle = IntPtr.Zero;
                    uint dupStatus = NtDuplicateObject(
                        targetProcessHandle,
                        (IntPtr)entry.HandleValue,
                        currentProcessHandle,
                        out duplicatedHandle,
                        0, //DesiredAccess (wird ignoriert bei DUPLICATE_SAME_ACCESS)
                        0, //HandleAttributes
                        DUPLICATE_SAME_ACCESS); //Options

                    if (dupStatus != STATUS_SUCCESS)
                    {
                        continue;
                    }

                    try
                    {
                        string typeName = GetHandleType(duplicatedHandle);
                        string name = "";

                        if (typeName == "File" || typeName == "Key" || typeName == "Section" || typeName == "Event" || typeName == "Mutant" || typeName == "Directory")
                        {
                            name = GetHandleName(duplicatedHandle);
                        }

                        handles.Add(new NativeHandleInfo
                        {
                            ProcessId = entry.ProcessId,
                            HandleValue = entry.HandleValue,
                            GrantedAccess = entry.GrantedAccess,
                            ObjectTypeIndex = entry.ObjectTypeIndex,
                            TypeName = typeName,
                            Name = name
                        });
                    }
                    finally
                    {
                        CloseHandle(duplicatedHandle);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, "Failed during handle enumeration.", ex);
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
                if (targetProcessHandle != IntPtr.Zero)
                {
                    CloseHandle(targetProcessHandle);
                }
            }

            return handles;
        }

        private string GetHandleType(IntPtr handle)
        {
            IntPtr buffer = IntPtr.Zero;
            uint bufferSize = 0x1000;

            try
            {
                buffer = Marshal.AllocHGlobal((int)bufferSize);

                int status = NtQueryObject(
                    handle,
                    ObjectTypeInformation,
                    buffer,
                    bufferSize,
                    out uint returnLength);

                if (status != STATUS_SUCCESS)
                {
                    return "N/A";
                }

                OBJECT_TYPE_INFORMATION typeInfo = (OBJECT_TYPE_INFORMATION)Marshal.PtrToStructure(buffer, typeof(OBJECT_TYPE_INFORMATION));
                return Marshal.PtrToStringUni(typeInfo.TypeName.Buffer, typeInfo.TypeName.Length / 2);
            }
            catch
            {
                return "N/A (Error)";
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }

        private string GetHandleName(IntPtr handle)
        {
            IntPtr buffer = IntPtr.Zero;
            uint bufferSize = 0x1000;

            try
            {
                buffer = Marshal.AllocHGlobal((int)bufferSize);

                int status = NtQueryObject(
                    handle,
                    ObjectNameInformation,
                    buffer,
                    bufferSize,
                    out uint returnLength);

                if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_OVERFLOW)
                {
                    Marshal.FreeHGlobal(buffer);
                    bufferSize = returnLength;
                    if (bufferSize == 0) return "";

                    buffer = Marshal.AllocHGlobal((int)bufferSize);
                    status = NtQueryObject(handle, ObjectNameInformation, buffer, bufferSize, out _);
                }

                if (status != STATUS_SUCCESS)
                {
                    return "";
                }

                OBJECT_NAME_INFORMATION nameInfo = (OBJECT_NAME_INFORMATION)Marshal.PtrToStructure(buffer, typeof(OBJECT_NAME_INFORMATION));
                if (nameInfo.Name.Length == 0)
                {
                    return "";
                }

                return Marshal.PtrToStringUni(nameInfo.Name.Buffer, nameInfo.Name.Length / 2);
            }
            catch
            {
                return "";
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }
    }
}
