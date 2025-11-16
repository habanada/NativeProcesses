using NativeProcesses.Core.Models;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static NativeProcesses.Core.Native.NtProcessInfoStructs;
using static NativeProcesses.Core.Native.NativeDefinitions;

namespace NativeProcesses.Core.Native
{
    public static class PebModuleEnumerator
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            IntPtr processInformation,
            uint processInformationLength,
            out uint returnLength);

        public static List<ProcessModuleInfo> GetModules(ManagedProcess process)
        {
            bool isWow64;
            try
            {
                isWow64 = process.GetIsWow64();
            }
            catch (Exception ex)
            {
                throw new Win32Exception("Failed to determine process architecture (GetIsWow64).", ex);
            }

            if (isWow64)
            {
                return GetWow64Modules(process);
            }
            else
            {
                return GetNativeModules(process);
            }
        }

        private static List<ProcessModuleInfo> GetNativeModules(ManagedProcess process)
        {
            var modules = new List<ProcessModuleInfo>();
            IntPtr pbiPtr = IntPtr.Zero;

            try
            {
                uint pbiSize = (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION_64));
                pbiPtr = Marshal.AllocHGlobal((int)pbiSize);
                int status = NtQueryInformationProcess(process.Handle, ProcessInformationClass.ProcessBasicInformation, pbiPtr, pbiSize, out _);
                if (status != 0)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "NtQueryInformationProcess(ProcessBasicInformation) failed.");
                }

                var pbi = ByteArrayToStructure<PROCESS_BASIC_INFORMATION_64>(ReadMemoryRaw(pbiPtr, (int)pbiSize));
                byte[] pebBytes = process.ReadMemory(pbi.PebBaseAddress, Marshal.SizeOf(typeof(PEB_64)));
                var peb = ByteArrayToStructure<PEB_64>(pebBytes);

                byte[] ldrBytes = process.ReadMemory(peb.Ldr, Marshal.SizeOf(typeof(PEB_LDR_DATA_64)));
                var ldrData = ByteArrayToStructure<PEB_LDR_DATA_64>(ldrBytes);

                IntPtr currentLink = ldrData.InLoadOrderModuleList.Flink;
                IntPtr listHead = IntPtr.Add(peb.Ldr, (int)Marshal.OffsetOf(typeof(PEB_LDR_DATA_64), "InLoadOrderModuleList"));

                for (int i = 0; i < 2048; i++)
                {
                    if (currentLink == listHead || currentLink == IntPtr.Zero)
                    {
                        break;
                    }

                    IntPtr entryAddress = currentLink;
                    byte[] entryBytes = process.ReadMemory(entryAddress, Marshal.SizeOf(typeof(LDR_DATA_TABLE_ENTRY_64)));
                    var entry = ByteArrayToStructure<LDR_DATA_TABLE_ENTRY_64>(entryBytes);

                    string baseName = ReadUnicodeString(process, entry.BaseDllName);
                    string fullName = ReadUnicodeString(process, entry.FullDllName);

                    modules.Add(new ProcessModuleInfo
                    {
                        BaseDllName = baseName,
                        FullDllName = fullName,
                        DllBase = entry.DllBase,
                        SizeOfImage = entry.SizeOfImage,
                        EntryPoint = entry.EntryPoint
                    });

                    currentLink = entry.InLoadOrderLinks.Flink;
                }

                return modules;
            }
            finally
            {
                if (pbiPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pbiPtr);
                }
            }
        }

        private static List<ProcessModuleInfo> GetWow64Modules(ManagedProcess process)
        {
            var modules = new List<ProcessModuleInfo>();
            IntPtr peb32AddressPtr = Marshal.AllocHGlobal(IntPtr.Size);

            try
            {
                int status = NtQueryInformationProcess(process.Handle, ProcessInformationClass.ProcessWow64Information, peb32AddressPtr, (uint)IntPtr.Size, out _);
                if (status != 0)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "NtQueryInformationProcess(ProcessWow64Information) failed.");
                }

                IntPtr peb32Address = (IntPtr)Marshal.ReadInt32(peb32AddressPtr);
                byte[] pebBytes = process.ReadMemory(peb32Address, Marshal.SizeOf(typeof(PEB_32)));
                var peb = ByteArrayToStructure<PEB_32>(pebBytes);

                byte[] ldrBytes = process.ReadMemory((IntPtr)peb.Ldr, Marshal.SizeOf(typeof(PEB_LDR_DATA_32)));
                var ldrData = ByteArrayToStructure<PEB_LDR_DATA_32>(ldrBytes);

                IntPtr currentLink = (IntPtr)ldrData.InLoadOrderModuleList.Flink;
                IntPtr listHead = IntPtr.Add((IntPtr)peb.Ldr, (int)Marshal.OffsetOf(typeof(PEB_LDR_DATA_32), "InLoadOrderModuleList"));

                for (int i = 0; i < 2048; i++)
                {
                    if (currentLink == listHead || currentLink == IntPtr.Zero)
                    {
                        break;
                    }

                    IntPtr entryAddress = currentLink;
                    byte[] entryBytes = process.ReadMemory(entryAddress, Marshal.SizeOf(typeof(LDR_DATA_TABLE_ENTRY_32)));
                    var entry = ByteArrayToStructure<LDR_DATA_TABLE_ENTRY_32>(entryBytes);

                    string baseName = ReadUnicodeString32(process, entry.BaseDllName);
                    string fullName = ReadUnicodeString32(process, entry.FullDllName);

                    modules.Add(new ProcessModuleInfo
                    {
                        BaseDllName = baseName,
                        FullDllName = fullName,
                        DllBase = (IntPtr)entry.DllBase,
                        SizeOfImage = entry.SizeOfImage,
                        EntryPoint = (IntPtr)entry.EntryPoint
                    });

                    currentLink = (IntPtr)entry.InLoadOrderLinks.Flink;
                }

                return modules;
            }
            finally
            {
                Marshal.FreeHGlobal(peb32AddressPtr);
            }
        }

        private static string ReadUnicodeString(ManagedProcess process, UNICODE_STRING_64 us)
        {
            if (us.Length == 0 || us.Buffer == IntPtr.Zero)
            {
                return string.Empty;
            }
            byte[] bytes = process.ReadMemory(us.Buffer, us.Length);
            return Encoding.Unicode.GetString(bytes);
        }

        private static string ReadUnicodeString32(ManagedProcess process, UNICODE_STRING_32 us)
        {
            if (us.Length == 0 || us.Buffer == 0)
            {
                return string.Empty;
            }
            byte[] bytes = process.ReadMemory((IntPtr)us.Buffer, us.Length);
            return Encoding.Unicode.GetString(bytes);
        }

        private static byte[] ReadMemoryRaw(IntPtr address, int size)
        {
            byte[] buffer = new byte[size];
            Marshal.Copy(address, buffer, 0, size);
            return buffer;
        }

        private static T ByteArrayToStructure<T>(byte[] bytes) where T : struct
        {
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                return (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            }
            finally
            {
                handle.Free();
            }
        }
    }
}
