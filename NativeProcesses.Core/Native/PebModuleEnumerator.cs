/*
   NativeProcesses Framework  |
   © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using NativeProcesses.Core.Models;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
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
                // 1. Prozess-Basis-Infos holen (um die PEB-Adresse zu finden)
                uint pbiSize = (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION_64));
                pbiPtr = Marshal.AllocHGlobal((int)pbiSize);

                int status = NtQueryInformationProcess(
                    process.Handle,
                    ProcessInformationClass.ProcessBasicInformation,
                    pbiPtr,
                    pbiSize,
                    out _);

                if (status != 0)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "NtQueryInformationProcess(ProcessBasicInformation) failed.");
                }

                var pbi = ByteArrayToStructure<PROCESS_BASIC_INFORMATION_64>(ReadMemoryRaw(pbiPtr, (int)pbiSize));

                // 2. PEB lesen (Achtung: pbi.PebBaseAddress ist ulong, wir brauchen IntPtr für ReadMemory)
                IntPtr pebAddress = (IntPtr)pbi.PebBaseAddress;
                byte[] pebBytes = process.ReadMemory(pebAddress, Marshal.SizeOf(typeof(PEB_64_PARTIAL)));
                var peb = ByteArrayToStructure<PEB_64_PARTIAL>(pebBytes);

                if (peb.Ldr == 0) return modules; // Ldr noch nicht initialisiert

                // 3. PEB_LDR_DATA lesen
                IntPtr ldrAddress = (IntPtr)peb.Ldr;
                byte[] ldrBytes = process.ReadMemory(ldrAddress, Marshal.SizeOf(typeof(PEB_LDR_DATA_64)));
                var ldrData = ByteArrayToStructure<PEB_LDR_DATA_64>(ldrBytes);

                // 4. Die Modul-Liste durchlaufen (InLoadOrderModuleList)
                // Wir arbeiten mit ulong Adressen aus den Structs, müssen sie aber zum Lesen in IntPtr wandeln.
                ulong head = ldrData.InLoadOrderModuleList.Flink;
                ulong current = head;

                // Startadresse der Liste berechnen (Offset von InLoadOrderModuleList innerhalb PEB_LDR_DATA)
                // PEB_LDR_DATA_64: Length(4) + Initialized(1) + Padding(3) + SsHandle(8) = 16 Bytes Offset
                ulong listHeadAddress = (ulong)ldrAddress + 16;

                // Sicherheits-Counter gegen Endlosschleifen
                for (int i = 0; i < 2048; i++)
                {
                    if (current == 0 || current == listHeadAddress)
                    {
                        break;
                    }

                    IntPtr entryAddress = (IntPtr)current;

                    // Lese den aktuellen Listeneintrag
                    byte[] entryBytes = process.ReadMemory(entryAddress, Marshal.SizeOf(typeof(LDR_DATA_TABLE_ENTRY_64)));
                    var entry = ByteArrayToStructure<LDR_DATA_TABLE_ENTRY_64>(entryBytes);

                    string baseName = ReadUnicodeString(process, entry.BaseDllName);
                    string fullName = ReadUnicodeString(process, entry.FullDllName);

                    if (!string.IsNullOrEmpty(baseName))
                    {
                        modules.Add(new ProcessModuleInfo
                        {
                            BaseDllName = baseName,
                            FullDllName = fullName,
                            DllBase = (IntPtr)entry.DllBase,
                            SizeOfImage = entry.SizeOfImage,
                            EntryPoint = (IntPtr)entry.EntryPoint
                        });
                    }

                    current = entry.InLoadOrderLinks.Flink;
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
                // WoW64 PEB Adresse holen
                int status = NtQueryInformationProcess(
                    process.Handle,
                    ProcessInformationClass.ProcessWow64Information,
                    peb32AddressPtr,
                    (uint)IntPtr.Size,
                    out _);

                if (status != 0)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "NtQueryInformationProcess(ProcessWow64Information) failed.");
                }

                IntPtr peb32Address = Marshal.ReadIntPtr(peb32AddressPtr);
                if (peb32Address == IntPtr.Zero) return modules;

                // PEB32 lesen
                byte[] pebBytes = process.ReadMemory(peb32Address, Marshal.SizeOf(typeof(PEB_32_PARTIAL)));
                var peb = ByteArrayToStructure<PEB_32_PARTIAL>(pebBytes);

                if (peb.Ldr == 0) return modules;

                // PEB_LDR_DATA32 lesen
                IntPtr ldrAddress = (IntPtr)peb.Ldr;
                byte[] ldrBytes = process.ReadMemory(ldrAddress, Marshal.SizeOf(typeof(PEB_LDR_DATA_32)));
                var ldrData = ByteArrayToStructure<PEB_LDR_DATA_32>(ldrBytes);

                uint head = ldrData.InLoadOrderModuleList.Flink;
                uint current = head;

                // PEB_LDR_DATA_32 Offset: Length(4) + Initialized(1) + Padding(3) + SsHandle(4) = 12 Bytes
                uint listHeadAddress = (uint)ldrAddress + 12;

                for (int i = 0; i < 2048; i++)
                {
                    if (current == 0 || current == listHeadAddress)
                    {
                        break;
                    }

                    IntPtr entryAddress = (IntPtr)current;
                    byte[] entryBytes = process.ReadMemory(entryAddress, Marshal.SizeOf(typeof(LDR_DATA_TABLE_ENTRY_32)));
                    var entry = ByteArrayToStructure<LDR_DATA_TABLE_ENTRY_32>(entryBytes);

                    string baseName = ReadUnicodeString32(process, entry.BaseDllName);
                    string fullName = ReadUnicodeString32(process, entry.FullDllName);

                    if (!string.IsNullOrEmpty(baseName))
                    {
                        modules.Add(new ProcessModuleInfo
                        {
                            BaseDllName = baseName,
                            FullDllName = fullName,
                            DllBase = (IntPtr)entry.DllBase,
                            SizeOfImage = entry.SizeOfImage,
                            EntryPoint = (IntPtr)entry.EntryPoint
                        });
                    }

                    current = entry.InLoadOrderLinks.Flink;
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
            if (us.Length == 0 || us.Buffer == 0)
            {
                return string.Empty;
            }
            // Hier: Cast von ulong Buffer zu IntPtr
            byte[] bytes = process.ReadMemory((IntPtr)us.Buffer, us.Length);
            return Encoding.Unicode.GetString(bytes);
        }

        private static string ReadUnicodeString32(ManagedProcess process, UNICODE_STRING_32 us)
        {
            if (us.Length == 0 || us.Buffer == 0)
            {
                return string.Empty;
            }
            // Hier: Cast von uint Buffer zu IntPtr
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