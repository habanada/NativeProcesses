using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using NativeProcesses.Core.Native;
using NativeProcesses.Core.PE;

namespace NativeProcesses.Core.PE.Loader
{
    public static class RemoteImportResolver
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        public static void ResolveAndWrite(ManagedProcess target, byte[] localImage, IntPtr remoteImageBase, bool is64Bit)
        {
            int e_lfanew = BitConverter.ToInt32(localImage, 0x3C);
            int ntHeader = e_lfanew;
            int optHeader = ntHeader + 4 + 20;

            int importDirOffset = is64Bit ? (optHeader + 112 + 8) : (optHeader + 96 + 8);
            uint importRva = BitConverter.ToUInt32(localImage, importDirOffset);
            uint importSize = BitConverter.ToUInt32(localImage, importDirOffset + 4);

            if (importRva == 0 || importSize == 0) return;

            int descOffset = (int)importRva;
            int ptrSize = is64Bit ? 8 : 4;

            while (true)
            {
                uint originalFirstThunk = BitConverter.ToUInt32(localImage, descOffset);
                uint nameRva = BitConverter.ToUInt32(localImage, descOffset + 12);
                uint firstThunk = BitConverter.ToUInt32(localImage, descOffset + 16);

                if (nameRva == 0 && firstThunk == 0) break;

                string dllName = ReadString(localImage, (int)nameRva);
                if (string.IsNullOrEmpty(dllName))
                {
                    descOffset += 20;
                    continue;
                }

                IntPtr remoteDllBase = EnsureRemoteModuleLoaded(target, dllName);

                uint thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
                uint iatRva = firstThunk;

                int currentThunkOffset = (int)thunkRva;
                int currentIatOffset = (int)iatRva;

                while (true)
                {
                    ulong rawVal = is64Bit
                        ? BitConverter.ToUInt64(localImage, currentThunkOffset)
                        : BitConverter.ToUInt32(localImage, currentThunkOffset);

                    if (rawVal == 0) break;

                    IntPtr funcAddress = IntPtr.Zero;
                    bool isOrdinal = is64Bit
                        ? (rawVal & 0x8000000000000000) != 0
                        : (rawVal & 0x80000000) != 0;

                    if (isOrdinal)
                    {
                        ushort ordinal = (ushort)(rawVal & 0xFFFF);
                        funcAddress = GetRemoteProcAddress(target, remoteDllBase, null, ordinal);
                    }
                    else
                    {
                        int nameStructOffset = (int)(rawVal & 0x7FFFFFFF);
                        if (nameStructOffset + 2 < localImage.Length)
                        {
                            string funcName = ReadString(localImage, nameStructOffset + 2);
                            funcAddress = GetRemoteProcAddress(target, remoteDllBase, funcName, 0);
                        }
                    }

                    if (funcAddress == IntPtr.Zero)
                    {
                        throw new Exception($"Failed to resolve remote import: {dllName}");
                    }

                    IntPtr remoteIatAddress = (IntPtr)((long)remoteImageBase + currentIatOffset);
                    byte[] addressBytes = is64Bit
                        ? BitConverter.GetBytes(funcAddress.ToInt64())
                        : BitConverter.GetBytes(funcAddress.ToInt32());

                    target.WriteMemory(remoteIatAddress, addressBytes);

                    currentThunkOffset += ptrSize;
                    currentIatOffset += ptrSize;
                }

                descOffset += 20;
            }
        }

        private static IntPtr EnsureRemoteModuleLoaded(ManagedProcess target, string dllName)
        {
            var modules = target.GetLoadedModules(null);
            var existing = modules.FirstOrDefault(m => m.BaseDllName.Equals(dllName, StringComparison.OrdinalIgnoreCase));

            if (existing != null) return existing.DllBase;

            IntPtr hKernel32 = GetModuleHandle("kernel32.dll");
            IntPtr pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");

            byte[] pathBytes = Encoding.Unicode.GetBytes(dllName + "\0");
            IntPtr pRemotePath = target.AllocateMemory(pathBytes.Length);
            target.WriteMemory(pRemotePath, pathBytes);

            IntPtr hThread = target.StartRemoteThread(pLoadLibrary, pRemotePath);
            NativeDefinitions.NtWaitForSingleObject(hThread, false, IntPtr.Zero);

            NativeDefinitions.GetExitCodeThread(hThread, out uint exitCode);

            return (IntPtr)exitCode;
        }

        private static IntPtr GetRemoteProcAddress(ManagedProcess target, IntPtr moduleBase, string funcName, ushort ordinal)
        {
            // Wir lesen den Export Table header VOM REMOTE PROZESS
            // Das ist langsam aber korrekt für ASLR/Different Versions.

            byte[] dosHeader = target.ReadMemory(moduleBase, 64);
            int e_lfanew = BitConverter.ToInt32(dosHeader, 0x3C);

            byte[] ntHeader = target.ReadMemory(moduleBase + e_lfanew, 264);
            // Magic check skipped for brevity, assuming structure matches
            // OptionalHeader Offset = 24
            // ExportDir RVA ist in DataDirectory[0]

            // Wir müssen wissen ob Target 64bit ist.
            bool is64 = target.GetIsWow64() == false;
            int exportDirOffset = is64 ? (24 + 112) : (24 + 96);

            uint exportRva = BitConverter.ToUInt32(ntHeader, exportDirOffset);
            if (exportRva == 0) return IntPtr.Zero;

            byte[] exportDirBytes = target.ReadMemory(moduleBase + (int)exportRva, 40); // IMAGE_EXPORT_DIRECTORY size

            uint numberOfNames = BitConverter.ToUInt32(exportDirBytes, 24);
            uint addressOfFunctions = BitConverter.ToUInt32(exportDirBytes, 28);
            uint addressOfNames = BitConverter.ToUInt32(exportDirBytes, 32);
            uint addressOfNameOrdinals = BitConverter.ToUInt32(exportDirBytes, 36);
            uint ordinalBase = BitConverter.ToUInt32(exportDirBytes, 16);

            // Ordinal Lookup
            if (string.IsNullOrEmpty(funcName))
            {
                uint index = ordinal - ordinalBase;
                // Read RVA from AddressOfFunctions table
                byte[] rvaBytes = target.ReadMemory(moduleBase + (int)addressOfFunctions + (int)(index * 4), 4);
                uint funcRva = BitConverter.ToUInt32(rvaBytes, 0);
                return moduleBase + (int)funcRva;
            }

            // Name Lookup (Binary Search wäre besser, hier linear für Simplicity)
            // Wir lesen den ganzen Block von Names RVAs
            byte[] nameRvas = target.ReadMemory(moduleBase + (int)addressOfNames, (int)numberOfNames * 4);

            for (int i = 0; i < numberOfNames; i++)
            {
                uint nameRva = BitConverter.ToUInt32(nameRvas, i * 4);
                // String lesen (langsam!)
                // Optimierung: Puffer lesen
                string currentName = ReadRemoteString(target, moduleBase + (int)nameRva);

                if (currentName.Equals(funcName, StringComparison.Ordinal))
                {
                    // Ordinal Index lesen
                    byte[] ordinalBytes = target.ReadMemory(moduleBase + (int)addressOfNameOrdinals + (i * 2), 2);
                    ushort ordinalIndex = BitConverter.ToUInt16(ordinalBytes, 0);

                    // Function RVA lesen
                    byte[] funcRvaBytes = target.ReadMemory(moduleBase + (int)addressOfFunctions + (int)(ordinalIndex * 4), 4);
                    uint funcRva = BitConverter.ToUInt32(funcRvaBytes, 0);

                    // TODO: Forwarder Check (wenn RVA innerhalb Export Dir liegt)
                    return moduleBase + (int)funcRva;
                }
            }

            return IntPtr.Zero;
        }

        private static string ReadString(byte[] buffer, int offset)
        {
            int end = offset;
            while (end < buffer.Length && buffer[end] != 0) end++;
            return Encoding.ASCII.GetString(buffer, offset, end - offset);
        }

        private static string ReadRemoteString(ManagedProcess target, IntPtr address)
        {
            // Einfache Implementierung, liest max 64 chars
            byte[] buf = target.ReadMemory(address, 64);
            int nullIdx = Array.IndexOf(buf, (byte)0);
            if (nullIdx >= 0) return Encoding.ASCII.GetString(buf, 0, nullIdx);
            return Encoding.ASCII.GetString(buf);
        }
    }
}