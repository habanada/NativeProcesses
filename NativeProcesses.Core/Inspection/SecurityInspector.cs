/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using NativeProcesses.Core.Engine;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;

namespace NativeProcesses.Core.Inspection
{
    public class SecurityInspector
    {
        private IEngineLogger _logger;

        #region P/Invoke Kernel32 (File Access)

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFileW(
            [MarshalAs(UnmanagedType.LPWStr)] string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadFile(
            IntPtr hFile,
            [Out] byte[] lpBuffer,
            uint nNumberOfBytesToRead,
            out uint lpNumberOfBytesRead,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        // Innerhalb der P/Invoke-Region...
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint SetFilePointer(
            IntPtr hFile,
            int lDistanceToMove,
            IntPtr lpDistanceToMoveHigh,
            uint dwMoveMethod); // 0 = FILE_BEGIN

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int SetFilePointerEx(
            IntPtr hFile,
            long liDistanceToMove,
            out long lpNewFilePointer,
            uint dwMoveMethod); // 0 = FILE_BEGIN


        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint OPEN_EXISTING = 3;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        #endregion
        // Fügen Sie diese using-Anweisung ganz oben in der Datei hinzu:

        // Fügen Sie diese Struktur hinzu, um die Ergebnisse zu speichern:
        public class IatHookInfo
        {
            public string ModuleName { get; set; }
            public string FunctionName { get; set; }
            public IntPtr ExpectedAddress { get; set; }
            public IntPtr ActualAddress { get; set; }
            public string TargetModule { get; set; }
        }
        public class InlineHookInfo
        {
            public string ModuleName{ get; set; }
            public string SectionName{ get; set; }
            public long Offset{ get; set; }
            public byte OriginalByte{ get; set; }
            public byte PatchedByte{ get; set; }
            public string HookType{ get; set; }
            public int HookSize{ get; set; }
            public IntPtr TargetAddress{ get; set; } 
            public string TargetModule{ get; set; } 
        }
        public struct SuspiciousThreadInfo
        {
            public int ThreadId{ get; set; }
            public IntPtr StartAddress{ get; set; }
            public string RegionState{ get; set; } // z.B. MEM_PRIVATE
            public string RegionProtection{ get; set; } // z.B. PAGE_EXECUTE_READWRITE
        }
        public struct SuspiciousMemoryRegionInfo
        {
            public IntPtr BaseAddress{ get; set; }
            public long RegionSize{ get; set; }
            public string Type{ get; set; } // z.B. MEM_PRIVATE
            public string Protection{ get; set; } // z.B. PAGE_EXECUTE_READWRITE
        }
        public SecurityInspector(IEngineLogger logger)
        {
            _logger = logger;
        }

        private T ByteArrayToStructure<T>(byte[] bytes, int offset = 0) where T : struct
        {
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                return (T)Marshal.PtrToStructure(IntPtr.Add(handle.AddrOfPinnedObject(), offset), typeof(T));
            }
            finally
            {
                handle.Free();
            }
        }
        //public IntPtr GetExportAddress(Native.ManagedProcess process, IntPtr moduleBase, string functionName)
        //{
        //    try
        //    {
        //        byte[] dosHeaderBytes = process.ReadMemory(moduleBase, Marshal.SizeOf(typeof(PeStructs.IMAGE_DOS_HEADER)));
        //        var dosHeader = ByteArrayToStructure<PeStructs.IMAGE_DOS_HEADER>(dosHeaderBytes);
        //        if (!dosHeader.IsValid)
        //        {
        //            _logger?.Log(LogLevel.Debug, $"SecurityInspector: Invalid DOS header for module at {moduleBase.ToString("X")}.", null);
        //            return IntPtr.Zero;
        //        }

        //        IntPtr ntHeaderAddr = IntPtr.Add(moduleBase, dosHeader.e_lfanew);
        //        byte[] ntHeaderMagicBytes = process.ReadMemory(IntPtr.Add(ntHeaderAddr, 4 + Marshal.SizeOf(typeof(PeStructs.IMAGE_FILE_HEADER))), sizeof(ushort));
        //        ushort magic = BitConverter.ToUInt16(ntHeaderMagicBytes, 0);

        //        PeStructs.IMAGE_DATA_DIRECTORY exportDirectory;

        //        if (magic == PeStructs.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        //        {
        //            byte[] ntHeaderBytes = process.ReadMemory(ntHeaderAddr, Marshal.SizeOf(typeof(PeStructs.IMAGE_NT_HEADERS64)));
        //            var ntHeader = ByteArrayToStructure<PeStructs.IMAGE_NT_HEADERS64>(ntHeaderBytes);
        //            exportDirectory = ntHeader.OptionalHeader.DataDirectory[PeStructs.IMAGE_DIRECTORY_ENTRY_EXPORT];
        //        }
        //        else
        //        {
        //            byte[] ntHeaderBytes = process.ReadMemory(ntHeaderAddr, Marshal.SizeOf(typeof(PeStructs.IMAGE_NT_HEADERS32)));
        //            var ntHeader = ByteArrayToStructure<PeStructs.IMAGE_NT_HEADERS32>(ntHeaderBytes);
        //            exportDirectory = ntHeader.OptionalHeader.DataDirectory[PeStructs.IMAGE_DIRECTORY_ENTRY_EXPORT];
        //        }

        //        if (exportDirectory.VirtualAddress == 0)
        //        {
        //            _logger?.Log(LogLevel.Debug, $"SecurityInspector: Module at {moduleBase.ToString("X")} has no Export Table.", null);
        //            return IntPtr.Zero;
        //        }

        //        IntPtr exportDirAddr = IntPtr.Add(moduleBase, (int)exportDirectory.VirtualAddress);
        //        byte[] exportDirBytes = process.ReadMemory(exportDirAddr, Marshal.SizeOf(typeof(PeStructs.IMAGE_EXPORT_DIRECTORY)));
        //        var eat = ByteArrayToStructure<PeStructs.IMAGE_EXPORT_DIRECTORY>(exportDirBytes);

        //        IntPtr pFunctions = IntPtr.Add(moduleBase, (int)eat.AddressOfFunctions);
        //        IntPtr pNames = IntPtr.Add(moduleBase, (int)eat.AddressOfNames);
        //        IntPtr pOrdinals = IntPtr.Add(moduleBase, (int)eat.AddressOfNameOrdinals);

        //        for (int i = 0; i < eat.NumberOfNames; i++)
        //        {
        //            byte[] nameRvaBytes = process.ReadMemory(IntPtr.Add(pNames, i * sizeof(uint)), sizeof(uint));
        //            uint nameRva = BitConverter.ToUInt32(nameRvaBytes, 0);
        //            string name = ReadNullTerminatedString(process, IntPtr.Add(moduleBase, (int)nameRva));

        //            if (name.Equals(functionName, StringComparison.OrdinalIgnoreCase))
        //            {
        //                byte[] ordinalBytes = process.ReadMemory(IntPtr.Add(pOrdinals, i * sizeof(ushort)), sizeof(ushort));
        //                ushort ordinal = BitConverter.ToUInt16(ordinalBytes, 0);

        //                byte[] functionRvaBytes = process.ReadMemory(IntPtr.Add(pFunctions, ordinal * sizeof(uint)), sizeof(uint));
        //                uint functionRva = BitConverter.ToUInt32(functionRvaBytes, 0);

        //                IntPtr functionAddress = IntPtr.Add(moduleBase, (int)functionRva);

        //                // HIER: Forwarder-Erkennung (Kritikpunkt 4 Ihres Kumpels)
        //                if (functionRva >= exportDirectory.VirtualAddress &&
        //                    functionRva < (exportDirectory.VirtualAddress + exportDirectory.Size))
        //                {
        //                    string forwarderString = ReadNullTerminatedString(process, functionAddress);
        //                    _logger?.Log(LogLevel.Debug, $"SecurityInspector: {functionName} is forwarded to {forwarderString}.", null);
        //                    return IntPtr.Zero; // Wir behandeln Forwarder (vorerst) als "nicht hier"
        //                }

        //                return functionAddress;
        //            }
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        _logger?.Log(LogLevel.Error, $"SecurityInspector.GetExportAddress failed for {functionName}", ex);
        //    }
        //    return IntPtr.Zero;
        //}
        // DIES IST DER NEUE ÖFFENTLICHE WRAPPER
        public IntPtr GetExportAddress(Native.ManagedProcess process,
                                       IntPtr moduleBase,
                                       string functionName,
                                       List<NativeProcesses.Core.Models.ProcessModuleInfo> allModules)
        {
            try
            {
                return ResolveExportAddressInternal(process, moduleBase, functionName, allModules, 0);
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, $"SecurityInspector.GetExportAddress failed for {functionName}", ex);
                return IntPtr.Zero;
            }
        }

        // DIES IST DIE NEUE REKURSIVE KERNLOGIK
        private IntPtr ResolveExportAddressInternal(Native.ManagedProcess process,
                                                    IntPtr moduleBase,
                                                    string functionName,
                                                    List<NativeProcesses.Core.Models.ProcessModuleInfo> allModules,
                                                    int recursionDepth)
        {
            if (recursionDepth > 10) // Schutz vor zirkulären Forwardern
            {
                _logger?.Log(LogLevel.Warning, $"SecurityInspector: Recursion limit hit resolving {functionName}", null);
                return IntPtr.Zero;
            }

            try
            {
                byte[] dosHeaderBytes = process.ReadMemory(moduleBase, Marshal.SizeOf(typeof(PeStructs.IMAGE_DOS_HEADER)));
                var dosHeader = ByteArrayToStructure<PeStructs.IMAGE_DOS_HEADER>(dosHeaderBytes);
                if (!dosHeader.IsValid)
                {
                    return IntPtr.Zero;
                }

                IntPtr ntHeaderAddr = IntPtr.Add(moduleBase, dosHeader.e_lfanew);
                byte[] ntHeaderMagicBytes = process.ReadMemory(IntPtr.Add(ntHeaderAddr, 4 + Marshal.SizeOf(typeof(PeStructs.IMAGE_FILE_HEADER))), sizeof(ushort));
                ushort magic = BitConverter.ToUInt16(ntHeaderMagicBytes, 0);

                PeStructs.IMAGE_DATA_DIRECTORY exportDirectory;

                if (magic == PeStructs.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    byte[] ntHeaderBytes = process.ReadMemory(ntHeaderAddr, Marshal.SizeOf(typeof(PeStructs.IMAGE_NT_HEADERS64)));
                    exportDirectory = ByteArrayToStructure<PeStructs.IMAGE_NT_HEADERS64>(ntHeaderBytes).OptionalHeader.DataDirectory[PeStructs.IMAGE_DIRECTORY_ENTRY_EXPORT];
                }
                else
                {
                    byte[] ntHeaderBytes = process.ReadMemory(ntHeaderAddr, Marshal.SizeOf(typeof(PeStructs.IMAGE_NT_HEADERS32)));
                    exportDirectory = ByteArrayToStructure<PeStructs.IMAGE_NT_HEADERS32>(ntHeaderBytes).OptionalHeader.DataDirectory[PeStructs.IMAGE_DIRECTORY_ENTRY_EXPORT];
                }

                if (exportDirectory.VirtualAddress == 0)
                {
                    return IntPtr.Zero;
                }

                IntPtr exportDirAddr = IntPtr.Add(moduleBase, (int)exportDirectory.VirtualAddress);
                var eat = ByteArrayToStructure<PeStructs.IMAGE_EXPORT_DIRECTORY>(process.ReadMemory(exportDirAddr, Marshal.SizeOf(typeof(PeStructs.IMAGE_EXPORT_DIRECTORY))));

                IntPtr pFunctions = IntPtr.Add(moduleBase, (int)eat.AddressOfFunctions);
                IntPtr pNames = IntPtr.Add(moduleBase, (int)eat.AddressOfNames);
                IntPtr pOrdinals = IntPtr.Add(moduleBase, (int)eat.AddressOfNameOrdinals);

                for (int i = 0; i < eat.NumberOfNames; i++)
                {
                    uint nameRva = BitConverter.ToUInt32(process.ReadMemory(IntPtr.Add(pNames, i * sizeof(uint)), sizeof(uint)), 0);
                    string name = ReadNullTerminatedString(process, IntPtr.Add(moduleBase, (int)nameRva));

                    if (name.Equals(functionName, StringComparison.OrdinalIgnoreCase))
                    {
                        ushort ordinal = BitConverter.ToUInt16(process.ReadMemory(IntPtr.Add(pOrdinals, i * sizeof(ushort)), sizeof(ushort)), 0);
                        uint functionRva = BitConverter.ToUInt32(process.ReadMemory(IntPtr.Add(pFunctions, ordinal * sizeof(uint)), sizeof(uint)), 0);

                        IntPtr functionAddress = IntPtr.Add(moduleBase, (int)functionRva);

                        // HIER IST DIE NEUE FORWARDER-LOGIK (Behebt Schwachstelle A)
                        if (functionRva >= exportDirectory.VirtualAddress &&
                            functionRva < (exportDirectory.VirtualAddress + exportDirectory.Size))
                        {
                            string forwarderString = ReadNullTerminatedString(process, functionAddress);
                            _logger?.Log(LogLevel.Debug, $"SecurityInspector: {functionName} is forwarded to {forwarderString}.", null);

                            string[] parts = forwarderString.Split('.');
                            if (parts.Length != 2)
                            {
                                return IntPtr.Zero; // Ungültiges Forwarder-Format
                            }

                            string forwardModuleName = parts[0] + ".dll";
                            string forwardFunctionName = parts[1];

                            var forwardModule = allModules.FirstOrDefault(m => m.BaseDllName.Equals(forwardModuleName, StringComparison.OrdinalIgnoreCase));
                            if (forwardModule == null)
                            {
                                return IntPtr.Zero; // Forwarder-Modul nicht gefunden
                            }

                            // Rekursiver Aufruf, um die Kette zu verfolgen
                            return ResolveExportAddressInternal(process, forwardModule.DllBase, forwardFunctionName, allModules, recursionDepth + 1);
                        }

                        // Kein Forwarder, das ist die echte Adresse
                        return functionAddress;
                    }
                }
            }
            catch (Exception ex)
            {
                // Fehler in der Rekursion abfangen
                _logger?.Log(LogLevel.Error, $"SecurityInspector.ResolveExportAddressInternal failed for {functionName}", ex);
            }
            return IntPtr.Zero;
        }
        private string ReadNullTerminatedString(Native.ManagedProcess process, IntPtr address)
        {
            var bytes = new System.Collections.Generic.List<byte>();
            int offset = 0;
            byte b;
            do
            {
                b = process.ReadMemory(IntPtr.Add(address, offset), 1)[0];
                if (b != 0)
                    bytes.Add(b);
                offset++;
            } while (b != 0 && offset < 256); // Max 256 Zeichen

            return System.Text.Encoding.ASCII.GetString(bytes.ToArray());
        }
        private byte[] ReadBytesFromFile(string filePath, uint offset, uint bytesToRead)
        {
            IntPtr hFile = IntPtr.Zero;
            try
            {
                hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                if (hFile == INVALID_HANDLE_VALUE)
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), $"CreateFileW failed for {filePath}");
                }

                if (Marshal.SizeOf(typeof(long)) == 8) // 64-bit
                {
                    if (SetFilePointerEx(hFile, (long)offset, out _, 0) == 0) // SEEK_SET = 0
                    {
                        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "SetFilePointerEx failed.");
                    }
                }
                else // 32-bit
                {
                    if (SetFilePointer(hFile, (int)offset, IntPtr.Zero, 0) == 0xFFFFFFFF) // SEEK_SET = 0
                    {
                        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "SetFilePointer failed.");
                    }
                }

                byte[] buffer = new byte[bytesToRead];
                if (!ReadFile(hFile, buffer, bytesToRead, out uint bytesRead, IntPtr.Zero) || bytesRead != bytesToRead)
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "ReadFile failed or did not read expected number of bytes.");
                }
                return buffer;
            }
            finally
            {
                if (hFile != IntPtr.Zero && hFile != INVALID_HANDLE_VALUE)
                {
                    CloseHandle(hFile);
                }
            }
        }

        private PeStructs.IMAGE_SECTION_HEADER[] GetPeHeadersFromFile(string filePath, out PeStructs.IMAGE_DOS_HEADER dosHeader, out PeStructs.IMAGE_FILE_HEADER fileHeader, out ushort magic)
        {
            byte[] buffer = ReadBytesFromFile(filePath, 0, (uint)Marshal.SizeOf(typeof(PeStructs.IMAGE_DOS_HEADER)));
            dosHeader = ByteArrayToStructure<PeStructs.IMAGE_DOS_HEADER>(buffer);
            if (!dosHeader.IsValid)
            {
                throw new Exception($"Invalid DOS header for file {filePath}.");
            }

            buffer = ReadBytesFromFile(filePath, (uint)dosHeader.e_lfanew, sizeof(uint) + (uint)Marshal.SizeOf(typeof(PeStructs.IMAGE_FILE_HEADER)));
            uint ntSignature = BitConverter.ToUInt32(buffer, 0);
            fileHeader = ByteArrayToStructure<PeStructs.IMAGE_FILE_HEADER>(buffer, 4);

            int optionalHeaderOffset = dosHeader.e_lfanew + 4 + Marshal.SizeOf(typeof(PeStructs.IMAGE_FILE_HEADER));
            buffer = ReadBytesFromFile(filePath, (uint)optionalHeaderOffset, sizeof(ushort));
            magic = BitConverter.ToUInt16(buffer, 0);

            int sectionHeaderOffset = optionalHeaderOffset + fileHeader.SizeOfOptionalHeader;
            int sectionHeaderSize = Marshal.SizeOf(typeof(PeStructs.IMAGE_SECTION_HEADER));

            PeStructs.IMAGE_SECTION_HEADER[] sections = new PeStructs.IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            buffer = ReadBytesFromFile(filePath, (uint)sectionHeaderOffset, (uint)(sectionHeaderSize * fileHeader.NumberOfSections));

            for (int i = 0; i < fileHeader.NumberOfSections; i++)
            {
                byte[] sectionBytes = new byte[sectionHeaderSize];
                Array.Copy(buffer, i * sectionHeaderSize, sectionBytes, 0, sectionHeaderSize);
                sections[i] = ByteArrayToStructure<PeStructs.IMAGE_SECTION_HEADER>(sectionBytes);
            }
            return sections;
        }

        private PeStructs.IMAGE_SECTION_HEADER[] GetPeHeadersFromMemory(Native.ManagedProcess process, IntPtr moduleBase, out PeStructs.IMAGE_DOS_HEADER dosHeader, out PeStructs.IMAGE_FILE_HEADER fileHeader, out ushort magic, out PeStructs.IMAGE_DATA_DIRECTORY relocDir)
        {
            byte[] buffer = process.ReadMemory(moduleBase, Marshal.SizeOf(typeof(PeStructs.IMAGE_DOS_HEADER)));
            dosHeader = ByteArrayToStructure<PeStructs.IMAGE_DOS_HEADER>(buffer);
            if (!dosHeader.IsValid)
            {
                throw new Exception($"Invalid DOS header in memory at {moduleBase.ToString("X")}.");
            }

            IntPtr ntHeaderAddr = IntPtr.Add(moduleBase, dosHeader.e_lfanew);
            buffer = process.ReadMemory(ntHeaderAddr, sizeof(uint) + Marshal.SizeOf(typeof(PeStructs.IMAGE_FILE_HEADER)));
            uint ntSignature = BitConverter.ToUInt32(buffer, 0);
            fileHeader = ByteArrayToStructure<PeStructs.IMAGE_FILE_HEADER>(buffer, 4);

            IntPtr optionalHeaderAddr = IntPtr.Add(ntHeaderAddr, 4 + Marshal.SizeOf(typeof(PeStructs.IMAGE_FILE_HEADER)));
            buffer = process.ReadMemory(optionalHeaderAddr, sizeof(ushort));
            magic = BitConverter.ToUInt16(buffer, 0);

            IntPtr sectionHeaderAddr = IntPtr.Add(optionalHeaderAddr, fileHeader.SizeOfOptionalHeader);
            int sectionHeaderSize = Marshal.SizeOf(typeof(PeStructs.IMAGE_SECTION_HEADER));

            PeStructs.IMAGE_SECTION_HEADER[] sections = new PeStructs.IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            buffer = process.ReadMemory(sectionHeaderAddr, sectionHeaderSize * fileHeader.NumberOfSections);

            for (int i = 0; i < fileHeader.NumberOfSections; i++)
            {
                byte[] sectionBytes = new byte[sectionHeaderSize];
                Array.Copy(buffer, i * sectionHeaderSize, sectionBytes, 0, sectionHeaderSize);
                sections[i] = ByteArrayToStructure<PeStructs.IMAGE_SECTION_HEADER>(sectionBytes);
            }
            // ... (Am Ende der GetPeHeadersFromMemory-Methode)

            relocDir = new PeStructs.IMAGE_DATA_DIRECTORY();
            if (magic == PeStructs.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                byte[] optHeaderBytes = process.ReadMemory(optionalHeaderAddr, Marshal.SizeOf<PeStructs.IMAGE_OPTIONAL_HEADER64>());
                var optHeader = ByteArrayToStructure<PeStructs.IMAGE_OPTIONAL_HEADER64>(optHeaderBytes);
                relocDir = optHeader.DataDirectory[PeStructs.IMAGE_DIRECTORY_ENTRY_BASERELOC];
            }
            else
            {
                byte[] optHeaderBytes = process.ReadMemory(optionalHeaderAddr, Marshal.SizeOf<PeStructs.IMAGE_OPTIONAL_HEADER32>());
                var optHeader = ByteArrayToStructure<PeStructs.IMAGE_OPTIONAL_HEADER32>(optHeaderBytes);
                relocDir = optHeader.DataDirectory[PeStructs.IMAGE_DIRECTORY_ENTRY_BASERELOC];
            }

            return sections;
        }
        private HashSet<uint> ParseRelocations(Native.ManagedProcess process, IntPtr moduleBase, PeStructs.IMAGE_DATA_DIRECTORY relocDir, bool isWow64)
        {
            var relocOffsets = new HashSet<uint>();
            if (relocDir.VirtualAddress == 0 || relocDir.Size == 0)
            {
                return relocOffsets;
            }

            try
            {
                IntPtr currentRelocAddr = IntPtr.Add(moduleBase, (int)relocDir.VirtualAddress);
                IntPtr relocEndAddr = IntPtr.Add(currentRelocAddr, (int)relocDir.Size);
                int relocBlockSize = Marshal.SizeOf(typeof(PeStructs.IMAGE_BASE_RELOCATION));

                while (currentRelocAddr.ToInt64() < relocEndAddr.ToInt64())
                {
                    byte[] blockHeaderBytes = process.ReadMemory(currentRelocAddr, relocBlockSize);
                    var relocBlock = ByteArrayToStructure<PeStructs.IMAGE_BASE_RELOCATION>(blockHeaderBytes);

                    if (relocBlock.VirtualAddress == 0 || relocBlock.SizeOfBlock == 0)
                        break;

                    int entryCount = (int)(relocBlock.SizeOfBlock - relocBlockSize) / sizeof(ushort);
                    IntPtr entryAddr = IntPtr.Add(currentRelocAddr, relocBlockSize);
                    byte[] entries = process.ReadMemory(entryAddr, (int)(entryCount * sizeof(ushort)));

                    for (int i = 0; i < entryCount; i++)
                    {
                        ushort entry = BitConverter.ToUInt16(entries, i * sizeof(ushort));
                        ushort type = (ushort)(entry >> 12);
                        uint offset = (uint)(entry & 0x0FFF);

                        // Wir interessieren uns nur für Relocations, die auf 32-bit/64-bit Zeiger abzielen
                        if (type == PeStructs.IMAGE_REL_BASED_DIR64 || type == PeStructs.IMAGE_REL_BASED_HIGHLOW)
                        {
                            uint relocRva = relocBlock.VirtualAddress + offset;
                            relocOffsets.Add(relocRva);

                            // Ein Zeiger ist 4 (HIGHLOW) oder 8 (DIR64) Bytes groß.
                            // Wir müssen alle Bytes dieses Zeigers zur Skip-Liste hinzufügen.
                            int ptrSize = (type == PeStructs.IMAGE_REL_BASED_DIR64) ? 8 : 4;
                            for (int p = 1; p < ptrSize; p++)
                            {
                                relocOffsets.Add(relocRva + (uint)p);
                            }
                        }
                    }
                    currentRelocAddr = IntPtr.Add(currentRelocAddr, (int)relocBlock.SizeOfBlock);
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, "SecurityInspector.ParseRelocations failed.", ex);
            }
            return relocOffsets;
        }
        // DIESE METHODE FEHLT IN DEINER SecurityInspector.cs
        public Dictionary<string, IntPtr> BuildExportMap(Native.ManagedProcess process, IntPtr moduleBase)
        {
            var exportMap = new Dictionary<string, IntPtr>(StringComparer.OrdinalIgnoreCase);
            try
            {
                byte[] dosHeaderBytes = process.ReadMemory(moduleBase, Marshal.SizeOf(typeof(PeStructs.IMAGE_DOS_HEADER)));
                var dosHeader = ByteArrayToStructure<PeStructs.IMAGE_DOS_HEADER>(dosHeaderBytes);
                if (!dosHeader.IsValid) return exportMap;

                IntPtr ntHeaderAddr = IntPtr.Add(moduleBase, dosHeader.e_lfanew);
                byte[] ntHeaderMagicBytes = process.ReadMemory(IntPtr.Add(ntHeaderAddr, 4 + Marshal.SizeOf(typeof(PeStructs.IMAGE_FILE_HEADER))), sizeof(ushort));
                ushort magic = BitConverter.ToUInt16(ntHeaderMagicBytes, 0);

                PeStructs.IMAGE_DATA_DIRECTORY exportDirectory;
                if (magic == PeStructs.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    byte[] ntHeaderBytes = process.ReadMemory(ntHeaderAddr, Marshal.SizeOf(typeof(PeStructs.IMAGE_NT_HEADERS64)));
                    exportDirectory = ByteArrayToStructure<PeStructs.IMAGE_NT_HEADERS64>(ntHeaderBytes).OptionalHeader.DataDirectory[PeStructs.IMAGE_DIRECTORY_ENTRY_EXPORT];
                }
                else
                {
                    byte[] ntHeaderBytes = process.ReadMemory(ntHeaderAddr, Marshal.SizeOf(typeof(PeStructs.IMAGE_NT_HEADERS32)));
                    exportDirectory = ByteArrayToStructure<PeStructs.IMAGE_NT_HEADERS32>(ntHeaderBytes).OptionalHeader.DataDirectory[PeStructs.IMAGE_DIRECTORY_ENTRY_EXPORT];
                }

                if (exportDirectory.VirtualAddress == 0) return exportMap;

                IntPtr exportDirAddr = IntPtr.Add(moduleBase, (int)exportDirectory.VirtualAddress);
                var eat = ByteArrayToStructure<PeStructs.IMAGE_EXPORT_DIRECTORY>(process.ReadMemory(exportDirAddr, Marshal.SizeOf(typeof(PeStructs.IMAGE_EXPORT_DIRECTORY))));

                IntPtr pFunctions = IntPtr.Add(moduleBase, (int)eat.AddressOfFunctions);
                IntPtr pNames = IntPtr.Add(moduleBase, (int)eat.AddressOfNames);
                IntPtr pOrdinals = IntPtr.Add(moduleBase, (int)eat.AddressOfNameOrdinals);

                // Performance: Buffer lesen statt Einzelzugriffe
                byte[] nameRvaBuffer = process.ReadMemory(pNames, (int)eat.NumberOfNames * 4);
                byte[] ordinalBuffer = process.ReadMemory(pOrdinals, (int)eat.NumberOfNames * 2);

                for (int i = 0; i < eat.NumberOfNames; i++)
                {
                    uint nameRva = BitConverter.ToUInt32(nameRvaBuffer, i * 4);
                    string name = ReadNullTerminatedString(process, IntPtr.Add(moduleBase, (int)nameRva));

                    ushort ordinal = BitConverter.ToUInt16(ordinalBuffer, i * 2);

                    byte[] funcRvaBytes = process.ReadMemory(IntPtr.Add(pFunctions, ordinal * 4), 4);
                    uint functionRva = BitConverter.ToUInt32(funcRvaBytes, 0);

                    // Forwarder-Check:
                    if (functionRva >= exportDirectory.VirtualAddress &&
                        functionRva < (exportDirectory.VirtualAddress + exportDirectory.Size))
                    {
                        continue; // Forwarder ignorieren wir für den Map-Build
                    }

                    IntPtr functionAddress = IntPtr.Add(moduleBase, (int)functionRva);

                    if (!string.IsNullOrEmpty(name) && !exportMap.ContainsKey(name))
                    {
                        exportMap[name] = functionAddress;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, "BuildExportMap failed.", ex);
            }
            return exportMap;
        }
        private PeStructs.IMAGE_SECTION_HEADER FindSection(PeStructs.IMAGE_SECTION_HEADER[] sections, string sectionName)
        {
            foreach (var section in sections)
            {
                if (section.Name.Equals(sectionName, StringComparison.OrdinalIgnoreCase))
                {
                    return section;
                }
            }
            throw new Exception($"Section '{sectionName}' not found.");
        }
        public List<IatHookInfo> CheckIatHooks(Native.ManagedProcess process,
                                                      IntPtr moduleToScanBase,
                                                      string moduleToScanName,
                                                      Dictionary<string, IntPtr> ntdllExports,
                                                      List<NativeProcesses.Core.Models.ProcessModuleInfo> allModules,
                                                      List<NativeProcesses.Core.Models.VirtualMemoryRegion> regions)
        {
            var results = new List<IatHookInfo>();
            bool isWow64 = process.GetIsWow64();

            // HASHEREZADE OPTIMIERUNG: Module Bounds Cache erstellen
            // Wir mappen "dllname.dll" -> (Start, Ende) für O(1) Range Checks.
            var moduleBounds = new Dictionary<string, Tuple<long, long>>(StringComparer.OrdinalIgnoreCase);
            foreach (var mod in allModules)
            {
                if (!moduleBounds.ContainsKey(mod.BaseDllName))
                {
                    long start = mod.DllBase.ToInt64();
                    long end = start + mod.SizeOfImage;
                    moduleBounds[mod.BaseDllName] = new Tuple<long, long>(start, end);
                }
            }

            try
            {
                byte[] dosHeaderBytes = process.ReadMemory(moduleToScanBase, Marshal.SizeOf(typeof(PeStructs.IMAGE_DOS_HEADER)));
                var dosHeader = ByteArrayToStructure<PeStructs.IMAGE_DOS_HEADER>(dosHeaderBytes);
                if (!dosHeader.IsValid) return results;

                IntPtr ntHeaderAddr = IntPtr.Add(moduleToScanBase, dosHeader.e_lfanew);
                byte[] ntHeaderMagicBytes = process.ReadMemory(IntPtr.Add(ntHeaderAddr, 4 + Marshal.SizeOf(typeof(PeStructs.IMAGE_FILE_HEADER))), sizeof(ushort));
                ushort magic = BitConverter.ToUInt16(ntHeaderMagicBytes, 0);

                PeStructs.IMAGE_DATA_DIRECTORY importDirectory;
                if (magic == PeStructs.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    byte[] ntHeaderBytes = process.ReadMemory(ntHeaderAddr, Marshal.SizeOf(typeof(PeStructs.IMAGE_NT_HEADERS64)));
                    importDirectory = ByteArrayToStructure<PeStructs.IMAGE_NT_HEADERS64>(ntHeaderBytes).OptionalHeader.DataDirectory[PeStructs.IMAGE_DIRECTORY_ENTRY_IMPORT];
                }
                else
                {
                    byte[] ntHeaderBytes = process.ReadMemory(ntHeaderAddr, Marshal.SizeOf(typeof(PeStructs.IMAGE_NT_HEADERS32)));
                    importDirectory = ByteArrayToStructure<PeStructs.IMAGE_NT_HEADERS32>(ntHeaderBytes).OptionalHeader.DataDirectory[PeStructs.IMAGE_DIRECTORY_ENTRY_IMPORT];
                }

                if (importDirectory.VirtualAddress == 0) return results;

                IntPtr importDescAddr = IntPtr.Add(moduleToScanBase, (int)importDirectory.VirtualAddress);
                int importDescSize = Marshal.SizeOf(typeof(PeStructs.IMAGE_IMPORT_DESCRIPTOR));

                for (int descIndex = 0; descIndex < 500; descIndex++) // Safety limit
                {
                    byte[] importDescBytes = process.ReadMemory(IntPtr.Add(importDescAddr, descIndex * importDescSize), importDescSize);
                    var importDesc = ByteArrayToStructure<PeStructs.IMAGE_IMPORT_DESCRIPTOR>(importDescBytes);

                    if (importDesc.Name == 0 && importDesc.FirstThunk == 0) break;

                    string importedDllName = ReadNullTerminatedString(process, IntPtr.Add(moduleToScanBase, (int)importDesc.Name));

                    // OPTIMIERUNG 1: Wir holen uns direkt die Grenzen der importierten DLL
                    long validStart = 0;
                    long validEnd = 0;
                    bool limitsFound = false;

                    if (moduleBounds.TryGetValue(importedDllName, out var bounds))
                    {
                        validStart = bounds.Item1;
                        validEnd = bounds.Item2;
                        limitsFound = true;
                    }

                    uint originalFirstThunkRva = importDesc.OriginalFirstThunk == 0 ? importDesc.FirstThunk : importDesc.OriginalFirstThunk;
                    IntPtr iatAddress = IntPtr.Add(moduleToScanBase, (int)importDesc.FirstThunk);

                    // Wir lesen die ganze IAT-Tabelle für diese DLL am Stück (Bulk Read), statt Eintrag für Eintrag.
                    // Annahme: Max 1000 Funktionen pro DLL -> 8000 Bytes (x64).
                    int maxEntries = 1000;
                    int ptrSize = isWow64 ? 4 : 8;
                    byte[] iatBlock = process.ReadMemory(iatAddress, maxEntries * ptrSize);

                    for (int thunkIndex = 0; thunkIndex < maxEntries; thunkIndex++)
                    {
                        ulong thunkValue;
                        if (isWow64)
                            thunkValue = BitConverter.ToUInt32(iatBlock, thunkIndex * 4);
                        else
                            thunkValue = BitConverter.ToUInt64(iatBlock, thunkIndex * 8);

                        if (thunkValue == 0) break; // Ende der Tabelle

                        IntPtr actualAddressInIat = (IntPtr)thunkValue;
                        long addrVal = actualAddressInIat.ToInt64();

                        // --- HASHEREZADE CHECK ---
                        // Liegt die Adresse im Bereich der importierten DLL?
                        if (limitsFound)
                        {
                            if (addrVal >= validStart && addrVal < validEnd)
                            {
                                // JA: Adresse zeigt in die korrekte DLL. Das ist zu 99.9% legitim.
                                // Wir überspringen den teuren Namens-Lookup!
                                continue;
                            }
                        }

                        // --- ANOMALIE GEFUNDEN ---
                        // Die Adresse liegt NICHT in der Ziel-DLL.
                        // Das kann zwei Gründe haben:
                        // 1. Es ist ein "Forwarder" (z.B. Kernel32 leitet an Ntdll weiter). Legitim.
                        // 2. Es ist ein Hook (Shellcode oder fremde DLL). Malicious.

                        // JETZT machen wir den teuren Lookup, um zu sehen was es ist.
                        string functionName = GetImportName(process, moduleToScanBase, originalFirstThunkRva, thunkIndex, isWow64);
                        if (functionName.StartsWith("Ordinal") || functionName == "[Error]") continue;

                        // Spezialfall NTDLL: Die haben wir gecached.
                        if (importedDllName.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase))
                        {
                            if (ntdllExports.TryGetValue(functionName, out IntPtr expectedAddress))
                            {
                                if (actualAddressInIat != expectedAddress)
                                {
                                    string targetModule = AttributeAddress(actualAddressInIat, allModules, regions);
                                    results.Add(new IatHookInfo
                                    {
                                        ModuleName = moduleToScanName,
                                        FunctionName = functionName,
                                        ExpectedAddress = expectedAddress,
                                        ActualAddress = actualAddressInIat,
                                        TargetModule = targetModule
                                    });
                                }
                            }
                            continue;
                        }

                        // Für andere DLLs (z.B. Kernel32 Forwarders):
                        // Wir prüfen, ob die Adresse zumindest in IRGENDEINER bekannten DLL liegt.
                        string targetModName = AttributeAddress(actualAddressInIat, allModules, regions);

                        if (targetModName.StartsWith("PRIVATE_MEMORY") || targetModName == "UNKNOWN_REGION")
                        {
                            // TREFFER! Adresse zeigt auf Heap/Stack/Unbekannt -> HOOK!
                            results.Add(new IatHookInfo
                            {
                                ModuleName = moduleToScanName,
                                FunctionName = $"{importedDllName}!{functionName}", // Zeige Herkunft
                                ExpectedAddress = IntPtr.Zero, // Unbekannt ohne EAT Parsing
                                ActualAddress = actualAddressInIat,
                                TargetModule = targetModName
                            });
                        }
                        // Falls es auf ein anderes Modul zeigt (z.B. ntdll), ist es wahrscheinlich ein Forwarder.
                        // Wir ignorieren das hier aus Performance-Gründen, da legitime Forwarders sehr häufig sind.
                    }
                }
            }
            catch (Exception ex)
            {
                // _logger?.Log(LogLevel.Error, $"CheckIatHooks error {moduleToScanName}", ex);
            }
            return results;
        }
        public List<InlineHookInfo> CheckForInlineHooks(Native.ManagedProcess process,
                                                                IntPtr moduleBase,
                                                                string modulePath,
                                                                List<NativeProcesses.Core.Models.ProcessModuleInfo> modules,
                                                                List<NativeProcesses.Core.Models.VirtualMemoryRegion> regions)
        {
            var results = new List<InlineHookInfo>();
            bool firstHookLogged = false;
            try
            {
                var memSections = GetPeHeadersFromMemory(process, moduleBase, out _, out _, out ushort magic, out PeStructs.IMAGE_DATA_DIRECTORY memRelocDir);
                bool isWow64 = (magic == PeStructs.IMAGE_NT_OPTIONAL_HDR32_MAGIC);

                HashSet<uint> relocOffsets = ParseRelocations(process, moduleBase, memRelocDir, isWow64);

                var fileSections = GetPeHeadersFromFile(modulePath, out _, out _, out _);

                var fileTextSection = FindSection(fileSections, ".text");
                var memTextSection = FindSection(memSections, ".text");

                if (fileTextSection.SizeOfRawData == 0 || memTextSection.VirtualSize == 0)
                {
                    return results;
                }

                uint sizeToCompare = Math.Min(fileTextSection.SizeOfRawData, memTextSection.VirtualSize);
                byte[] fileBytes = ReadBytesFromFile(modulePath, fileTextSection.PointerToRawData, sizeToCompare);
                byte[] memBytes = process.ReadMemory(IntPtr.Add(moduleBase, (int)memTextSection.VirtualAddress), (int)sizeToCompare);

                for (int i = 0; i < sizeToCompare; i++)
                {
                    uint currentRva = memTextSection.VirtualAddress + (uint)i;

                    if (relocOffsets.Contains(currentRva))
                    {
                        continue;
                    }

                    if (fileBytes[i] != memBytes[i])
                    {
                        // HOOK GEFUNDEN! Jetzt analysieren
                        var hookInfo = AnalyzeHook(process, memBytes, i, IntPtr.Add(moduleBase, (int)currentRva), isWow64);
                        if (hookInfo != null)
                        {
                            hookInfo.ModuleName = System.IO.Path.GetFileName(modulePath);
                            hookInfo.SectionName = ".text";
                            hookInfo.Offset = i;

                            hookInfo.TargetModule = AttributeAddress(hookInfo.TargetAddress, modules, regions);

                            results.Add(hookInfo);

                            if (!firstHookLogged)
                            {
                                _logger?.Log(LogLevel.Warning, $"SecurityInspector: HOOK DETECTED! Type: {hookInfo.HookType} in {modulePath} at .text + 0x{i.ToString("X")}. Target: {hookInfo.TargetModule}", null);
                                firstHookLogged = true;
                            }

                            // Zum nächsten Byte *nach* dem Hook springen
                            i += (hookInfo.HookSize - 1);
                        }
                    }
                }

                if (results.Count > 1 && firstHookLogged)
                {
                    _logger?.Log(LogLevel.Warning, $"SecurityInspector: Full scan complete. Found {results.Count} total hooks in {modulePath} .text section.", null);
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, $"SecurityInspector.CheckForInlineHooks failed for {modulePath}", ex);
            }
            return results;
        }
        private InlineHookInfo AnalyzeHook(Native.ManagedProcess process, byte[] memBytes, int offset, IntPtr patchAddress, bool isWow64)
        {
            if (offset >= memBytes.Length)
            {
                return null;
            }

            byte op = memBytes[offset];

            try
            {
                // --- JMP rel32 (Relativer Sprung) ---
                if (op == 0xE9 && offset + 4 < memBytes.Length)
                {
                    int relativeOffset = BitConverter.ToInt32(memBytes, offset + 1);
                    IntPtr targetAddress = IntPtr.Add(patchAddress, 5 + relativeOffset);
                    return new InlineHookInfo
                    {
                        HookType = "JMP_REL32",
                        HookSize = 5,
                        TargetAddress = targetAddress
                    };
                }

                // --- PUSH addr / RET (Klassischer 32-Bit-Hook) ---
                if (isWow64 && op == 0x68 && offset + 5 < memBytes.Length && memBytes[offset + 5] == 0xC3)
                {
                    uint targetAddress32 = BitConverter.ToUInt32(memBytes, offset + 1);
                    return new InlineHookInfo
                    {
                        HookType = "PUSH_RET_32",
                        HookSize = 6,
                        TargetAddress = (IntPtr)targetAddress32
                    };
                }

                // --- JMP [addr] (Absoluter Sprung / 64-Bit RIP-Relativ) ---
                if (op == 0xFF && offset + 5 < memBytes.Length && memBytes[offset + 1] == 0x25)
                {
                    int relativeOffset = BitConverter.ToInt32(memBytes, offset + 2);
                    IntPtr pointerAddress;
                    if (isWow64)
                    {
                        pointerAddress = (IntPtr)relativeOffset;
                    }
                    else
                    {
                        pointerAddress = IntPtr.Add(patchAddress, 6 + relativeOffset);
                    }

                    IntPtr targetAddress = ReadIntPtr(process, pointerAddress, isWow64);

                    return new InlineHookInfo
                    {
                        HookType = isWow64 ? "JMP_ABS_32" : "JMP_RIP_REL_64",
                        HookSize = 6,
                        TargetAddress = targetAddress
                    };
                }

                // --- MOV RAX, [addr] / JMP RAX (64-Bit-Trampolin) ---
                if (!isWow64 && op == 0x48 && offset + 11 < memBytes.Length && memBytes[offset + 1] == 0xB8)
                {
                    if (memBytes[offset + 10] == 0xFF && memBytes[offset + 11] == 0xE0)
                    {
                        long targetAddress64 = BitConverter.ToInt64(memBytes, offset + 2);
                        return new InlineHookInfo
                        {
                            HookType = "MOV_RAX_JMP_RAX_64",
                            HookSize = 12,
                            TargetAddress = (IntPtr)targetAddress64
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, "SecurityInspector.AnalyzeHook failed", ex);
                return null;
            }

            // Konnte nicht als bekannter Hook-Typ identifiziert werden
            // Wir geben einen gültigen Typ zurück, damit wir ihn überspringen können
            return new InlineHookInfo
            {
                HookType = "UNKNOWN_PATCH",
                HookSize = 1,
                TargetAddress = IntPtr.Zero
            };
        }
        private string AttributeAddress(IntPtr targetAddress,
                                        List<NativeProcesses.Core.Models.ProcessModuleInfo> modules,
                                        List<NativeProcesses.Core.Models.VirtualMemoryRegion> regions)
        {
            if (targetAddress == IntPtr.Zero)
            {
                return "N/A";
            }

            long target = targetAddress.ToInt64();

            // 1. Landet es in einem geladenen Modul? (Legitim / EDR)
            foreach (var mod in modules)
            {
                if (mod.DllBase == IntPtr.Zero || mod.SizeOfImage == 0) continue;
                long start = mod.DllBase.ToInt64();
                long end = start + mod.SizeOfImage;

                if (target >= start && target < end)
                {
                    return mod.BaseDllName;
                }
            }

            // 2. Landet es in privatem Speicher? (Shellcode!)
            foreach (var region in regions)
            {
                long regionStart = region.BaseAddress.ToInt64();
                long regionEnd = regionStart + region.RegionSize;

                if (target >= regionStart && target < regionEnd)
                {
                    return $"PRIVATE_MEMORY ({region.Type} / {region.Protection})";
                }
            }

            return "UNKNOWN_REGION";
        }
        public List<InlineHookInfo> CheckForInlineHooksFirstFoundBreak(Native.ManagedProcess process, IntPtr moduleBase, string modulePath)
        {
            var results = new List<InlineHookInfo>();
            try
            {
                // 1. Hole Header und Relocation-Informationen aus dem Speicher
                var memSections = GetPeHeadersFromMemory(process, moduleBase, out _, out _, out ushort magic, out PeStructs.IMAGE_DATA_DIRECTORY memRelocDir);
                bool isWow64 = (magic == PeStructs.IMAGE_NT_OPTIONAL_HDR32_MAGIC);

                // 2. Parse die Relocation-Liste aus dem Speicher
                HashSet<uint> relocOffsets = ParseRelocations(process, moduleBase, memRelocDir, isWow64);

                // 3. Hole Header aus der Datei
                var fileSections = GetPeHeadersFromFile(modulePath, out _, out _, out _);

                var fileTextSection = FindSection(fileSections, ".text");
                var memTextSection = FindSection(memSections, ".text");

                if (fileTextSection.SizeOfRawData == 0 || memTextSection.VirtualSize == 0)
                {
                    return results;
                }

                uint sizeToCompare = Math.Min(fileTextSection.SizeOfRawData, memTextSection.VirtualSize);

                // 4. Lese beide .text-Sektionen 
                byte[] fileBytes = ReadBytesFromFile(modulePath, fileTextSection.PointerToRawData, sizeToCompare);
                byte[] memBytes = process.ReadMemory(IntPtr.Add(moduleBase, (int)memTextSection.VirtualAddress), (int)sizeToCompare);

                // 5. Vergleiche Byte für Byte (MIT RELOCATION-CHECK)
                for (int i = 0; i < sizeToCompare; i++)
                {
                    uint currentRva = memTextSection.VirtualAddress + (uint)i;

                    // HIER IST DER NEUE SCHRITT:
                    // Wenn diese Adresse vom Loader gepatcht wurde, überspringe den Vergleich.
                    if (relocOffsets.Contains(currentRva))
                    {
                        continue;
                    }

                    if (fileBytes[i] != memBytes[i])
                    {
                        results.Add(new InlineHookInfo
                        {
                            ModuleName = System.IO.Path.GetFileName(modulePath),
                            SectionName = ".text",
                            Offset = i,
                            OriginalByte = fileBytes[i],
                            PatchedByte = memBytes[i]
                        });

                        _logger?.Log(LogLevel.Warning, $"SecurityInspector: HOOK DETECTED! Mismatch in {modulePath} at .text + 0x{i.ToString("X")}.", null);
                        return results;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, $"SecurityInspector.CheckForInlineHooks failed for {modulePath}", ex);
            }
            return results;
        }
        public List<SuspiciousThreadInfo> CheckForSuspiciousThreads(
            List<NativeProcesses.Core.ThreadInfo> threads,
            List<NativeProcesses.Core.Models.ProcessModuleInfo> modules,
            List<NativeProcesses.Core.Models.VirtualMemoryRegion> regions)
        {
            var results = new List<SuspiciousThreadInfo>();
            var legitModuleRanges = new List<Tuple<long, long>>();

            foreach (var mod in modules)
            {
                if (mod.DllBase == IntPtr.Zero || mod.SizeOfImage == 0) continue;
                legitModuleRanges.Add(new Tuple<long, long>(mod.DllBase.ToInt64(), mod.DllBase.ToInt64() + mod.SizeOfImage));
            }

            foreach (var thread in threads)
            {
                if (thread.StartAddress == IntPtr.Zero) continue;

                long threadStart = thread.StartAddress.ToInt64();
                bool isInModule = false;

                // 1. Prüfen, ob der Thread-Start in einer legitimen DLL/EXE liegt (MEM_IMAGE)
                foreach (var range in legitModuleRanges)
                {
                    if (threadStart >= range.Item1 && threadStart < range.Item2)
                    {
                        isInModule = true;
                        break;
                    }
                }

                if (isInModule)
                {
                    continue; // Dieser Thread ist sauber (startet in einem Modul)
                }

                // 2. Thread startet NICHT in einem Modul. Prüfe die Speicherregion.
                foreach (var region in regions)
                {
                    long regionStart = region.BaseAddress.ToInt64();
                    long regionEnd = regionStart + region.RegionSize;

                    if (threadStart >= regionStart && threadStart < regionEnd)
                    {
                        // Wir haben die Region gefunden. Ist sie verdächtig?
                        if (region.State == "Commit" && // MEM_COMMIT
                            (region.Type == "Private" || region.Type == "Mapped") && // MEM_PRIVATE oder MEM_MAPPED (nicht MEM_IMAGE)
                            (region.Protection.Contains("EXECUTE"))) // PAGE_EXECUTE...
                        {
                            results.Add(new SuspiciousThreadInfo
                            {
                                ThreadId = thread.ThreadId,
                                StartAddress = thread.StartAddress,
                                RegionState = region.Type,
                                RegionProtection = region.Protection
                            });
                        }
                        break;
                    }
                }
            }
            return results;
        }

        public List<SuspiciousMemoryRegionInfo> CheckForSuspiciousMemoryRegions(List<NativeProcesses.Core.Models.VirtualMemoryRegion> regions)
        {
            var results = new List<SuspiciousMemoryRegionInfo>();

            try
            {
                // Der "klassische" Shellcode-Indikator:
                // Speicher, der COMMITTED und PRIVATE ist, aber EXECUTE-Rechte hat.
                // Legitime JIT-Compiler (wie .NET) tun dies, aber es ist dennoch
                // ein starkes Anzeichen für eine Injektion.
                var suspiciousRegions = regions
                    .Where(r => r.State == "Commit" &&
                                r.Type == "Private" &&
                                r.Protection.Contains("EXECUTE"))
                    .ToList();

                foreach (var region in suspiciousRegions)
                {
                    results.Add(new SuspiciousMemoryRegionInfo
                    {
                        BaseAddress = region.BaseAddress,
                        RegionSize = region.RegionSize,
                        Type = region.Type,
                        Protection = region.Protection
                    });
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, "SecurityInspector.CheckForSuspiciousMemoryRegions failed.", ex);
            }
            return results;
        }
        public List<FoundPeHeaderInfo> CheckDataRegionsForPeHeaders(Native.ManagedProcess process, List<NativeProcesses.Core.Models.VirtualMemoryRegion> regions)
        {
            var results = new List<FoundPeHeaderInfo>();

            try
            {
                // Wir scannen NUR private, committete Regionen.
                // MEM_IMAGE  (legitime DLLs) und MEM_MAPPED (Speicher-Dateien) werden ignoriert.
                var privateRegions = regions
                    .Where(r => r.State == "Commit" &&
                                r.Type == "Private")
                    .ToList();

                foreach (var region in privateRegions)
                {
                    // Wir müssen nicht die ganze Region lesen (kann GB groß sein).
                    // Ein PE-Header muss am Anfang (Offset 0) der Region liegen.
                    // Wir lesen die ersten 4096 Bytes (4KB), das reicht für alle Header.
                    int bytesToRead = (int)Math.Min(region.RegionSize, 4096);
                    if (bytesToRead < 1024) // Weniger als 1KB ist unwahrscheinlich für ein PE
                    {
                        continue;
                    }

                    byte[] buffer;
                    try
                    {
                        buffer = process.ReadMemory(region.BaseAddress, bytesToRead);
                    }
                    catch (Exception)
                    {
                        continue; // Lesefehler (z.B. Konkurrenzsituation), Region überspringen
                    }

                    // 1. Suche nach "MZ"-Signatur  am Anfang
                    if (buffer[0] != 0x4D || buffer[1] != 0x5A) // 'M' 'Z'
                    {
                        continue;
                    }

                    // 2. Finde den "e_lfanew"  (Offset zum PE-Header)
                    int e_lfanew = BitConverter.ToInt32(buffer, 0x3C);
                    if (e_lfanew + 4 > buffer.Length)
                    {
                        continue; // PE-Header liegt außerhalb unseres gelesenen Puffers
                    }

                    // 3. Suche nach "PE\0\0"-Signatur 
                    if (buffer[e_lfanew] == 0x50 && buffer[e_lfanew + 1] == 0x45 &&
                        buffer[e_lfanew + 2] == 0x00 && buffer[e_lfanew + 3] == 0x00)
                    {
                        // FUND! Ein PE-Header liegt im privaten Speicher .
                        results.Add(new FoundPeHeaderInfo
                        {
                            BaseAddress = region.BaseAddress,
                            RegionSize = region.RegionSize,
                            RegionType = region.Type,
                            RegionProtection = region.Protection,
                            Status = $"PE Header found at offset 0 (RW/R-Only Memory)"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, "SecurityInspector.CheckDataRegionsForPeHeaders failed.", ex);
            }
            return results;
        }

        private IntPtr ReadIntPtr(Native.ManagedProcess process, IntPtr address, bool isWow64)
        {
            int ptrSize = isWow64 ? 4 : 8;
            byte[] bytes = process.ReadMemory(address, ptrSize);
            return isWow64 ? (IntPtr)BitConverter.ToInt32(bytes, 0) : (IntPtr)BitConverter.ToInt64(bytes, 0);
        }

        private ulong ReadUIntPtr(Native.ManagedProcess process, IntPtr address, bool isWow64)
        {
            int ptrSize = isWow64 ? 4 : 8;
            byte[] bytes = process.ReadMemory(address, ptrSize);
            return isWow64 ? (ulong)BitConverter.ToUInt32(bytes, 0) : (ulong)BitConverter.ToUInt64(bytes, 0);
        }

        private string GetImportName(Native.ManagedProcess process, IntPtr moduleBase, uint originalFirstThunkRva, int thunkIndex, bool isWow64)
        {
            try
            {
                int ptrSize = isWow64 ? 4 : 8;

                // 1. Finde die Adresse des Eintrags in der Namens-Tabelle (OriginalFirstThunk)
                IntPtr nameThunkAddr = IntPtr.Add(moduleBase, (int)originalFirstThunkRva + (thunkIndex * ptrSize));

                // 2. Lese die RVA (den Verweis) auf die IMAGE_IMPORT_BY_NAME-Struktur
                ulong nameRva = ReadUIntPtr(process, nameThunkAddr, isWow64);

                // 3. Prüfe auf Ordinal-Import (Bit 63 oder 31 ist gesetzt)
                if ((nameRva & (isWow64 ? 0x8000000000000000 : 0x80000000)) != 0)
                {
                    return $"Ordinal {nameRva & 0xFFFF}";
                }

                // 4. Lese den Namen aus der IMAGE_IMPORT_BY_NAME-Struktur (RVA + 2 Bytes für das 'Hint'-Feld)
                IntPtr nameAddr = IntPtr.Add(moduleBase, (int)nameRva + 2);
                return ReadNullTerminatedString(process, nameAddr);
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, $"GetImportName failed for thunk index {thunkIndex}", ex);
                return "[Error]";
            }
        }


    }
    public class HookDetectionResult
    {
        public int ProcessId { get; internal set; }
        public List<SecurityInspector.IatHookInfo> IatHooks { get; internal set; }
        public List<SecurityInspector.InlineHookInfo> InlineHooks { get; internal set; }
        public List<SecurityInspector.SuspiciousThreadInfo> SuspiciousThreads { get; internal set; }
        public List<SecurityInspector.SuspiciousMemoryRegionInfo> SuspiciousMemoryRegions { get; internal set; }
        public List<FoundPeHeaderInfo> FoundPeHeaders { get; internal set; } 
        public List<string> Errors { get; internal set; }
        public List<PeAnomalyInfo> Anomalies { get; internal set; }

        public bool IsHooked
        {
            get { return (IatHooks.Count > 0) || (InlineHooks.Count > 0) || (SuspiciousThreads.Count > 0) || (SuspiciousMemoryRegions.Count > 0) || (FoundPeHeaders.Count > 0) ||
                       (Anomalies.Count > 0);  } 
            }

        internal HookDetectionResult(int pid)
        {
            ProcessId = pid;
            IatHooks = new List<SecurityInspector.IatHookInfo>();
            InlineHooks = new List<SecurityInspector.InlineHookInfo>();
            SuspiciousThreads = new List<SecurityInspector.SuspiciousThreadInfo>();
            SuspiciousMemoryRegions = new List<SecurityInspector.SuspiciousMemoryRegionInfo>();
            Anomalies = new List<PeAnomalyInfo>(); // NEU: Initialisierung
            Errors = new List<string>();
        }
    }
}