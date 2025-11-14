using System;
using System.Runtime.InteropServices;
using NativeProcesses.Core.Engine;
using System.Collections.Generic;
using System.Linq;

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
        public struct IatHookInfo
        {
            public string ModuleName;
            public string FunctionName;
            public IntPtr ExpectedAddress;
            public IntPtr ActualAddress;
        }
        public struct InlineHookInfo
        {
            public string ModuleName;
            public string SectionName;
            public long Offset;
            public byte OriginalByte;
            public byte PatchedByte;
        }
        public struct SuspiciousThreadInfo
        {
            public int ThreadId;
            public IntPtr StartAddress;
            public string RegionState; // z.B. MEM_PRIVATE
            public string RegionProtection; // z.B. PAGE_EXECUTE_READWRITE
        }
        public struct SuspiciousMemoryRegionInfo
        {
            public IntPtr BaseAddress;
            public long RegionSize;
            public string Type; // z.B. MEM_PRIVATE
            public string Protection; // z.B. PAGE_EXECUTE_READWRITE
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

        private PeStructs.IMAGE_SECTION_HEADER[] GetPeHeadersFromMemory(Native.ManagedProcess process, IntPtr moduleBase, out PeStructs.IMAGE_DOS_HEADER dosHeader, out PeStructs.IMAGE_FILE_HEADER fileHeader, out ushort magic)
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
            return sections;
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
        public List<IatHookInfo> CheckIatHooks(Native.ManagedProcess process, IntPtr moduleToScanBase, string moduleToScanName, IntPtr ntdllBase, List<NativeProcesses.Core.Models.ProcessModuleInfo> allModules)
        {
            var results = new List<IatHookInfo>();
            bool isWow64 = process.GetIsWow64();

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

                if (importDirectory.VirtualAddress == 0)
                {
                    return results;
                }

                IntPtr importDescAddr = IntPtr.Add(moduleToScanBase, (int)importDirectory.VirtualAddress);
                int importDescSize = Marshal.SizeOf(typeof(PeStructs.IMAGE_IMPORT_DESCRIPTOR));

                for (int descIndex = 0; ; descIndex++)
                {
                    byte[] importDescBytes = process.ReadMemory(IntPtr.Add(importDescAddr, descIndex * importDescSize), importDescSize);
                    var importDesc = ByteArrayToStructure<PeStructs.IMAGE_IMPORT_DESCRIPTOR>(importDescBytes);

                    if (importDesc.Name == 0 && importDesc.FirstThunk == 0)
                        break;

                    string dllName = ReadNullTerminatedString(process, IntPtr.Add(moduleToScanBase, (int)importDesc.Name));

                    if (!dllName.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase))
                        continue;

                    uint originalFirstThunkRva = importDesc.OriginalFirstThunk == 0 ? importDesc.FirstThunk : importDesc.OriginalFirstThunk;
                    IntPtr iatAddress = IntPtr.Add(moduleToScanBase, (int)importDesc.FirstThunk);

                    for (int thunkIndex = 0; ; thunkIndex++)
                    {
                        int ptrSize = isWow64 ? 4 : 8;
                        IntPtr thunkEntryAddr = IntPtr.Add(iatAddress, thunkIndex * ptrSize);

                        ulong thunkValue = ReadUIntPtr(process, thunkEntryAddr, isWow64);
                        if (thunkValue == 0)
                            break;

                        string functionName = GetImportName(process, moduleToScanBase, originalFirstThunkRva, thunkIndex, isWow64);

                        if (functionName.StartsWith("Ordinal"))
                            continue; // Ordinal-Imports überspringen wir (zu komplex für diesen Check)

                        IntPtr actualAddressInIat = (IntPtr)thunkValue;

                        // HIER IST DIE VALIDIERUNG (Option A)
                        // Wir holen die ECHTE Adresse aus der EAT von ntdll.dll
                        IntPtr expectedAddress = GetExportAddress(process, ntdllBase, functionName, allModules);
                        if (expectedAddress == IntPtr.Zero)
                        {
                            // Funktion ist ein Forwarder (Kritikpunkt #4) oder existiert nicht.
                            // In beiden Fällen ist es kein Hook.
                            continue;
                        }

                        if (actualAddressInIat != expectedAddress)
                        {
                            // HOOK GEFUNDEN!
                            // Die IAT (actualAddress) zeigt NICHT auf die EAT (expectedAddress).
                            results.Add(new IatHookInfo
                            {
                                ModuleName = moduleToScanName,
                                FunctionName = functionName,
                                ExpectedAddress = expectedAddress,
                                ActualAddress = actualAddressInIat
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, $"SecurityInspector.CheckIatHooks failed for {moduleToScanName}", ex);
            }
            return results;
        }

        public List<InlineHookInfo> CheckForInlineHooks(Native.ManagedProcess process, IntPtr moduleBase, string modulePath)
        {
            var results = new List<InlineHookInfo>();
            try
            {
                var fileSections = GetPeHeadersFromFile(modulePath, out _, out _, out _);
                var memSections = GetPeHeadersFromMemory(process, moduleBase, out _, out _, out _);

                var fileTextSection = FindSection(fileSections, ".text");
                var memTextSection = FindSection(memSections, ".text");

                if (fileTextSection.SizeOfRawData == 0 || memTextSection.VirtualSize == 0)
                {
                    _logger?.Log(LogLevel.Debug, $"SecurityInspector: {modulePath} .text size is zero.", null);
                    return results;
                }

                uint sizeToCompare = Math.Min(fileTextSection.SizeOfRawData, memTextSection.VirtualSize);

                byte[] fileBytes = ReadBytesFromFile(modulePath, fileTextSection.PointerToRawData, sizeToCompare);
                byte[] memBytes = process.ReadMemory(IntPtr.Add(moduleBase, (int)memTextSection.VirtualAddress), (int)sizeToCompare);

                for (int i = 0; i < sizeToCompare; i++)
                {
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

                        // Wir melden nur den ersten Fund pro Sektion, um das Log nicht zu fluten
                        _logger?.Log(LogLevel.Warning, $"SecurityInspector: HOOK DETECTED! Mismatch in {modulePath} at .text + 0x{i.ToString("X")}.", null);
                        return results;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, $"SecurityInspector.CheckForInlineHooks failed for {modulePath}", ex);
            }
            return results; // Keine Hooks gefunden
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
        public List<string> Errors { get; internal set; }

        public bool IsHooked
        {
            get { return (IatHooks.Count > 0) || (InlineHooks.Count > 0); }
        }

        internal HookDetectionResult(int pid)
        {
            ProcessId = pid;
            IatHooks = new List<SecurityInspector.IatHookInfo>();
            InlineHooks = new List<SecurityInspector.InlineHookInfo>();
            SuspiciousThreads = new List<SecurityInspector.SuspiciousThreadInfo>();
            SuspiciousMemoryRegions = new List<SecurityInspector.SuspiciousMemoryRegionInfo>();
            Errors = new List<string>();
        }
    }
}