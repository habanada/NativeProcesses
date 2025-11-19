/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using NativeProcesses.Core.Engine;
using NativeProcesses.Core.Models;
using NativeProcesses.Core.Native;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NativeProcesses.Core.Inspection
{
    public class SecurityInspector
    {
        private IEngineLogger _logger;
        private static readonly Dictionary<string, bool> _signatureCache = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, Dictionary<string, IntPtr>> _globalExportCache = new Dictionary<string, Dictionary<string, IntPtr>>(StringComparer.OrdinalIgnoreCase);
        // Lock-Objekte für Thread-Safety
        private static readonly object _sigLock = new object();
        private static readonly object _exportLock = new object();

        #region P/Invoke Kernel32
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

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint SetFilePointer(
            IntPtr hFile,
            int lDistanceToMove,
            IntPtr lpDistanceToMoveHigh,
            uint dwMoveMethod);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int SetFilePointerEx(
            IntPtr hFile,
            long liDistanceToMove,
            out long lpNewFilePointer,
            uint dwMoveMethod);

        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint OPEN_EXISTING = 3;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        #endregion

        public class IatHookInfo
        {
            public string ModuleName { get; set; }
            public string FunctionName { get; set; }
            public IntPtr ExpectedAddress { get; set; }
            public IntPtr ActualAddress { get; set; }
            public string TargetModule { get; set; }
            public bool IsSafe { get; set; }
        }

        public class InlineHookInfo
        {
            public string ModuleName { get; set; }
            public string SectionName { get; set; }
            public long Offset { get; set; }
            public byte OriginalByte { get; set; }
            public byte PatchedByte { get; set; }
            public string HookType { get; set; }
            public int HookSize { get; set; }
            public IntPtr TargetAddress { get; set; }
            public string TargetModule { get; set; }
            public bool IsSafe { get; set; }
        }

        public struct SuspiciousThreadInfo
        {
            public int ThreadId { get; set; }
            public IntPtr StartAddress { get; set; }
            public string RegionState { get; set; }
            public string RegionProtection { get; set; }
        }

        public struct SuspiciousMemoryRegionInfo
        {
            public IntPtr BaseAddress { get; set; }
            public long RegionSize { get; set; }
            public string Type { get; set; }
            public string Protection { get; set; }
        }

        public SecurityInspector(IEngineLogger logger)
        {
            _logger = logger;
        }
        // Statt Exceptions zu werfen, gibt es null zurück. Das macht den Scan 100x schneller.
        private byte[] SafeRead(ManagedProcess process, IntPtr address, int size)
        {
            // Nutzt deine ManagedProcess.TryReadMemory Implementierung
            if (process.TryReadMemory(address, size, out byte[] buffer))
            {
                return buffer;
            }
            return null;
        }

        // --- HELPER: String Reading (Optimiert) ---
        private string ReadNullTerminatedString(ManagedProcess process, IntPtr address)
        {
            var sb = new StringBuilder(64);
            int offset = 0;
            // Lesen in 32-Byte Blöcken statt Byte-für-Byte (Syscall Reduktion)
            while (offset < 512)
            {
                byte[] chunk = SafeRead(process, IntPtr.Add(address, offset), 32);
                if (chunk == null) break; // Ende des lesbaren Speichers

                for (int i = 0; i < chunk.Length; i++)
                {
                    if (chunk[i] == 0) return sb.ToString();
                    sb.Append((char)chunk[i]);
                }
                offset += 32;
            }
            return sb.ToString();
        }
        // --- High Performance String Reader ---

        private string ReadNullTerminatedStringFast(ManagedProcess process, IntPtr address)
        {
            // 1. Optimierung: Wir lesen direkt 64 Bytes auf einmal.
            // Das reicht für fast alle DLL-Namen (z.B. "kernel32.dll" ist nur 12 Bytes).
            // Das spart uns den Overhead, Byte für Byte zu lesen.
            if (process.TryReadMemory(address, 64, out byte[] buffer))
            {
                int nullIndex = Array.IndexOf(buffer, (byte)0);
                if (nullIndex >= 0)
                {
                    // Null-Terminator gefunden -> String direkt zurückgeben
                    return Encoding.ASCII.GetString(buffer, 0, nullIndex);
                }

                // Null-Terminator nicht in den ersten 64 Bytes? 
                // Dann ist es ein langer String -> Fallback auf Robust-Methode.
                return ReadNullTerminatedStringRobust(process, address);
            }

            // Wenn der erste Read fehlschlägt (z.B. ungültiger Pointer), geben wir null zurück.
            return null;
        }

        private string ReadNullTerminatedStringRobust(ManagedProcess process, IntPtr address)
        {
            var sb = new StringBuilder(128);
            int offset = 0;

            // Sicherheits-Limit: Maximal 512 Bytes lesen, um Endlosschleifen bei Garbage-Daten zu verhindern.
            while (offset < 512)
            {
                // Wir lesen in kleinen 32-Byte Chunks weiter
                if (process.TryReadMemory(IntPtr.Add(address, offset), 32, out byte[] chunk))
                {
                    for (int i = 0; i < chunk.Length; i++)
                    {
                        if (chunk[i] == 0)
                        {
                            // Ende gefunden
                            return sb.ToString();
                        }

                        // Optional: Hier könnte man nicht-druckbare Zeichen filtern, 
                        // aber für DLL-Namen reicht ASCII meist aus.
                        sb.Append((char)chunk[i]);
                    }
                    offset += 32;
                }
                else
                {
                    // Speicherbereich nicht mehr lesbar (z.B. Page Boundary erreicht) -> Abbruch
                    break;
                }
            }

            // Geben wir zurück, was wir bis zum Abbruch gefunden haben
            return sb.ToString();
        }
        // --- 2. GetExportAddress (Nutzt Cache) ---
        public IntPtr GetExportAddress(ManagedProcess process, IntPtr moduleBase, string functionName, List<ProcessModuleInfo> allModules, string moduleNameForCache)
        {
            try
            {
                if (!string.IsNullOrEmpty(moduleNameForCache))
                {
                    // Cache Read
                    lock (_exportLock)
                    {
                        if (_globalExportCache.ContainsKey(moduleNameForCache))
                        {
                            return _globalExportCache[moduleNameForCache].TryGetValue(functionName, out IntPtr cached) ? cached : IntPtr.Zero;
                        }
                    }
                    // Cache Miss -> Build
                    var map = BuildExportMap(process, moduleBase);
                    // Cache Write
                    lock (_exportLock)
                    {
                        if (!_globalExportCache.ContainsKey(moduleNameForCache)) _globalExportCache[moduleNameForCache] = map;
                        return map.TryGetValue(functionName, out IntPtr addr) ? addr : IntPtr.Zero;
                    }
                }
                return IntPtr.Zero;
            }
            catch { return IntPtr.Zero; }
        }
        public Dictionary<string, IntPtr> BuildExportMap(ManagedProcess process, IntPtr moduleBase)
        {
            var exportMap = new Dictionary<string, IntPtr>(StringComparer.OrdinalIgnoreCase);
            try
            {
                // 1. PE Header lesen (DOS + NT Header) - Kleiner Read
                byte[] headers = SafeRead(process, moduleBase, 1024);
                if (headers == null) return exportMap;

                int e_lfanew = BitConverter.ToInt32(headers, 0x3C);
                if (e_lfanew > headers.Length - 256) return exportMap;

                // NT Header Magic prüfen (32/64 Bit)
                ushort magic = BitConverter.ToUInt16(headers, e_lfanew + 24);
                bool is64 = (magic == PeStructs.IMAGE_NT_OPTIONAL_HDR64_MAGIC);

                // Export Directory RVA und Size finden
                // 64bit: Offset 136 (112 + 24), 32bit: Offset 120 (96 + 24)
                int exportDirOffset = e_lfanew + 24 + (is64 ? 112 : 96);

                uint exportRva = BitConverter.ToUInt32(headers, exportDirOffset);
                uint exportSize = BitConverter.ToUInt32(headers, exportDirOffset + 4);

                if (exportRva == 0 || exportSize == 0) return exportMap;

                // --- DER PE-SIEVE TRICK ---
                // Wir lesen ALLES auf einmal: Die Tables UND die Strings.
                // Export-Sektionen sind meist < 100 KB. Das geht in einem Rutsch.
                IntPtr exportDirAddr = IntPtr.Add(moduleBase, (int)exportRva);

                // Wir lesen den ganzen Bereich (Verzeichnis + Strings liegen meist nah beieinander in der .rdata Sektion)
                byte[] exportBlob = SafeRead(process, exportDirAddr, (int)exportSize);
                if (exportBlob == null) return exportMap;

                // Wir brauchen Hilfsfunktionen, um aus dem Blob zu lesen statt aus dem Prozess
                // Da RVA relativ zur Modulbasis ist, müssen wir die Offsets im Blob berechnen.
                // Achtung: Die Strings können theoretisch außerhalb des 'exportSize' Bereichs liegen, 
                // aber meistens sind sie drin. Falls nicht, lesen wir sie einzeln (Fallback).

                // Export Directory Struktur parsen (steht am Anfang von exportRva)
                // IMAGE_EXPORT_DIRECTORY ist 40 Bytes lang
                if (exportBlob.Length < 40) return exportMap;

                uint numberOfFunctions = BitConverter.ToUInt32(exportBlob, 20);
                uint numberOfNames = BitConverter.ToUInt32(exportBlob, 24);
                uint addressOfFunctions = BitConverter.ToUInt32(exportBlob, 28); // RVA
                uint addressOfNames = BitConverter.ToUInt32(exportBlob, 32);     // RVA
                uint addressOfOrdinals = BitConverter.ToUInt32(exportBlob, 36);  // RVA

                // Berechne Offsets im Blob (Delta zwischen ExportRva und den Tabellen)
                // Hinweis: Wenn die Tabellen weit weg sind (anderer Section), klappt der Blob-Read evtl. nicht ganz,
                // aber für Standard-DLLs ist alles kompakt.

                // Sicherheitshalber lesen wir die Tabellen spezifisch, falls sie nicht im ersten Blob sind
                // (Das ist immer noch schneller als String-für-String)
                byte[] nameRvas = ReadRelocatedData(process, moduleBase, addressOfNames, numberOfNames * 4, exportRva, exportBlob);
                byte[] ordinals = ReadRelocatedData(process, moduleBase, addressOfOrdinals, numberOfNames * 2, exportRva, exportBlob);
                byte[] funcs = ReadRelocatedData(process, moduleBase, addressOfFunctions, numberOfFunctions * 4, exportRva, exportBlob);

                if (nameRvas == null || ordinals == null || funcs == null) return exportMap;

                for (int i = 0; i < numberOfNames; i++)
                {
                    uint nameRva = BitConverter.ToUInt32(nameRvas, i * 4);

                    // Versuche Name aus Blob zu lesen
                    string name = ExtractStringFromBlob(nameRva, exportRva, exportBlob);

                    // Fallback: Wenn Name außerhalb des Blobs liegt, einzeln lesen (langsam, aber sicher)
                    if (name == null)
                    {
                        name = ReadNullTerminatedStringFast(process, IntPtr.Add(moduleBase, (int)nameRva));
                    }

                    if (string.IsNullOrEmpty(name)) continue;

                    ushort ordinal = BitConverter.ToUInt16(ordinals, i * 2);
                    if (ordinal >= numberOfFunctions) continue;

                    uint funcRva = BitConverter.ToUInt32(funcs, ordinal * 4);

                    // Forwarder Check
                    if (funcRva >= exportRva && funcRva < (exportRva + exportSize)) continue;

                    IntPtr funcAddr = IntPtr.Add(moduleBase, (int)funcRva);
                    if (!exportMap.ContainsKey(name)) exportMap[name] = funcAddr;
                }
            }
            catch { }
            return exportMap;
        }

        // Helper: Versucht Daten aus dem lokalen Blob zu holen, sonst liest er nach
        private byte[] ReadRelocatedData(ManagedProcess process, IntPtr moduleBase, uint targetRva, uint size, uint exportStartRva, byte[] exportBlob)
        {
            // Liegt der angeforderte Bereich im Blob?
            // Blob beginnt bei exportStartRva
            if (targetRva >= exportStartRva && (targetRva + size) <= (exportStartRva + exportBlob.Length))
            {
                int offset = (int)(targetRva - exportStartRva);
                byte[] buffer = new byte[size];
                Array.Copy(exportBlob, offset, buffer, 0, size);
                return buffer;
            }

            // Nicht im Blob -> Nachladen
            return SafeRead(process, IntPtr.Add(moduleBase, (int)targetRva), (int)size);
        }

        // Helper: String aus Blob extrahieren
        private string ExtractStringFromBlob(uint stringRva, uint exportStartRva, byte[] blob)
        {
            if (stringRva >= exportStartRva && stringRva < (exportStartRva + blob.Length))
            {
                int offset = (int)(stringRva - exportStartRva);
                int end = offset;
                // Suche Null-Terminator
                while (end < blob.Length && blob[end] != 0) end++;

                return Encoding.ASCII.GetString(blob, offset, end - offset);
            }
            return null; // Außerhalb
        }
        public List<PeAnomalyInfo> CheckSectionPermissionMismatch(
                    ManagedProcess process,
                    ProcessModuleInfo module,
                    List<VirtualMemoryRegion> regions)
        {
            var anomalies = new List<PeAnomalyInfo>();

            if (string.IsNullOrEmpty(module.FullDllName) || !System.IO.File.Exists(module.FullDllName))
                return anomalies;

            try
            {
                PeStructs.IMAGE_DOS_HEADER dosHeader;
                PeStructs.IMAGE_FILE_HEADER fileHeader;
                ushort magic;

                var sectionsOnDisk = GetPeHeadersFromFile(module.FullDllName, out dosHeader, out fileHeader, out magic);

                foreach (var section in sectionsOnDisk)
                {
                    IntPtr sectionAddress = IntPtr.Add(module.DllBase, (int)section.VirtualAddress);

                    var region = regions.FirstOrDefault(r =>
                        sectionAddress.ToInt64() >= r.BaseAddress.ToInt64() &&
                        sectionAddress.ToInt64() < (r.BaseAddress.ToInt64() + r.RegionSize));

                    if (region != null)
                    {
                        bool isMemExec = region.Protection.ToUpper().Contains("EXECUTE");
                        bool isDiskExec = (section.Characteristics & 0x20000000) != 0;

                        if (isMemExec && !isDiskExec)
                        {
                            anomalies.Add(new PeAnomalyInfo
                            {
                                ModuleName = module.BaseDllName,
                                AnomalyType = "Permission Mismatch",
                                Details = $"Section {section.Name} is EXECUTE in memory but DATA on disk. Potential Stomping/Shellcode.",
                                Severity = "High"
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, $"CheckSectionPermissionMismatch failed for {module.BaseDllName}: {ex.Message}", ex);
            }

            return anomalies;
        }

        private T ByteArrayToStructure<T>(byte[] bytes, int offset = 0) where T : struct
        {
            if (bytes == null) return default(T);
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try { return (T)Marshal.PtrToStructure(IntPtr.Add(handle.AddrOfPinnedObject(), offset), typeof(T)); }
            finally { handle.Free(); }
        }

        //public IntPtr GetExportAddress(ManagedProcess process,
        //                                IntPtr moduleBase,
        //                                string functionName,
        //                                List<ProcessModuleInfo> allModules,
        //                                string moduleNameForCache)
        //{
        //    try
        //    {
        //        // 1. Cache prüfen (Thread-Safe)
        //        if (!string.IsNullOrEmpty(moduleNameForCache))
        //        {
        //            lock (_exportLock)
        //            {
        //                if (_globalExportCache.ContainsKey(moduleNameForCache))
        //                {
        //                    if (_globalExportCache[moduleNameForCache].TryGetValue(functionName, out IntPtr cachedAddr))
        //                    {
        //                        return cachedAddr;
        //                    }
        //                    // Wenn im Cache, aber Funktion nicht gefunden -> Return Zero (kein Fehler)
        //                    return IntPtr.Zero;
        //                }
        //            }

        //            // Nicht im Cache -> Bauen (außerhalb des Locks, um andere Threads nicht zu blockieren, 
        //            // wir locken nur das Schreiben am Ende)
        //            var map = BuildExportMap(process, moduleBase);

        //            lock (_exportLock)
        //            {
        //                if (!_globalExportCache.ContainsKey(moduleNameForCache))
        //                {
        //                    _globalExportCache[moduleNameForCache] = map;
        //                }

        //                if (map.TryGetValue(functionName, out IntPtr addr))
        //                {
        //                    return addr;
        //                }
        //            }
        //        }
        //        return IntPtr.Zero;
        //    }
        //    catch (Exception ex)
        //    {
        //        _logger?.Log(LogLevel.Error, $"GetExportAddress failed for {functionName}", ex);
        //        return IntPtr.Zero;
        //    }
        //}

        //private string ReadNullTerminatedString(ManagedProcess process, IntPtr address)
        //{
        //    var result = new StringBuilder(64);
        //    int offset = 0;
        //    bool nullFound = false;

        //    while (!nullFound && offset < 256)
        //    {
        //        try
        //        {
        //            byte[] chunk = process.ReadMemory(IntPtr.Add(address, offset), 32); // Kleinere Chunks
        //            if (chunk == null || chunk.Length == 0) break;

        //            for (int i = 0; i < chunk.Length; i++)
        //            {
        //                if (chunk[i] == 0)
        //                {
        //                    nullFound = true;
        //                    break;
        //                }
        //                result.Append((char)chunk[i]);
        //            }
        //            offset += 32;
        //        }
        //        catch
        //        {
        //            break; // Abbruch bei Fehler
        //        }
        //    }
        //    return result.ToString();
        //}
        private IntPtr ResolveExportAddressInternal(ManagedProcess process,
                                                    IntPtr moduleBase,
                                                    string functionName,
                                                    List<ProcessModuleInfo> allModules,
                                                    int recursionDepth)
        {
            if (recursionDepth > 10)
            {
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

                        if (functionRva >= exportDirectory.VirtualAddress &&
                            functionRva < (exportDirectory.VirtualAddress + exportDirectory.Size))
                        {
                            string forwarderString = ReadNullTerminatedString(process, functionAddress);

                            string[] parts = forwarderString.Split('.');
                            if (parts.Length != 2)
                            {
                                return IntPtr.Zero;
                            }

                            string forwardModuleName = parts[0] + ".dll";
                            string forwardFunctionName = parts[1];

                            var forwardModule = allModules.FirstOrDefault(m => m.BaseDllName.Equals(forwardModuleName, StringComparison.OrdinalIgnoreCase));
                            if (forwardModule == null)
                            {
                                return IntPtr.Zero;
                            }

                            return ResolveExportAddressInternal(process, forwardModule.DllBase, forwardFunctionName, allModules, recursionDepth + 1);
                        }

                        return functionAddress;
                    }
                }
            }
            catch
            {
            }
            return IntPtr.Zero;
        }

        //private string ReadNullTerminatedString(ManagedProcess process, IntPtr address)
        //{
        //    var bytes = new List<byte>();
        //    int offset = 0;
        //    byte b;
        //    do
        //    {
        //        b = process.ReadMemory(IntPtr.Add(address, offset), 1)[0];
        //        if (b != 0)
        //            bytes.Add(b);
        //        offset++;
        //    } while (b != 0 && offset < 256);

        //    return Encoding.ASCII.GetString(bytes.ToArray());
        //}

        private byte[] ReadBytesFromFile(string filePath, uint offset, uint bytesToRead)
        {
            IntPtr hFile = IntPtr.Zero;
            try
            {
                hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                if (hFile == INVALID_HANDLE_VALUE)
                {
                    return new byte[0];
                }

                if (Marshal.SizeOf(typeof(long)) == 8)
                {
                    SetFilePointerEx(hFile, (long)offset, out _, 0);
                }
                else
                {
                    SetFilePointer(hFile, (int)offset, IntPtr.Zero, 0);
                }

                byte[] buffer = new byte[bytesToRead];
                ReadFile(hFile, buffer, bytesToRead, out _, IntPtr.Zero);
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

        private PeStructs.IMAGE_SECTION_HEADER[] GetPeHeadersFromMemory(ManagedProcess process, IntPtr moduleBase, out PeStructs.IMAGE_DOS_HEADER dosHeader, out PeStructs.IMAGE_FILE_HEADER fileHeader, out ushort magic, out PeStructs.IMAGE_DATA_DIRECTORY relocDir)
        {
            byte[] buffer = process.ReadMemory(moduleBase, Marshal.SizeOf(typeof(PeStructs.IMAGE_DOS_HEADER)));
            dosHeader = ByteArrayToStructure<PeStructs.IMAGE_DOS_HEADER>(buffer);
            if (!dosHeader.IsValid)
            {
                throw new Exception($"Invalid DOS header in memory at {moduleBase.ToString("X")}.");
            }

            IntPtr ntHeaderAddr = IntPtr.Add(moduleBase, dosHeader.e_lfanew);
            buffer = process.ReadMemory(ntHeaderAddr, sizeof(uint) + Marshal.SizeOf(typeof(PeStructs.IMAGE_FILE_HEADER)));
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

        private HashSet<uint> ParseRelocations(ManagedProcess process, IntPtr moduleBase, PeStructs.IMAGE_DATA_DIRECTORY relocDir, bool isWow64)
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

                        if (type == PeStructs.IMAGE_REL_BASED_DIR64 || type == PeStructs.IMAGE_REL_BASED_HIGHLOW)
                        {
                            uint relocRva = relocBlock.VirtualAddress + offset;
                            relocOffsets.Add(relocRva);

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

        // Diese Methode baut EINE komplette Map für ein Modul auf. Das machen wir nur 1x pro Modul.
        //public Dictionary<string, IntPtr> BuildExportMap(ManagedProcess process, IntPtr moduleBase)
        //{
        //    var exportMap = new Dictionary<string, IntPtr>(StringComparer.OrdinalIgnoreCase);
        //    try
        //    {
        //        byte[] dosHeaderBytes = process.ReadMemory(moduleBase, Marshal.SizeOf(typeof(PeStructs.IMAGE_DOS_HEADER)));
        //        var dosHeader = ByteArrayToStructure<PeStructs.IMAGE_DOS_HEADER>(dosHeaderBytes);
        //        if (!dosHeader.IsValid) return exportMap;

        //        IntPtr ntHeaderAddr = IntPtr.Add(moduleBase, dosHeader.e_lfanew);
        //        byte[] ntHeaderMagicBytes = process.ReadMemory(IntPtr.Add(ntHeaderAddr, 4 + Marshal.SizeOf(typeof(PeStructs.IMAGE_FILE_HEADER))), sizeof(ushort));
        //        ushort magic = BitConverter.ToUInt16(ntHeaderMagicBytes, 0);

        //        PeStructs.IMAGE_DATA_DIRECTORY exportDirectory;
        //        if (magic == PeStructs.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        //        {
        //            byte[] ntHeaderBytes = process.ReadMemory(ntHeaderAddr, Marshal.SizeOf(typeof(PeStructs.IMAGE_NT_HEADERS64)));
        //            exportDirectory = ByteArrayToStructure<PeStructs.IMAGE_NT_HEADERS64>(ntHeaderBytes).OptionalHeader.DataDirectory[PeStructs.IMAGE_DIRECTORY_ENTRY_EXPORT];
        //        }
        //        else
        //        {
        //            byte[] ntHeaderBytes = process.ReadMemory(ntHeaderAddr, Marshal.SizeOf(typeof(PeStructs.IMAGE_NT_HEADERS32)));
        //            exportDirectory = ByteArrayToStructure<PeStructs.IMAGE_NT_HEADERS32>(ntHeaderBytes).OptionalHeader.DataDirectory[PeStructs.IMAGE_DIRECTORY_ENTRY_EXPORT];
        //        }

        //        if (exportDirectory.VirtualAddress == 0) return exportMap;

        //        IntPtr exportDirAddr = IntPtr.Add(moduleBase, (int)exportDirectory.VirtualAddress);
        //        var eat = ByteArrayToStructure<PeStructs.IMAGE_EXPORT_DIRECTORY>(process.ReadMemory(exportDirAddr, Marshal.SizeOf(typeof(PeStructs.IMAGE_EXPORT_DIRECTORY))));

        //        IntPtr pFunctions = IntPtr.Add(moduleBase, (int)eat.AddressOfFunctions);
        //        IntPtr pNames = IntPtr.Add(moduleBase, (int)eat.AddressOfNames);
        //        IntPtr pOrdinals = IntPtr.Add(moduleBase, (int)eat.AddressOfNameOrdinals);

        //        // Bulk Read für Performance
        //        byte[] nameRvaBuffer = process.ReadMemory(pNames, (int)eat.NumberOfNames * 4);
        //        byte[] ordinalBuffer = process.ReadMemory(pOrdinals, (int)eat.NumberOfNames * 2);
        //        byte[] funcRvaBuffer = process.ReadMemory(pFunctions, (int)eat.NumberOfFunctions * 4);

        //        for (int i = 0; i < eat.NumberOfNames; i++)
        //        {
        //            uint nameRva = BitConverter.ToUInt32(nameRvaBuffer, i * 4);
        //            string name = ReadNullTerminatedString(process, IntPtr.Add(moduleBase, (int)nameRva));

        //            ushort ordinal = BitConverter.ToUInt16(ordinalBuffer, i * 2);
        //            if (ordinal >= eat.NumberOfFunctions) continue;

        //            uint functionRva = BitConverter.ToUInt32(funcRvaBuffer, ordinal * 4);

        //            // Forwarder-Filter (wir speichern keine Forwarder im Cache, da komplex aufzulösen)
        //            if (functionRva >= exportDirectory.VirtualAddress &&
        //                functionRva < (exportDirectory.VirtualAddress + exportDirectory.Size))
        //            {
        //                continue;
        //            }

        //            IntPtr functionAddress = IntPtr.Add(moduleBase, (int)functionRva);

        //            if (!string.IsNullOrEmpty(name) && !exportMap.ContainsKey(name))
        //            {
        //                exportMap[name] = functionAddress;
        //            }
        //        }
        //    }
        //    catch
        //    {
        //        // Fehler beim Map-Building ignorieren, unvollständige Map zurückgeben
        //    }
        //    return exportMap;
        //}
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
        public List<IatHookInfo> CheckIatHooks(ManagedProcess process, IntPtr moduleToScanBase, string moduleToScanName, Dictionary<string, IntPtr> unused, List<ProcessModuleInfo> allModules, List<VirtualMemoryRegion> regions)
        {
            var results = new List<IatHookInfo>();
            bool isWow64 = process.GetIsWow64();
            int ptrSize = isWow64 ? 4 : 8;

            var moduleBounds = new Dictionary<string, ProcessModuleInfo>(StringComparer.OrdinalIgnoreCase);
            foreach (var mod in allModules) if (!moduleBounds.ContainsKey(mod.BaseDllName)) moduleBounds[mod.BaseDllName] = mod;

            try
            {
                byte[] dosBuffer = SafeRead(process, moduleToScanBase, 64);
                if (dosBuffer == null) return results;
                var dosHeader = ByteArrayToStructure<PeStructs.IMAGE_DOS_HEADER>(dosBuffer);
                if (!dosHeader.IsValid) return results;

                IntPtr ntAddr = IntPtr.Add(moduleToScanBase, dosHeader.e_lfanew);
                byte[] ntMagic = SafeRead(process, IntPtr.Add(ntAddr, 24), 2);
                if (ntMagic == null) return results;
                ushort magic = BitConverter.ToUInt16(ntMagic, 0);

                bool is64 = (magic == PeStructs.IMAGE_NT_OPTIONAL_HDR64_MAGIC);

                // Bestimme Import Dir Offset
                // OptionalHeader start ist ntAddr + 24
                // DataDirectory ist am Ende des OptionalHeader.
                // 32bit OptionalHeader ist 224 bytes (96 bytes Standard + 128 bytes DataDir) -> DataDir ist bei Offset 96
                // 64bit OptionalHeader ist 240 bytes (112 bytes Standard + 128 bytes DataDir) -> DataDir ist bei Offset 112
                int dataDirOffsetInOptHeader = is64 ? 112 : 96;
                IntPtr dataDirAddr = IntPtr.Add(ntAddr, 24 + dataDirOffsetInOptHeader + (int)PeStructs.IMAGE_DIRECTORY_ENTRY_IMPORT * 8);

                byte[] importDirBytes = SafeRead(process, dataDirAddr, 8); // RVA + Size
                if (importDirBytes == null) return results;
                uint importRva = BitConverter.ToUInt32(importDirBytes, 0);
                uint importSize = BitConverter.ToUInt32(importDirBytes, 4);

                if (importRva == 0 || importSize == 0) return results;

                IntPtr importDescAddr = IntPtr.Add(moduleToScanBase, (int)importRva);
                int descriptorSize = 20; // IMAGE_IMPORT_DESCRIPTOR

                while (true)
                {
                    byte[] descBytes = SafeRead(process, importDescAddr, descriptorSize);
                    if (descBytes == null) break;

                    // Manuelles Parsing
                    int nameRva = BitConverter.ToInt32(descBytes, 12);
                    int firstThunkRva = BitConverter.ToInt32(descBytes, 16);
                    int originalFirstThunkRva = BitConverter.ToInt32(descBytes, 0); // Characteristics/OriginalFirstThunk

                    if (nameRva == 0 && firstThunkRva == 0) break;

                    if (originalFirstThunkRva == 0) originalFirstThunkRva = firstThunkRva;

                    string dllName = ReadNullTerminatedString(process, IntPtr.Add(moduleToScanBase, nameRva));

                    // Validierung (um Garbage zu filtern)
                    if (string.IsNullOrEmpty(dllName) || dllName.Length < 4)
                    {
                        importDescAddr = IntPtr.Add(importDescAddr, descriptorSize);
                        continue;
                    }

                    ProcessModuleInfo targetModule = null;
                    moduleBounds.TryGetValue(dllName, out targetModule);

                    IntPtr thunkAddr = IntPtr.Add(moduleToScanBase, firstThunkRva);
                    int thunkIndex = 0;

                    // KEIN aggressiver Circuit Breaker, da der alte Code das auch nicht hatte.
                    // SafeRead verhindert Crashes, das reicht.

                    while (true)
                    {
                        byte[] ptrBytes = SafeRead(process, thunkAddr, ptrSize);
                        if (ptrBytes == null) break; // Speicher nicht lesbar -> Ende der Thunks oder Page Boundary

                        ulong funcVal = isWow64 ? BitConverter.ToUInt32(ptrBytes, 0) : BitConverter.ToUInt64(ptrBytes, 0);
                        if (funcVal == 0) break; // Ende der Import-Liste

                        IntPtr actualAddress = (IntPtr)funcVal;

                        // Quick Check: Ist Adresse im Zielmodul?
                        bool isInRange = false;
                        if (targetModule != null)
                        {
                            long start = targetModule.DllBase.ToInt64();
                            if ((long)funcVal >= start && (long)funcVal < (start + targetModule.SizeOfImage)) isInRange = true;
                        }

                        if (!isInRange)
                        {
                            string funcName = GetImportName(process, moduleToScanBase, (uint)originalFirstThunkRva, thunkIndex, isWow64);

                            if (!string.IsNullOrEmpty(funcName) && funcName != "[Error]")
                            {
                                IntPtr expectedAddress = IntPtr.Zero;
                                if (targetModule != null)
                                    expectedAddress = GetExportAddress(process, targetModule.DllBase, funcName, allModules, targetModule.BaseDllName);

                                if (expectedAddress != IntPtr.Zero && actualAddress != expectedAddress)
                                {
                                    string targetLoc = ResolveTargetAddress(actualAddress, process, allModules, regions);
                                    bool isSafe = IsSafeHookTarget(targetLoc, allModules);
                                    results.Add(new IatHookInfo { ModuleName = moduleToScanName, FunctionName = $"{dllName}!{funcName}", ExpectedAddress = expectedAddress, ActualAddress = actualAddress, TargetModule = targetLoc, IsSafe = isSafe });
                                }
                                else if (expectedAddress == IntPtr.Zero)
                                {
                                    string targetLoc = ResolveTargetAddress(actualAddress, process, allModules, regions);
                                    if (targetLoc.StartsWith("PRIVATE_MEMORY"))
                                        results.Add(new IatHookInfo { ModuleName = moduleToScanName, FunctionName = $"{dllName}!{funcName}", ExpectedAddress = IntPtr.Zero, ActualAddress = actualAddress, TargetModule = targetLoc, IsSafe = false });
                                }
                            }
                        }
                        thunkAddr = IntPtr.Add(thunkAddr, ptrSize);
                        thunkIndex++;
                        if (thunkIndex > 4000) break; // Safety
                    }
                    importDescAddr = IntPtr.Add(importDescAddr, descriptorSize);
                }
            }
            catch (Exception ex) { _logger?.Log(LogLevel.Debug, $"IAT Scan failed: {ex.Message}", null); }
            return results;
        }
        //public List<IatHookInfo> CheckIatHooks(ManagedProcess process,
        //                                          IntPtr moduleToScanBase,
        //                                          string moduleToScanName,
        //                                          Dictionary<string, IntPtr> ntdllExports, // Legacy
        //                                          List<ProcessModuleInfo> allModules,
        //                                          List<VirtualMemoryRegion> regions)
        //{
        //    var results = new List<IatHookInfo>();
        //    bool isWow64 = process.GetIsWow64();
        //    int ptrSize = isWow64 ? 4 : 8;

        //    var moduleBounds = new Dictionary<string, ProcessModuleInfo>(StringComparer.OrdinalIgnoreCase);
        //    foreach (var mod in allModules)
        //    {
        //        if (!moduleBounds.ContainsKey(mod.BaseDllName))
        //            moduleBounds[mod.BaseDllName] = mod;
        //    }

        //    try
        //    {
        //        var dosHeader = ByteArrayToStructure<PeStructs.IMAGE_DOS_HEADER>(process.ReadMemory(moduleToScanBase, Marshal.SizeOf(typeof(PeStructs.IMAGE_DOS_HEADER))));
        //        if (!dosHeader.IsValid) return results;

        //        IntPtr ntHeaderAddr = IntPtr.Add(moduleToScanBase, dosHeader.e_lfanew);
        //        ushort magic = BitConverter.ToUInt16(process.ReadMemory(IntPtr.Add(ntHeaderAddr, 24), 2), 0);
        //        bool is64BitPE = (magic == PeStructs.IMAGE_NT_OPTIONAL_HDR64_MAGIC);

        //        PeStructs.IMAGE_DATA_DIRECTORY importDir;
        //        if (is64BitPE)
        //        {
        //            var nt64 = ByteArrayToStructure<PeStructs.IMAGE_NT_HEADERS64>(process.ReadMemory(ntHeaderAddr, Marshal.SizeOf(typeof(PeStructs.IMAGE_NT_HEADERS64))));
        //            importDir = nt64.OptionalHeader.DataDirectory[PeStructs.IMAGE_DIRECTORY_ENTRY_IMPORT];
        //        }
        //        else
        //        {
        //            var nt32 = ByteArrayToStructure<PeStructs.IMAGE_NT_HEADERS32>(process.ReadMemory(ntHeaderAddr, Marshal.SizeOf(typeof(PeStructs.IMAGE_NT_HEADERS32))));
        //            importDir = nt32.OptionalHeader.DataDirectory[PeStructs.IMAGE_DIRECTORY_ENTRY_IMPORT];
        //        }

        //        if (importDir.VirtualAddress == 0 || importDir.Size == 0) return results;

        //        IntPtr importDescAddr = IntPtr.Add(moduleToScanBase, (int)importDir.VirtualAddress);
        //        int descriptorSize = Marshal.SizeOf(typeof(PeStructs.IMAGE_IMPORT_DESCRIPTOR));

        //        while (true)
        //        {
        //            var desc = ByteArrayToStructure<PeStructs.IMAGE_IMPORT_DESCRIPTOR>(process.ReadMemory(importDescAddr, descriptorSize));
        //            if (desc.Name == 0 && desc.FirstThunk == 0) break;

        //            string dllName = ReadNullTerminatedString(process, IntPtr.Add(moduleToScanBase, (int)desc.Name));

        //            // VALIDIERUNG: Import Descriptor prüfen
        //            if (string.IsNullOrEmpty(dllName) || dllName.Length < 4 ||
        //                (!dllName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && !dllName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)))
        //            {
        //                importDescAddr = IntPtr.Add(importDescAddr, descriptorSize);
        //                continue;
        //            }

        //            ProcessModuleInfo targetModule = null;
        //            moduleBounds.TryGetValue(dllName, out targetModule);

        //            IntPtr thunkAddr = IntPtr.Add(moduleToScanBase, (int)desc.FirstThunk);
        //            int thunkIndex = 0;
        //            int consecutiveErrors = 0;

        //            while (true)
        //            {
        //                ulong funcAddrVal = ReadUIntPtr(process, thunkAddr, isWow64);
        //                if (funcAddrVal == 0) break;

        //                IntPtr actualAddress = (IntPtr)funcAddrVal;
        //                bool isInRange = false;
        //                if (targetModule != null)
        //                {
        //                    long start = targetModule.DllBase.ToInt64();
        //                    long end = start + targetModule.SizeOfImage;
        //                    if ((long)funcAddrVal >= start && (long)funcAddrVal < end) isInRange = true;
        //                }

        //                if (!isInRange)
        //                {
        //                    string funcName = GetImportName(process, moduleToScanBase, (uint)(desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk), thunkIndex, isWow64);

        //                    // NOTBREMSE
        //                    if (string.IsNullOrEmpty(funcName) || funcName == "[Error]")
        //                    {
        //                        consecutiveErrors++;
        //                        if (consecutiveErrors > 5) break; // Abort DLL
        //                    }
        //                    else
        //                    {
        //                        consecutiveErrors = 0;
        //                        IntPtr expectedAddress = IntPtr.Zero;

        //                        // Cache nutzen!
        //                        if (targetModule != null)
        //                        {
        //                            expectedAddress = GetExportAddress(process, targetModule.DllBase, funcName, allModules, targetModule.BaseDllName);
        //                        }

        //                        if (expectedAddress != IntPtr.Zero && actualAddress != expectedAddress)
        //                        {
        //                            string targetLocation = ResolveTargetAddress(actualAddress, process, allModules, regions);
        //                            bool isSafe = IsSafeHookTarget(targetLocation, allModules);

        //                            results.Add(new IatHookInfo
        //                            {
        //                                ModuleName = moduleToScanName,
        //                                FunctionName = $"{dllName}!{funcName}",
        //                                ExpectedAddress = expectedAddress,
        //                                ActualAddress = actualAddress,
        //                                TargetModule = targetLocation,
        //                                IsSafe = isSafe
        //                            });
        //                        }
        //                        else if (expectedAddress == IntPtr.Zero)
        //                        {
        //                            string targetLocation = ResolveTargetAddress(actualAddress, process, allModules, regions);
        //                            if (targetLocation.StartsWith("PRIVATE_MEMORY"))
        //                            {
        //                                results.Add(new IatHookInfo
        //                                {
        //                                    ModuleName = moduleToScanName,
        //                                    FunctionName = $"{dllName}!{funcName}",
        //                                    ExpectedAddress = IntPtr.Zero,
        //                                    ActualAddress = actualAddress,
        //                                    TargetModule = targetLocation,
        //                                    IsSafe = false
        //                                });
        //                            }
        //                        }
        //                    }
        //                }

        //                thunkAddr = IntPtr.Add(thunkAddr, ptrSize);
        //                thunkIndex++;
        //                if (thunkIndex > 5000) break; // Safety Break
        //            }

        //            importDescAddr = IntPtr.Add(importDescAddr, descriptorSize);
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        _logger?.Log(LogLevel.Debug, $"IAT Scan failed for {moduleToScanName}: {ex.Message}", null);
        //    }

        //    return results;
        //}

        public List<InlineHookInfo> CheckForInlineHooks(ManagedProcess process, IntPtr moduleBase, string modulePath, List<ProcessModuleInfo> modules, List<VirtualMemoryRegion> regions)
        {
            var results = new List<InlineHookInfo>();
            if (string.IsNullOrEmpty(modulePath) || !System.IO.File.Exists(modulePath)) return results;
            try
            {
                byte[] localMappedImage = null;
                try { localMappedImage = PeEmulation.MapAndRelocate(modulePath, moduleBase); } catch { return results; }
                var dosHeader = ByteArrayToStructure<PeStructs.IMAGE_DOS_HEADER>(localMappedImage, 0);
                int ntOffset = dosHeader.e_lfanew;
                ushort magic = BitConverter.ToUInt16(localMappedImage, ntOffset + 24);
                bool is64Bit = (magic == PeStructs.IMAGE_NT_OPTIONAL_HDR64_MAGIC);
                ushort numberOfSections = BitConverter.ToUInt16(localMappedImage, ntOffset + 4 + 2);
                ushort sizeOfOptionalHeader = BitConverter.ToUInt16(localMappedImage, ntOffset + 4 + 16);
                int sectionHeadersOffset = ntOffset + 24 + sizeOfOptionalHeader;
                int sectionSize = Marshal.SizeOf(typeof(PeStructs.IMAGE_SECTION_HEADER));

                for (int i = 0; i < numberOfSections; i++)
                {
                    var sec = ByteArrayToStructure<PeStructs.IMAGE_SECTION_HEADER>(localMappedImage, sectionHeadersOffset + (i * sectionSize));
                    bool isExecutable = (sec.Characteristics & 0x20000000) != 0;
                    if (isExecutable && sec.VirtualSize > 0)
                    {
                        IntPtr remoteSectionAddress = IntPtr.Add(moduleBase, (int)sec.VirtualAddress);
                        int sizeToCompare = Math.Min((int)sec.VirtualSize, (int)sec.SizeOfRawData);
                        if (sizeToCompare > 0 && (sec.VirtualAddress + sizeToCompare) <= localMappedImage.Length)
                        {
                            // SafeRead
                            byte[] remoteBytes = SafeRead(process, remoteSectionAddress, sizeToCompare);
                            if (remoteBytes == null) continue;

                            for (int k = 0; k < sizeToCompare; k++)
                            {
                                if (localMappedImage[sec.VirtualAddress + k] != remoteBytes[k])
                                {
                                    var hookInfo = AnalyzeHook(process, remoteBytes, k, IntPtr.Add(remoteSectionAddress, k), !is64Bit);
                                    if (hookInfo != null)
                                    {
                                        hookInfo.ModuleName = System.IO.Path.GetFileName(modulePath);
                                        hookInfo.SectionName = sec.Name;
                                        hookInfo.Offset = k;
                                        hookInfo.OriginalByte = localMappedImage[sec.VirtualAddress + k];
                                        hookInfo.PatchedByte = remoteBytes[k];
                                        hookInfo.TargetModule = ResolveTargetAddress(hookInfo.TargetAddress, process, modules, regions);
                                        hookInfo.IsSafe = IsSafeHookTarget(hookInfo.TargetModule, modules);
                                        results.Add(hookInfo);
                                        k += (hookInfo.HookSize - 1);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }
            return results;
        }

        private InlineHookInfo AnalyzeHook(ManagedProcess process, byte[] memBytes, int offset, IntPtr patchAddress, bool isWow64)
        {
            if (offset >= memBytes.Length)
            {
                return null;
            }

            byte op = memBytes[offset];

            try
            {
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

            return new InlineHookInfo
            {
                HookType = "UNKNOWN_PATCH",
                HookSize = 1,
                TargetAddress = IntPtr.Zero
            };
        }

        public string ResolveTargetAddress(IntPtr targetAddress,
                                            ManagedProcess process,
                                            List<ProcessModuleInfo> modules,
                                            List<VirtualMemoryRegion> regions)
        {
            if (targetAddress == IntPtr.Zero) return "N/A";
            long target = targetAddress.ToInt64();

            foreach (var mod in modules)
            {
                if (mod.DllBase == IntPtr.Zero || mod.SizeOfImage == 0) continue;

                long start = mod.DllBase.ToInt64();
                long end = start + mod.SizeOfImage;

                if (target >= start && target < end)
                {
                    string symbol = FindNearestExport(process, mod.DllBase, targetAddress);

                    if (!string.IsNullOrEmpty(symbol))
                    {
                        return $"{mod.BaseDllName}!{symbol}";
                    }

                    long offset = target - start;
                    return $"{mod.BaseDllName}+0x{offset:X}";
                }
            }

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

        private string FindNearestExport(ManagedProcess process, IntPtr moduleBase, IntPtr targetAddress)
        {
            try
            {
                var exports = BuildExportMap(process, moduleBase);

                string bestMatchName = "";
                long smallestDelta = long.MaxValue;
                long target = targetAddress.ToInt64();

                foreach (var kvp in exports)
                {
                    long funcAddr = kvp.Value.ToInt64();

                    if (target >= funcAddr)
                    {
                        long delta = target - funcAddr;
                        if (delta < smallestDelta)
                        {
                            smallestDelta = delta;
                            bestMatchName = kvp.Key;
                        }
                    }
                }

                if (!string.IsNullOrEmpty(bestMatchName))
                {
                    if (smallestDelta == 0)
                        return bestMatchName;
                    else
                        return $"{bestMatchName}+0x{smallestDelta:X}";
                }
            }
            catch
            {
            }
            return null;
        }

        public List<SuspiciousThreadInfo> CheckForSuspiciousThreads(
            List<ThreadInfo> threads,
            List<ProcessModuleInfo> modules,
            List<VirtualMemoryRegion> regions)
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
                    continue;
                }

                foreach (var region in regions)
                {
                    long regionStart = region.BaseAddress.ToInt64();
                    long regionEnd = regionStart + region.RegionSize;

                    if (threadStart >= regionStart && threadStart < regionEnd)
                    {
                        if (region.State == "Commit" &&
                            (region.Type == "Private" || region.Type == "Mapped") &&
                            (region.Protection.Contains("EXECUTE")))
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

        public List<SuspiciousMemoryRegionInfo> CheckForSuspiciousMemoryRegions(List<VirtualMemoryRegion> regions)
        {
            var results = new List<SuspiciousMemoryRegionInfo>();

            try
            {
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

        public List<FoundPeHeaderInfo> CheckDataRegionsForPeHeaders(ManagedProcess process, List<VirtualMemoryRegion> regions)
        {
            var results = new List<FoundPeHeaderInfo>();
            try
            {
                var privateRegions = regions
                    .Where(r => r.State == "Commit" && r.Type == "Private")
                    .ToList();

                foreach (var region in privateRegions)
                {
                    int bytesToRead = (int)Math.Min(region.RegionSize, 4096);
                    if (bytesToRead < 512) continue;

                    byte[] buffer;
                    try
                    {
                        buffer = process.ReadMemory(region.BaseAddress, bytesToRead);
                    }
                    catch
                    {
                        continue;
                    }
                    var familyInfo = MalwareFamilyDetector.ScanMemoryBlock(buffer, region.BaseAddress);
                    if (familyInfo != null)
                    {
                        results.Add(new FoundPeHeaderInfo
                        {
                            BaseAddress = region.BaseAddress,
                            RegionSize = region.RegionSize,
                            RegionType = region.Type,
                            RegionProtection = region.Protection,
                            Status = $"[FAMILY DETECTED] {familyInfo.FamilyName} ({familyInfo.Variant}) - {familyInfo.Details}",
                            RequiresHeaderReconstruction = true
                        });
                        goto NextRegion;
                    }
                    if (buffer[0] == 0x4D && buffer[1] == 0x5A)
                    {
                        int e_lfanew = BitConverter.ToInt32(buffer, 0x3C);
                        if (e_lfanew > 0 && e_lfanew < buffer.Length - 4)
                        {
                            if (buffer[e_lfanew] == 0x50 && buffer[e_lfanew + 1] == 0x45)
                            {
                                results.Add(new FoundPeHeaderInfo
                                {
                                    BaseAddress = region.BaseAddress,
                                    RegionSize = region.RegionSize,
                                    RegionType = region.Type,
                                    RegionProtection = region.Protection,
                                    Status = "Standard PE Header (MZ+PE)",
                                    RequiresHeaderReconstruction = false
                                });
                                continue;
                            }
                        }
                    }

                    for (int i = 0; i < bytesToRead - 24; i += 4)
                    {
                        if (buffer[i] == 0x50 && buffer[i + 1] == 0x45 && buffer[i + 2] == 0x00 && buffer[i + 3] == 0x00)
                        {
                            ushort machine = BitConverter.ToUInt16(buffer, i + 4);
                            if (machine == 0x014c || machine == 0x8664)
                            {
                                ushort sizeOpt = BitConverter.ToUInt16(buffer, i + 20);
                                if (sizeOpt > 0 && sizeOpt < 0xFF)
                                {
                                    byte[] fakeHeader = GenerateFakeDosHeader(i);

                                    results.Add(new FoundPeHeaderInfo
                                    {
                                        BaseAddress = region.BaseAddress,
                                        RegionSize = region.RegionSize,
                                        RegionType = region.Type,
                                        RegionProtection = region.Protection,
                                        Status = $"Stripped PE Header (Found NT sig at 0x{i:X})",
                                        RequiresHeaderReconstruction = true,
                                        SuggestedHeaderFix = fakeHeader
                                    });
                                    goto NextRegion;
                                }
                            }
                        }
                    }

                    if (CalculatePointerDensity(buffer, region.BaseAddress, region.RegionSize) > 0.85)
                    {
                        results.Add(new FoundPeHeaderInfo
                        {
                            BaseAddress = region.BaseAddress,
                            RegionSize = region.RegionSize,
                            RegionType = region.Type,
                            RegionProtection = region.Protection,
                            Status = "High Density of Internal Pointers (Shellcode Table / Data)",
                            RequiresHeaderReconstruction = false
                        });
                    }

                    NextRegion:;
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, "CheckDataRegionsForPeHeaders failed", ex);
            }
            return results;
        }

        private byte[] GenerateFakeDosHeader(int ntHeaderOffset)
        {
            byte[] dos = new byte[64];
            dos[0] = 0x4D;
            dos[1] = 0x5A;

            BitConverter.GetBytes(ntHeaderOffset).CopyTo(dos, 0x3C);

            return dos;
        }

        private double CalculatePointerDensity(byte[] buffer, IntPtr baseAddress, long regionSize)
        {
            int ptrSize = IntPtr.Size;
            long start = baseAddress.ToInt64();
            long end = start + regionSize;
            int validCount = 0;
            int totalCount = 0;

            for (int i = 0; i < buffer.Length - ptrSize; i += ptrSize)
            {
                long val;
                if (ptrSize == 8) val = BitConverter.ToInt64(buffer, i);
                else val = BitConverter.ToInt32(buffer, i);

                if (val >= start && val < end) validCount++;
                totalCount++;
            }

            if (totalCount == 0) return 0;
            return (double)validCount / totalCount;
        }

        private IntPtr ReadIntPtr(ManagedProcess process, IntPtr address, bool isWow64)
        {
            byte[] bytes = SafeRead(process, address, isWow64 ? 4 : 8);
            if (bytes == null) return IntPtr.Zero;
            return isWow64 ? (IntPtr)BitConverter.ToInt32(bytes, 0) : (IntPtr)BitConverter.ToInt64(bytes, 0);
        }

        private ulong ReadUIntPtr(ManagedProcess process, IntPtr address, bool isWow64)
        {
            int ptrSize = isWow64 ? 4 : 8;
            byte[] bytes = process.ReadMemory(address, ptrSize);
            return isWow64 ? (ulong)BitConverter.ToUInt32(bytes, 0) : (ulong)BitConverter.ToUInt64(bytes, 0);
        }

        private string GetImportName(ManagedProcess process, IntPtr moduleBase, uint originalFirstThunkRva, int thunkIndex, bool isWow64)
        {
            int ptrSize = isWow64 ? 4 : 8;
            IntPtr nameThunkAddr = IntPtr.Add(moduleBase, (int)originalFirstThunkRva + (thunkIndex * ptrSize));
            byte[] ptrBytes = SafeRead(process, nameThunkAddr, ptrSize);
            if (ptrBytes == null) return null;

            ulong nameRva = isWow64 ? BitConverter.ToUInt32(ptrBytes, 0) : BitConverter.ToUInt64(ptrBytes, 0);
            if ((nameRva & (isWow64 ? 0x8000000000000000 : 0x80000000)) != 0) return $"Ordinal {nameRva & 0xFFFF}";
            if (nameRva == 0 || nameRva > 0x10000000) return null;

            return ReadNullTerminatedString(process, IntPtr.Add(moduleBase, (int)nameRva + 2));
        }
        public List<string> CheckForModuleOverloading(ManagedProcess process, List<ProcessModuleInfo> modules)
        {
            var results = new List<string>();
            StringBuilder sb = new StringBuilder(1024);

            foreach (var mod in modules)
            {
                if (mod.DllBase == IntPtr.Zero) continue;

                string mappedPath = "";
                try
                {
                    uint len = GetMappedFileName(process.Handle, mod.DllBase, sb, 1024);
                    if (len > 0)
                    {
                        mappedPath = sb.ToString();
                        mappedPath = ConvertDevicePathToDosPath(mappedPath);
                    }
                }
                catch { continue; }

                string pebPath = mod.FullDllName;

                if (string.IsNullOrEmpty(mappedPath) || string.IsNullOrEmpty(pebPath)) continue;

                if (!string.Equals(mappedPath, pebPath, StringComparison.OrdinalIgnoreCase))
                {
                    if (System.IO.Path.GetFileName(mappedPath).ToLower() != System.IO.Path.GetFileName(pebPath).ToLower())
                    {
                        results.Add($"Overloading Detected: Module {mod.BaseDllName} maps to '{mappedPath}' but PEB says '{pebPath}'");
                    }
                }
                sb.Clear();
            }
            return results;
        }

        [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint GetMappedFileName(IntPtr hProcess, IntPtr lpv, StringBuilder lpFilename, int nSize);

        private string ConvertDevicePathToDosPath(string devicePath)
        {
            return devicePath;
        }

        private bool IsSafeHookTarget(string targetModulePath, List<ProcessModuleInfo> allModules)
        {
            if (string.IsNullOrEmpty(targetModulePath)) return false;

            string dllName = targetModulePath.Contains("!") ? targetModulePath.Split('!')[0] : targetModulePath;
            dllName = dllName.Split('+')[0].Trim();

            if (_signatureCache.TryGetValue(dllName, out bool cachedResult))
            {
                return cachedResult;
            }

            var targetMod = allModules.FirstOrDefault(m => m.BaseDllName.Equals(dllName, StringComparison.OrdinalIgnoreCase));
            if (targetMod == null)
            {
                _signatureCache[dllName] = false;
                return false;
            }

            try
            {
                var sig = SignatureVerifier.Verify(targetMod.FullDllName);
                bool isTrusted = sig.IsSigned && (
                    sig.SignerName.Contains("Microsoft") ||
                    sig.SignerName.Contains("Bitdefender") ||
                    sig.SignerName.Contains("Symantec") ||
                    sig.SignerName.Contains("McAfee") ||
                    sig.SignerName.Contains("CrowdStrike") ||
                    sig.SignerName.Contains("SentinelOne") ||
                    sig.SignerName.Contains("Kaspersky") ||
                    sig.SignerName.Contains("ESET") ||
                    sig.SignerName.Contains("Sophos")
                );

                _signatureCache[dllName] = isTrusted;
                return isTrusted;
            }
            catch
            {
                _signatureCache[dllName] = false;
                return false;
            }
        }
    }
}