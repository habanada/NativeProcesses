/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using NativeProcesses.Core.Engine;
using NativeProcesses.Core.Models;
using NativeProcesses.Core.Native;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NativeProcesses.Core.Inspection
{
    public class SecurityInspector
    {
        private IEngineLogger _logger;
        private static readonly ConcurrentDictionary<string, Dictionary<string, ExportEntry>> _globalExportCache
                    = new ConcurrentDictionary<string, Dictionary<string, ExportEntry>>(StringComparer.OrdinalIgnoreCase);

        private static readonly ConcurrentDictionary<string, bool> _signatureCache
            = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        public struct ExportEntry
        {
            public uint Rva;
            public string ForwarderString;
            public bool IsForwarder => !string.IsNullOrEmpty(ForwarderString);
        }
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
            public HookTrustLevel TrustLevel { get; set; }
            public string Signer { get; set; }
            public bool IsSafe { get; set; } // Legacy-Kompatibilität
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
        //public IntPtr GetExportAddress(ManagedProcess process, IntPtr moduleBase, string functionName, List<ProcessModuleInfo> allModules, string moduleNameForCache, int recursionDepth = 0)
        //{
        //    // Schutz vor Endlosschleifen (z.B. A->B->A Forwarding)
        //    if (recursionDepth > 10) return IntPtr.Zero;
        //    if (string.IsNullOrEmpty(moduleNameForCache)) return IntPtr.Zero;

        //    Dictionary<string, ExportEntry> map = null;

        //    // 1. Thread-Safe Cache Zugriff
        //    if (!_globalExportCache.TryGetValue(moduleNameForCache, out map))
        //    {
        //        var moduleInfo = allModules.FirstOrDefault(m => m.BaseDllName.Equals(moduleNameForCache, StringComparison.OrdinalIgnoreCase));
        //        // Fallback: Wenn FullDllName leer ist, versuchen wir ihn zu erraten (System32)
        //        string path = moduleInfo?.FullDllName;
        //        if (string.IsNullOrEmpty(path))
        //        {
        //            path = Path.Combine(Environment.SystemDirectory, moduleNameForCache);
        //            if (!path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) path += ".dll";
        //        }

        //        if (File.Exists(path))
        //        {
        //            map = BuildExportMapFromDisk(path);
        //            _globalExportCache.TryAdd(moduleNameForCache, map);
        //        }
        //    }

        //    if (map != null && map.TryGetValue(functionName, out ExportEntry entry))
        //    {
        //        if (entry.IsForwarder)
        //        {
        //            // Forwarder String parsen (Format: "DLLName.FunctionName" oder "DLLName.#Ordinal")
        //            string fwd = entry.ForwarderString;
        //            int dotIdx = fwd.IndexOf('.');
        //            if (dotIdx > 0)
        //            {
        //                string targetDllName = fwd.Substring(0, dotIdx);
        //                string targetFunc = fwd.Substring(dotIdx + 1);

        //                if (!targetDllName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
        //                    targetDllName += ".dll";

        //                var targetMod = allModules.FirstOrDefault(m => m.BaseDllName.Equals(targetDllName, StringComparison.OrdinalIgnoreCase));

        //                // Rekursion: Wir springen zur nächsten DLL
        //                if (targetMod != null)
        //                {
        //                    // WICHTIG: Wir rufen uns selbst auf mit der neuen DLL
        //                    return GetExportAddress(process, targetMod.DllBase, targetFunc, allModules, targetMod.BaseDllName, recursionDepth + 1);
        //                }
        //            }
        //            // Sackgasse (Modul nicht geladen) -> 0
        //            return IntPtr.Zero;
        //        }
        //        else
        //        {
        //            // Volltreffer: Echte Adresse berechnen
        //            return IntPtr.Add(moduleBase, (int)entry.Rva);
        //        }
        //    }

        //    return IntPtr.Zero;
        //}
        public IntPtr GetExportAddress(ManagedProcess process, IntPtr moduleBase, string functionName, List<ProcessModuleInfo> allModules, string moduleNameForCache, int recursionDepth = 0)
        {
            // Schutz vor Endlosschleifen (max 5 Hops bei Forwarding)
            if (recursionDepth > 5) return IntPtr.Zero;
            if (string.IsNullOrEmpty(moduleNameForCache)) return IntPtr.Zero;

            Dictionary<string, ExportEntry> map = null;

            // 1. Cache Lookup (Thread Safe)
            if (!_globalExportCache.TryGetValue(moduleNameForCache, out map))
            {
                var moduleInfo = allModules.FirstOrDefault(m => m.BaseDllName.Equals(moduleNameForCache, StringComparison.OrdinalIgnoreCase));
                // Versuchen, den Pfad zu finden, auch wenn wir nur den Namen haben (z.B. "kernelbase.dll" aus einem Forwarder String)
                string path = moduleInfo?.FullDllName;

                if (string.IsNullOrEmpty(path))
                {
                    // Fallback: Suche in System32
                    path = Path.Combine(Environment.SystemDirectory, moduleNameForCache);
                    if (!path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && !Path.HasExtension(path)) path += ".dll";
                }

                if (File.Exists(path))
                {
                    // Lade Golden Image von Platte (Forwarder-Aware!)
                    map = BuildExportMapFromDisk(path);
                    _globalExportCache.TryAdd(moduleNameForCache, map);
                }
            }

            if (map != null && map.TryGetValue(functionName, out ExportEntry entry))
            {
                if (entry.IsForwarder)
                {
                    // Forwarder String parsen (Format: "DLLName.FunctionName" oder "DLLName.#Ordinal")
                    // Beispiel: "NTDLL.RtlAllocateHeap"
                    string fwd = entry.ForwarderString;
                    int dotIdx = fwd.IndexOf('.');
                    if (dotIdx > 0)
                    {
                        string targetDllName = fwd.Substring(0, dotIdx);
                        string targetFunc = fwd.Substring(dotIdx + 1);

                        // Wenn keine Extension, .dll anhängen
                        if (!targetDllName.Contains(".")) targetDllName += ".dll";

                        var targetMod = allModules.FirstOrDefault(m => m.BaseDllName.Equals(targetDllName, StringComparison.OrdinalIgnoreCase));

                        // REKURSION: Wir springen zur nächsten DLL
                        if (targetMod != null)
                        {
                            // Wir rufen uns selbst auf, aber mit der NEUEN DllBase und dem NEUEN Namen
                            return GetExportAddress(process, targetMod.DllBase, targetFunc, allModules, targetMod.BaseDllName, recursionDepth + 1);
                        }
                    }
                    // Sackgasse (Modul nicht geladen) -> Wir können die Adresse nicht validieren -> 0
                    return IntPtr.Zero;
                }
                else
                {
                    // Kein Forwarder -> Das ist die echte Adresse (RVA + Base)
                    return IntPtr.Add(moduleBase, (int)entry.Rva);
                }
            }

            return IntPtr.Zero;
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
                bool is64 = (magic == PE.PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC);

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
        /// <summary>
        /// Baut die Export-Map direkt von der Festplatte ("Golden Image").
        /// Erkennt jetzt auch Forwarder Strings!
        /// </summary>
        public Dictionary<string, ExportEntry> BuildExportMapFromDisk(string modulePath)
        {
            var exportMap = new Dictionary<string, ExportEntry>(StringComparer.OrdinalIgnoreCase);
            byte[] image = MapFileToMemory(modulePath);

            if (image == null) return exportMap;

            try
            {
                int e_lfanew = BitConverter.ToInt32(image, 0x3C);
                // PE Header Parsing...
                ushort magic = BitConverter.ToUInt16(image, e_lfanew + 24);
                bool is64 = (magic == PE.PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC);
                int exportDirOffset = e_lfanew + 24 + (is64 ? 112 : 96);

                uint exportRva = BitConverter.ToUInt32(image, exportDirOffset);
                uint exportSize = BitConverter.ToUInt32(image, exportDirOffset + 4);

                if (exportRva == 0 || exportRva >= image.Length) return exportMap;

                int dirOffset = (int)exportRva;
                uint numberOfFunctions = BitConverter.ToUInt32(image, dirOffset + 20);
                uint numberOfNames = BitConverter.ToUInt32(image, dirOffset + 24);
                uint addressOfFunctions = BitConverter.ToUInt32(image, dirOffset + 28);
                uint addressOfNames = BitConverter.ToUInt32(image, dirOffset + 32);
                uint addressOfOrdinals = BitConverter.ToUInt32(image, dirOffset + 36);

                for (int i = 0; i < numberOfNames; i++)
                {
                    uint nameRva = BitConverter.ToUInt32(image, (int)addressOfNames + (i * 4));
                    if (nameRva == 0 || nameRva >= image.Length) continue;

                    string name = ReadStringFromBuffer(image, (int)nameRva);
                    if (string.IsNullOrEmpty(name)) continue;

                    ushort ordinal = BitConverter.ToUInt16(image, (int)addressOfOrdinals + (i * 2));
                    if (ordinal >= numberOfFunctions) continue;

                    uint funcRva = BitConverter.ToUInt32(image, (int)addressOfFunctions + (ordinal * 4));

                    // LOGIK: Wenn die Funktions-Adresse INNERHALB des Export-Verzeichnisses liegt, 
                    // ist es ein Forwarder-String, kein Code!
                    bool isForwarder = (funcRva >= exportRva && funcRva < (exportRva + exportSize));

                    var entry = new ExportEntry { Rva = funcRva };

                    if (isForwarder)
                    {
                        entry.ForwarderString = ReadStringFromBuffer(image, (int)funcRva);
                    }

                    if (!exportMap.ContainsKey(name))
                    {
                        exportMap[name] = entry;
                    }
                }
            }
            catch { }
            return exportMap;
        }
        // Kleiner Helper für lokales Lesen
        private string ReadStringFromBuffer(byte[] buffer, int offset)
        {
            int end = offset;
            while (end < buffer.Length && buffer[end] != 0) end++;
            return Encoding.ASCII.GetString(buffer, offset, end - offset);
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
                PE.PeHeaders.IMAGE_DOS_HEADER dosHeader;
                PE.PeHeaders.IMAGE_FILE_HEADER fileHeader;
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
                byte[] dosHeaderBytes = process.ReadMemory(moduleBase, Marshal.SizeOf(typeof(PE.PeHeaders.IMAGE_DOS_HEADER)));
                var dosHeader = ByteArrayToStructure<PE.PeHeaders.IMAGE_DOS_HEADER>(dosHeaderBytes);
                if (!dosHeader.IsValid)
                {
                    return IntPtr.Zero;
                }

                IntPtr ntHeaderAddr = IntPtr.Add(moduleBase, dosHeader.e_lfanew);
                byte[] ntHeaderMagicBytes = process.ReadMemory(IntPtr.Add(ntHeaderAddr, 4 + Marshal.SizeOf(typeof(PE.PeHeaders.IMAGE_FILE_HEADER))), sizeof(ushort));
                ushort magic = BitConverter.ToUInt16(ntHeaderMagicBytes, 0);

                PE.PeHeaders.IMAGE_DATA_DIRECTORY exportDirectory;

                if (magic == PE.PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    byte[] ntHeaderBytes = process.ReadMemory(ntHeaderAddr, Marshal.SizeOf(typeof(PE.PeHeaders.IMAGE_NT_HEADERS64)));
                    exportDirectory = ByteArrayToStructure<PE.PeHeaders.IMAGE_NT_HEADERS64>(ntHeaderBytes).OptionalHeader.DataDirectory[PE.PeHeaders.IMAGE_DIRECTORY_ENTRY_EXPORT];
                }
                else
                {
                    byte[] ntHeaderBytes = process.ReadMemory(ntHeaderAddr, Marshal.SizeOf(typeof(PE.PeHeaders.IMAGE_NT_HEADERS32)));
                    exportDirectory = ByteArrayToStructure<PE.PeHeaders.IMAGE_NT_HEADERS32>(ntHeaderBytes).OptionalHeader.DataDirectory[PE.PeHeaders.IMAGE_DIRECTORY_ENTRY_EXPORT];
                }

                if (exportDirectory.VirtualAddress == 0)
                {
                    return IntPtr.Zero;
                }

                IntPtr exportDirAddr = IntPtr.Add(moduleBase, (int)exportDirectory.VirtualAddress);
                var eat = ByteArrayToStructure<PE.PeHeaders.IMAGE_EXPORT_DIRECTORY>(process.ReadMemory(exportDirAddr, Marshal.SizeOf(typeof(PE.PeHeaders.IMAGE_EXPORT_DIRECTORY))));

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

        private PE.PeHeaders.IMAGE_SECTION_HEADER[] GetPeHeadersFromFile(string filePath, out PE.PeHeaders.IMAGE_DOS_HEADER dosHeader, out PE.PeHeaders.IMAGE_FILE_HEADER fileHeader, out ushort magic)
        {
            byte[] buffer = ReadBytesFromFile(filePath, 0, (uint)Marshal.SizeOf(typeof(PE.PeHeaders.IMAGE_DOS_HEADER)));
            dosHeader = ByteArrayToStructure<PE.PeHeaders.IMAGE_DOS_HEADER>(buffer);
            if (!dosHeader.IsValid)
            {
                throw new Exception($"Invalid DOS header for file {filePath}.");
            }

            buffer = ReadBytesFromFile(filePath, (uint)dosHeader.e_lfanew, sizeof(uint) + (uint)Marshal.SizeOf(typeof(PE.PeHeaders.IMAGE_FILE_HEADER)));
            fileHeader = ByteArrayToStructure<PE.PeHeaders.IMAGE_FILE_HEADER>(buffer, 4);

            int optionalHeaderOffset = dosHeader.e_lfanew + 4 + Marshal.SizeOf(typeof(PE.PeHeaders.IMAGE_FILE_HEADER));
            buffer = ReadBytesFromFile(filePath, (uint)optionalHeaderOffset, sizeof(ushort));
            magic = BitConverter.ToUInt16(buffer, 0);

            int sectionHeaderOffset = optionalHeaderOffset + fileHeader.SizeOfOptionalHeader;
            int sectionHeaderSize = Marshal.SizeOf(typeof(PE.PeHeaders.IMAGE_SECTION_HEADER));

            PE.PeHeaders.IMAGE_SECTION_HEADER[] sections = new PE.PeHeaders.IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            buffer = ReadBytesFromFile(filePath, (uint)sectionHeaderOffset, (uint)(sectionHeaderSize * fileHeader.NumberOfSections));

            for (int i = 0; i < fileHeader.NumberOfSections; i++)
            {
                byte[] sectionBytes = new byte[sectionHeaderSize];
                Array.Copy(buffer, i * sectionHeaderSize, sectionBytes, 0, sectionHeaderSize);
                sections[i] = ByteArrayToStructure<PE.PeHeaders.IMAGE_SECTION_HEADER>(sectionBytes);
            }
            return sections;
        }

        private PE.PeHeaders.IMAGE_SECTION_HEADER[] GetPeHeadersFromMemory(ManagedProcess process, IntPtr moduleBase, out PE.PeHeaders.IMAGE_DOS_HEADER dosHeader, out PE.PeHeaders.IMAGE_FILE_HEADER fileHeader, out ushort magic, out PE.PeHeaders.IMAGE_DATA_DIRECTORY relocDir)
        {
            byte[] buffer = process.ReadMemory(moduleBase, Marshal.SizeOf(typeof(PE.PeHeaders.IMAGE_DOS_HEADER)));
            dosHeader = ByteArrayToStructure<PE.PeHeaders.IMAGE_DOS_HEADER>(buffer);
            if (!dosHeader.IsValid)
            {
                throw new Exception($"Invalid DOS header in memory at {moduleBase.ToString("X")}.");
            }

            IntPtr ntHeaderAddr = IntPtr.Add(moduleBase, dosHeader.e_lfanew);
            buffer = process.ReadMemory(ntHeaderAddr, sizeof(uint) + Marshal.SizeOf(typeof(PE.PeHeaders.IMAGE_FILE_HEADER)));
            fileHeader = ByteArrayToStructure<PE.PeHeaders.IMAGE_FILE_HEADER>(buffer, 4);

            IntPtr optionalHeaderAddr = IntPtr.Add(ntHeaderAddr, 4 + Marshal.SizeOf(typeof(PE.PeHeaders.IMAGE_FILE_HEADER)));
            buffer = process.ReadMemory(optionalHeaderAddr, sizeof(ushort));
            magic = BitConverter.ToUInt16(buffer, 0);

            IntPtr sectionHeaderAddr = IntPtr.Add(optionalHeaderAddr, fileHeader.SizeOfOptionalHeader);
            int sectionHeaderSize = Marshal.SizeOf(typeof(PE.PeHeaders.IMAGE_SECTION_HEADER));

            PE.PeHeaders.IMAGE_SECTION_HEADER[] sections = new PE.PeHeaders.IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            buffer = process.ReadMemory(sectionHeaderAddr, sectionHeaderSize * fileHeader.NumberOfSections);

            for (int i = 0; i < fileHeader.NumberOfSections; i++)
            {
                byte[] sectionBytes = new byte[sectionHeaderSize];
                Array.Copy(buffer, i * sectionHeaderSize, sectionBytes, 0, sectionHeaderSize);
                sections[i] = ByteArrayToStructure<PE.PeHeaders.IMAGE_SECTION_HEADER>(sectionBytes);
            }

            relocDir = new PE.PeHeaders.IMAGE_DATA_DIRECTORY();
            if (magic == PE.PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                byte[] optHeaderBytes = process.ReadMemory(optionalHeaderAddr, Marshal.SizeOf<PE.PeHeaders.IMAGE_OPTIONAL_HEADER64>());
                var optHeader = ByteArrayToStructure<PE.PeHeaders.IMAGE_OPTIONAL_HEADER64>(optHeaderBytes);
                relocDir = optHeader.DataDirectory[PE.PeHeaders.IMAGE_DIRECTORY_ENTRY_BASERELOC];
            }
            else
            {
                byte[] optHeaderBytes = process.ReadMemory(optionalHeaderAddr, Marshal.SizeOf<PE.PeHeaders.IMAGE_OPTIONAL_HEADER32>());
                var optHeader = ByteArrayToStructure<PE.PeHeaders.IMAGE_OPTIONAL_HEADER32>(optHeaderBytes);
                relocDir = optHeader.DataDirectory[PE.PeHeaders.IMAGE_DIRECTORY_ENTRY_BASERELOC];
            }

            return sections;
        }

        private HashSet<uint> ParseRelocations(ManagedProcess process, IntPtr moduleBase, PE.PeHeaders.IMAGE_DATA_DIRECTORY relocDir, bool isWow64)
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
                int relocBlockSize = Marshal.SizeOf(typeof(PE.PeHeaders.IMAGE_BASE_RELOCATION));

                while (currentRelocAddr.ToInt64() < relocEndAddr.ToInt64())
                {
                    byte[] blockHeaderBytes = process.ReadMemory(currentRelocAddr, relocBlockSize);
                    var relocBlock = ByteArrayToStructure<PE.PeHeaders.IMAGE_BASE_RELOCATION>(blockHeaderBytes);

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

                        if (type == PE.PeHeaders.IMAGE_REL_BASED_DIR64 || type == PE.PeHeaders.IMAGE_REL_BASED_HIGHLOW)
                        {
                            uint relocRva = relocBlock.VirtualAddress + offset;
                            relocOffsets.Add(relocRva);

                            int ptrSize = (type == PE.PeHeaders.IMAGE_REL_BASED_DIR64) ? 8 : 4;
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
        //        byte[] dosHeaderBytes = process.ReadMemory(moduleBase, Marshal.SizeOf(typeof(PE.PeHeaders.IMAGE_DOS_HEADER)));
        //        var dosHeader = ByteArrayToStructure<PE.PeHeaders.IMAGE_DOS_HEADER>(dosHeaderBytes);
        //        if (!dosHeader.IsValid) return exportMap;

        //        IntPtr ntHeaderAddr = IntPtr.Add(moduleBase, dosHeader.e_lfanew);
        //        byte[] ntHeaderMagicBytes = process.ReadMemory(IntPtr.Add(ntHeaderAddr, 4 + Marshal.SizeOf(typeof(PE.PeHeaders.IMAGE_FILE_HEADER))), sizeof(ushort));
        //        ushort magic = BitConverter.ToUInt16(ntHeaderMagicBytes, 0);

        //        PE.PeHeaders.IMAGE_DATA_DIRECTORY exportDirectory;
        //        if (magic == PE.PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        //        {
        //            byte[] ntHeaderBytes = process.ReadMemory(ntHeaderAddr, Marshal.SizeOf(typeof(PE.PeHeaders.IMAGE_NT_HEADERS64)));
        //            exportDirectory = ByteArrayToStructure<PE.PeHeaders.IMAGE_NT_HEADERS64>(ntHeaderBytes).OptionalHeader.DataDirectory[PE.PeHeaders.IMAGE_DIRECTORY_ENTRY_EXPORT];
        //        }
        //        else
        //        {
        //            byte[] ntHeaderBytes = process.ReadMemory(ntHeaderAddr, Marshal.SizeOf(typeof(PE.PeHeaders.IMAGE_NT_HEADERS32)));
        //            exportDirectory = ByteArrayToStructure<PE.PeHeaders.IMAGE_NT_HEADERS32>(ntHeaderBytes).OptionalHeader.DataDirectory[PE.PeHeaders.IMAGE_DIRECTORY_ENTRY_EXPORT];
        //        }

        //        if (exportDirectory.VirtualAddress == 0) return exportMap;

        //        IntPtr exportDirAddr = IntPtr.Add(moduleBase, (int)exportDirectory.VirtualAddress);
        //        var eat = ByteArrayToStructure<PE.PeHeaders.IMAGE_EXPORT_DIRECTORY>(process.ReadMemory(exportDirAddr, Marshal.SizeOf(typeof(PE.PeHeaders.IMAGE_EXPORT_DIRECTORY))));

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
        private PE.PeHeaders.IMAGE_SECTION_HEADER FindSection(PE.PeHeaders.IMAGE_SECTION_HEADER[] sections, string sectionName)
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
        public List<InlineHookInfo> CheckForInlineHooks(ManagedProcess process, IntPtr moduleBase, string modulePath, List<ProcessModuleInfo> modules, List<VirtualMemoryRegion> regions)
        {
            var results = new List<InlineHookInfo>();
            if (string.IsNullOrEmpty(modulePath) || !File.Exists(modulePath)) return results;

            try
            {
                byte[] diskImage = PeEmulation.MapAndRelocate(modulePath, moduleBase);
                if (diskImage == null) return results;

                var dosHeader = ByteArrayToStructure<PE.PeHeaders.IMAGE_DOS_HEADER>(diskImage);
                int ntOffset = dosHeader.e_lfanew;

                ushort magic = BitConverter.ToUInt16(diskImage, ntOffset + 24);
                bool is64Bit = (magic == PE.PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC);

                uint sizeOfImage = is64Bit
                    ? BitConverter.ToUInt32(diskImage, ntOffset + 24 + 56)
                    : BitConverter.ToUInt32(diskImage, ntOffset + 24 + 56);

                long moduleStart = moduleBase.ToInt64();
                long moduleEnd = moduleStart + sizeOfImage;

                ushort numSections = BitConverter.ToUInt16(diskImage, ntOffset + 6);
                ushort sizeOptHeader = BitConverter.ToUInt16(diskImage, ntOffset + 20);
                int sectionStart = ntOffset + 24 + sizeOptHeader;
                int sectionSize = 40;

                // 1. Relocations parsen
                HashSet<uint> relocationRvas = new HashSet<uint>();
                int dataDirOffset = is64Bit ? 112 : 96;
                int relocDirOffset = ntOffset + 24 + dataDirOffset + (5 * 8);
                uint relocAddr = BitConverter.ToUInt32(diskImage, relocDirOffset);
                uint relocSize = BitConverter.ToUInt32(diskImage, relocDirOffset + 4);

                if (relocAddr > 0 && relocSize > 0 && relocAddr + relocSize <= diskImage.Length)
                {
                    uint currentPos = 0;
                    while (currentPos < relocSize)
                    {
                        uint blockRva = BitConverter.ToUInt32(diskImage, (int)(relocAddr + currentPos));
                        uint blockSize = BitConverter.ToUInt32(diskImage, (int)(relocAddr + currentPos + 4));
                        if (blockSize == 0) break;
                        int entryCount = (int)(blockSize - 8) / 2;
                        for (int i = 0; i < entryCount; i++)
                        {
                            ushort entry = BitConverter.ToUInt16(diskImage, (int)(relocAddr + currentPos + 8 + (i * 2)));
                            ushort type = (ushort)(entry >> 12);
                            int offset = entry & 0x0FFF;
                            if (type == 3 || type == 10)
                            {
                                uint rvaToSkip = blockRva + (uint)offset;
                                int bytesToSkip = (type == 10) ? 8 : 4;
                                for (int b = 0; b < bytesToSkip; b++) relocationRvas.Add(rvaToSkip + (uint)b);
                            }
                        }
                        currentPos += blockSize;
                    }
                }

                for (int i = 0; i < numSections; i++)
                {
                    if (results.Count > 50)
                    {
                        results.Clear();
                        results.Add(new InlineHookInfo
                        {
                            ModuleName = Path.GetFileName(modulePath),
                            HookType = "High Anomaly Count (Packed?)",
                            IsSafe = false,
                            TargetModule = "Analysis Aborted",
                            TargetAddress = IntPtr.Zero
                        });
                        return results;
                    }

                    var sec = ByteArrayToStructure<PE.PeHeaders.IMAGE_SECTION_HEADER>(diskImage, sectionStart + (i * sectionSize));

                    bool isExecutable = (sec.Characteristics & 0x20000000) != 0;
                    bool isWritable = (sec.Characteristics & 0x80000000) != 0;

                    if (isExecutable && !isWritable && sec.VirtualSize > 0)
                    {
                        byte[] memBytes = SafeRead(process, IntPtr.Add(moduleBase, (int)sec.VirtualAddress), (int)sec.VirtualSize);
                        if (memBytes == null) continue;

                        int compareLen = Math.Min(memBytes.Length, (int)sec.SizeOfRawData);

                        for (int k = 0; k < compareLen; k++)
                        {
                            int rva = (int)sec.VirtualAddress + k;

                            if (relocationRvas.Contains((uint)rva)) continue;
                            if (diskImage[rva] == 0xCC || diskImage[rva] == 0x00 || diskImage[rva] == 0x90) continue;

                            if (memBytes[k] != diskImage[rva])
                            {
                                // --- NEU: Expliziter Filter für E8->E9 Thunks (Everything.exe Fix) ---
                                // Wenn auf Disk ein CALL (E8) ist und im RAM ein JMP (E9), ist das ein Linker-Fixup.
                                if (diskImage[rva] == 0xE8 && memBytes[k] == 0xE9)
                                {
                                    continue; // Ignorieren!
                                }
                                // ---------------------------------------------------------------------

                                byte opcode = memBytes[k];
                                // Nur relevante Opcodes prüfen
                                bool isLikelyHook = (opcode == 0xE9 || opcode == 0xE8 || opcode == 0xFF || opcode == 0x68 || opcode == 0xEB);

                                if (!isLikelyHook) continue;

                                var hook = AnalyzeHook(process, memBytes, k, IntPtr.Add(moduleBase, rva), !is64Bit);

                                if (hook != null)
                                {
                                    long targetVal = hook.TargetAddress.ToInt64();
                                    if (targetVal == 0) continue;

                                    // Range Check (wie gehabt)
                                    if (targetVal >= moduleStart && targetVal < moduleEnd)
                                    {
                                        k += (hook.HookSize - 1);
                                        continue;
                                    }

                                    hook.ModuleName = Path.GetFileName(modulePath);
                                    hook.SectionName = sec.Name;
                                    hook.Offset = k;
                                    hook.OriginalByte = diskImage[rva];
                                    hook.PatchedByte = memBytes[k];
                                    hook.TargetModule = ResolveTargetAddress(hook.TargetAddress, process, modules, regions);
                                    hook.IsSafe = IsSafeHookTarget(hook.TargetModule, modules);

                                    results.Add(hook);
                                    k += (hook.HookSize - 1);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, $"InlineHook check failed: {ex.Message}");
            }
            return results;
        }
        private InlineHookInfo AnalyzeHook(ManagedProcess process, byte[] bytes, int offset, IntPtr currentAddr, bool isWow64)
        {
            if (offset >= bytes.Length) return null;
            byte op = bytes[offset];

            // Wir unterstützen hier die wichtigsten Opcodes für Hooks
            // 0xE9 = JMP Rel32
            // 0xE8 = CALL Rel32 (oft für Trampolines genutzt)
            // 0xEB = JMP Rel8 (Short Jump)

            if (op == 0xE9 || op == 0xE8)
            {
                if (offset + 4 >= bytes.Length) return null;
                int rel = BitConverter.ToInt32(bytes, offset + 1);
                IntPtr target = IntPtr.Add(currentAddr, 5 + rel);
                string type = op == 0xE9 ? "JMP (Rel32)" : "CALL (Rel32)";
                return new InlineHookInfo { HookType = type, HookSize = 5, TargetAddress = target };
            }

            if (op == 0xEB) // JMP Short
            {
                if (offset + 1 >= bytes.Length) return null;
                sbyte rel = (sbyte)bytes[offset + 1];
                IntPtr target = IntPtr.Add(currentAddr, 2 + rel);
                return new InlineHookInfo { HookType = "JMP (Short)", HookSize = 2, TargetAddress = target };
            }

            // Absolute Jumps (x86/x64 Indirect)
            if (op == 0xFF && offset + 1 < bytes.Length)
            {
                byte sub = bytes[offset + 1];
                if (sub == 0x25) // JMP [RIP+...] (x64) oder JMP [Addr] (x86)
                {
                    // Adressberechnung erfordert Lesen des Pointers, das sparen wir hier für Performance
                    // Wir geben einfach zurück DASS es ein JMP ist, aber Target 0.
                    // Im Loop oben wird Target 0 ignoriert, was korrekt ist, da wir indirekte Sprünge schwer validieren können ohne Pointer-Read.
                    // (Hier könnte man noch ReadMemory einbauen, wenn man *sehr* genau sein will)
                    return new InlineHookInfo { HookType = "JMP Indirect", HookSize = 6, TargetAddress = IntPtr.Zero };
                }
            }

            if (op == 0x68 && isWow64) // PUSH Imm32
            {
                if (offset + 5 >= bytes.Length) return null;
                uint addr = BitConverter.ToUInt32(bytes, offset + 1);
                return new InlineHookInfo { HookType = "PUSH", HookSize = 5, TargetAddress = (IntPtr)addr };
            }

            if (!isWow64 && op == 0x48 && offset + 2 < bytes.Length && bytes[offset + 1] == 0xB8) // MOV RAX, Imm64
            {
                if (offset + 10 >= bytes.Length) return null;
                long addr = BitConverter.ToInt64(bytes, offset + 2);
                return new InlineHookInfo { HookType = "MOV RAX", HookSize = 10, TargetAddress = (IntPtr)addr };
            }

            return null;
        }
        public string ResolveTargetAddress(IntPtr targetAddress, ManagedProcess process, List<ProcessModuleInfo> modules, List<VirtualMemoryRegion> regions)
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
                    string flags = region.Protection;
                    if (region.Type == "Private") return $"PRIVATE_MEMORY ({flags})";
                    if (region.Type == "Mapped") return $"Mapped Memory ({flags})";
                    return $"{region.Type} ({flags})";
                }
            }

            return "Unbacked / Unknown Memory";
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
            try
            {
                int ptrSize = isWow64 ? 4 : 8;
                // Adresse des Eintrags in der Import Name Table (INT)
                IntPtr nameThunkAddr = IntPtr.Add(moduleBase, (int)originalFirstThunkRva + (thunkIndex * ptrSize));

                byte[] ptrBytes = SafeRead(process, nameThunkAddr, ptrSize);
                if (ptrBytes == null) return null;

                ulong nameRvaVal = isWow64 ? BitConverter.ToUInt32(ptrBytes, 0) : BitConverter.ToUInt64(ptrBytes, 0);

                // Check auf Ordinal Import (High Bit gesetzt)
                // 32-Bit: 0x80000000, 64-Bit: 0x8000000000000000
                bool isOrdinal = isWow64
                    ? (nameRvaVal & 0x80000000) != 0
                    : (nameRvaVal & 0x8000000000000000) != 0;

                if (isOrdinal)
                {
                    return $"#{nameRvaVal & 0xFFFF}"; // Import by Ordinal
                }

                if (nameRvaVal == 0 || nameRvaVal > 0x7FFFFFFF) return null; // Invalid RVA

                // Name RVA lesen (IMAGE_IMPORT_BY_NAME Struktur: Hint(2) + Name)
                // Wir addieren 2 Bytes, um den "Hint" zu überspringen und direkt zum String zu kommen.
                return ReadNullTerminatedString(process, IntPtr.Add(moduleBase, (int)nameRvaVal + 2));
            }
            catch
            {
                return "[Error]";
            }
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

        public bool IsSafeHookTarget(string targetModuleInfo, List<ProcessModuleInfo> allModules)
        {
            if (string.IsNullOrEmpty(targetModuleInfo)) return false;

            // Extrahiere den DLL-Namen (z.B. aus "antivirus.dll!ScanFunction")
            string dllName = targetModuleInfo.Split('!')[0].Trim(); // Alles vor dem "!"
            dllName = dllName.Split('+')[0].Trim(); // Alles vor dem Offset "+"

            // Wenn es keine DLL ist (z.B. "Private Memory"), ist es nie sicher!
            if (dllName.Contains("Private") || dllName.Contains("Unbacked")) return false;

            // Cache Check
            if (_signatureCache.TryGetValue(dllName, out bool isTrusted))
            {
                return isTrusted;
            }

            // Modul in der Liste suchen
            var module = allModules.FirstOrDefault(m => m.BaseDllName.Equals(dllName, StringComparison.OrdinalIgnoreCase));
            if (module == null)
            {
                // DLL nicht gefunden -> Unsicher
                _signatureCache.TryAdd(dllName, false);
                return false;
            }

            try
            {
                // Digitale Signatur prüfen
                var sigInfo = SignatureVerifier.Verify(module.FullDllName);

                if (!sigInfo.IsSigned)
                {
                    _signatureCache.TryAdd(dllName, false);
                    return false;
                }

                string signer = sigInfo.SignerName.ToLowerInvariant();

                // Whitelist bekannter Sicherheits-Vendors & Microsoft
                bool safe = signer.Contains("microsoft") ||
                            signer.Contains("windows") ||
                            signer.Contains("crowdstrike") ||
                            signer.Contains("bitdefender") ||
                            signer.Contains("symantec") ||
                            signer.Contains("mcafee") ||
                            signer.Contains("avast") ||
                            signer.Contains("eset") ||
                            signer.Contains("kaspersky") ||
                            signer.Contains("sentinel one") ||
                            signer.Contains("sophos") ||
                            signer.Contains("carbon black") ||
                            signer.Contains("cylance") ||
                            signer.Contains("trend micro");

                _signatureCache.TryAdd(dllName, safe);
                return safe;
            }
            catch
            {
                return false;
            }
        }        // --- NEU: Golden Image Helper ---

        /// <summary>
        /// Lädt eine DLL von der Festplatte und mappt sie manuell in ein Byte-Array,
        /// sodass RVA-Zugriffe funktionieren (ähnlich wie LoadLibrary, aber passiv).
        /// </summary>
        private byte[] MapFileToMemory(string filePath)
        {
            try
            {
                if (!System.IO.File.Exists(filePath)) return null;

                byte[] rawFile = System.IO.File.ReadAllBytes(filePath);

                // DOS Header prüfen
                if (rawFile.Length < 64 || rawFile[0] != 'M' || rawFile[1] != 'Z') return null;

                int e_lfanew = BitConverter.ToInt32(rawFile, 0x3C);
                if (e_lfanew >= rawFile.Length - 264) return null;

                // Optional Header für SizeOfImage lesen
                ushort magic = BitConverter.ToUInt16(rawFile, e_lfanew + 24);
                bool is64 = (magic == PE.PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC);
                int sizeOfImageOffset = e_lfanew + 24 + 56; // Offset in OptionalHeader

                uint sizeOfImage = BitConverter.ToUInt32(rawFile, sizeOfImageOffset);

                // Virtuellen Speicher simulieren
                byte[] virtualImage = new byte[sizeOfImage];

                // Header kopieren (SizeOfHeaders steht an Offset 60 im Optional Header)
                uint sizeOfHeaders = BitConverter.ToUInt32(rawFile, e_lfanew + 24 + 60);
                Array.Copy(rawFile, 0, virtualImage, 0, Math.Min(rawFile.Length, sizeOfHeaders));

                // Sektionen mappen
                ushort numberOfSections = BitConverter.ToUInt16(rawFile, e_lfanew + 6);
                ushort sizeOfOptionalHeader = BitConverter.ToUInt16(rawFile, e_lfanew + 20);
                int sectionHeaderStart = e_lfanew + 24 + sizeOfOptionalHeader;
                int sectionSize = 40; // IMAGE_SECTION_HEADER size

                for (int i = 0; i < numberOfSections; i++)
                {
                    int entryOffset = sectionHeaderStart + (i * sectionSize);

                    uint virtualAddress = BitConverter.ToUInt32(rawFile, entryOffset + 12);
                    uint sizeOfRawData = BitConverter.ToUInt32(rawFile, entryOffset + 16);
                    uint pointerToRawData = BitConverter.ToUInt32(rawFile, entryOffset + 20);

                    if (pointerToRawData > 0 && sizeOfRawData > 0 &&
                        (pointerToRawData + sizeOfRawData) <= rawFile.Length &&
                        (virtualAddress + sizeOfRawData) <= virtualImage.Length)
                    {
                        Array.Copy(rawFile, (int)pointerToRawData, virtualImage, (int)virtualAddress, (int)sizeOfRawData);
                    }
                }

                return virtualImage;
            }
            catch
            {
                return null;
            }
        }
    }
}