using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using NativeProcesses.Core.Engine;
using NativeProcesses.Core.Models;
using NativeProcesses.Core.Native;
using NativeProcesses.Core.PE;
using NativeProcesses.Core.PE.Loader;

namespace NativeProcesses.Core.Inspection
{
    public enum HookType
    {
        None,
        JmpRel32,   // E9
        CallRel32,  // E8
        JmpShort,   // EB
        JmpIndirect, // FF 25 ...
        PushRet,    // 68 ... C3 (x86)
        MovRaxJmp   // 48 B8 ... FF E0 (x64)
    }

    public class PeAnomalyScanner
    {
        private readonly IEngineLogger _logger;

        public PeAnomalyScanner(IEngineLogger logger)
        {
            _logger = logger;
        }
        private HookType IdentifyHook(byte[] memory, int offset, bool is64Bit, out int hookSize, out long targetAddress)
        {
            hookSize = 0;
            targetAddress = 0;

            if (offset >= memory.Length) return HookType.None;
            byte op = memory[offset];

            // 1. E9 / E8 (Relative Jumps/Calls - 5 Bytes)
            if (op == 0xE9 || op == 0xE8)
            {
                if (offset + 5 > memory.Length) return HookType.None;
                int relOffset = BitConverter.ToInt32(memory, offset + 1);
                // Target = CurrentAddr + 5 + Relative
                // Da wir relative Offsets im Buffer haben, ist das etwas komplexer zu mappen, 
                // aber für die Erkennung reicht, DASS es ein Jump ist.
                hookSize = 5;
                return (op == 0xE9) ? HookType.JmpRel32 : HookType.CallRel32;
            }

            // 2. FF 25 (JMP Absolute Indirect - 6 Bytes)
            if (op == 0xFF && offset + 1 < memory.Length && memory[offset + 1] == 0x25)
            {
                hookSize = 6;
                return HookType.JmpIndirect;
            }

            // 3. EB (Short Jump - 2 Bytes)
            if (op == 0xEB)
            {
                hookSize = 2;
                return HookType.JmpShort;
            }

            // 4. MOV RAX, IMM64; JMP RAX (x64 Trampoline - 12 Bytes)
            if (is64Bit && op == 0x48 && offset + 1 < memory.Length && memory[offset + 1] == 0xB8)
            {
                // Check auf JMP RAX (FF E0) am Ende
                if (offset + 12 <= memory.Length)
                {
                    if (memory[offset + 10] == 0xFF && memory[offset + 11] == 0xE0)
                    {
                        hookSize = 12;
                        targetAddress = BitConverter.ToInt64(memory, offset + 2);
                        return HookType.MovRaxJmp;
                    }
                }
            }

            return HookType.None;
        }
        private bool Is64BitPe(byte[] peBuffer)
        {
            if (peBuffer.Length < 512) return false; // Zu klein

            // 1. DOS Header: e_lfanew lesen (Offset 0x3C)
            int e_lfanew = BitConverter.ToInt32(peBuffer, 0x3C);

            // Safety check
            if (e_lfanew > peBuffer.Length - 256) return false;

            // 2. Optional Header Magic lesen
            // NT Header Start = e_lfanew
            // Signature (4 bytes) + FileHeader (20 bytes) = 24 bytes Offset bis zum OptionalHeader
            int optHeaderOffset = e_lfanew + 24;

            ushort magic = BitConverter.ToUInt16(peBuffer, optHeaderOffset);

            // 0x20B ist PE32+ (64-Bit)
            return magic == PE.PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        }
        private bool IsDotNetModule(byte[] peBuffer)
        {
            try
            {
                if (peBuffer.Length < 512) return false;

                // 1. DOS Header: e_lfanew lesen (Offset 0x3C)
                int e_lfanew = BitConverter.ToInt32(peBuffer, 0x3C);
                if (e_lfanew > peBuffer.Length - 256) return false;

                // 2. Optional Header Start finden
                // NT Signature (4 bytes) + FileHeader (20 bytes) = 24 bytes
                int optHeaderOffset = e_lfanew + 24;

                // 3. Magic prüfen (32 vs 64 Bit) um Offset zum DataDirectory zu finden
                ushort magic = BitConverter.ToUInt16(peBuffer, optHeaderOffset);

                // Offset zum DataDirectory-Array im Optional Header:
                // 32-Bit (0x10B): 96 Bytes Standard-Felder
                // 64-Bit (0x20B): 112 Bytes Standard-Felder
                int dataDirArrayOffset = (magic == PE.PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC) ? 112 : 96;

                // 4. Zum COM Descriptor (Index 14) springen
                // IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14
                // Jeder Eintrag ist 8 Bytes lang (VirtualAddress + Size)
                int comDirOffset = optHeaderOffset + dataDirArrayOffset + (14 * 8);

                if (comDirOffset + 8 > peBuffer.Length) return false;

                // 5. Prüfen, ob Adresse und Größe != 0 sind
                uint rva = BitConverter.ToUInt32(peBuffer, comDirOffset);
                uint size = BitConverter.ToUInt32(peBuffer, comDirOffset + 4);

                return rva != 0 && size != 0;
            }
            catch
            {
                return false;
            }
        }
        public List<PeAnomalyInfo> ScanModule2(ManagedProcess process, ProcessModuleInfo module)
        {
            var anomalies = new List<PeAnomalyInfo>();

            // CASE 2 & 3: Datei existiert nicht mehr auf Disk oder ist unzugänglich
            if (string.IsNullOrEmpty(module.FullDllName) || !File.Exists(module.FullDllName))
            {
                anomalies.Add(new PeAnomalyInfo
                {
                    ModuleName = module.BaseDllName,
                    AnomalyType = "Unreachable File / Missing Backing File",
                    Details = $"The module '{module.BaseDllName}' is loaded in memory at 0x{module.DllBase:X}, but the file on disk ({module.FullDllName}) cannot be accessed or does not exist. Typical for Reflective Injection or Deleted Malware.",
                    Severity = "High"
                });

                // Wir können ohne Datei keinen Byte-Vergleich machen, also brechen wir hier ab.
                // Aber wir haben den kritischen Befund gemeldet!
                return anomalies;
            }

            try
            {
                // 1. Golden Image laden (Disk -> Virtual)
                byte[] rawFile = File.ReadAllBytes(module.FullDllName);
                byte[] localImage = PeLoader.MapRawToVirtual(rawFile);
                if (localImage == null) return anomalies;

                // 2. Relocations anwenden (auf lokale Kopie)
                // Wir simulieren, dass die Datei an der Adresse geladen wurde, wo sie im Prozess liegt.
                if (!RelocationsFixer.ApplyRelocations(localImage, (ulong)module.DllBase.ToInt64()))
                {
                    // Relocs failed (vielleicht stripped). Wir machen weiter.
                }

                // 3. Remote Speicher lesen
                byte[] remoteImage = process.ReadMemory(module.DllBase, localImage.Length);
                if (remoteImage == null || remoteImage.Length < 512) return anomalies;
                bool isDotNet = IsDotNetModule(localImage); // <--- HIER DER AUFRUF
                bool is64Bit = Is64BitPe(localImage); // Deine existierende Methode

                // 4. Header Scan (Stomping)
                // 1. Normalisierung
                NormalizeHeaders(localImage, is64Bit);
                NormalizeHeaders(remoteImage, is64Bit);

                // 2. Detaillierter Vergleich
                var anomaly = CompareHeaders(localImage, remoteImage, isDotNet); // Du musst IsDotNet Info durchreichen

                if (anomaly != HeaderAnomalyType.None)
                {
                    var info = new PeAnomalyInfo { ModuleName = module.BaseDllName };

                    switch (anomaly)
                    {
                        case HeaderAnomalyType.DosHeaderModified:
                            info.AnomalyType = "Header Stomping (DOS)";
                            info.Severity = "High";
                            break;
                        case HeaderAnomalyType.EntryPointModified:
                            // Das ist oft Malware (z.B. Hollowing wo nur EP umgebogen wurde)
                            info.AnomalyType = "Entry Point Modification";
                            info.Severity = "Critical";
                            break;
                            // ...
                    }
                    anomalies.Add(info);
                }

                // 5. Code Scan mit Exclusion Zones
                CheckSectionsWithExclusions(module, localImage, remoteImage, anomalies);
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, $"Scan failed for {module.BaseDllName}", ex);
            }

            return anomalies;
        }
        // Neue Signatur: Benötigt Memory Regions für den Structural Scan!
        public List<PeAnomalyInfo> ScanModule(ManagedProcess process, ProcessModuleInfo module, List<VirtualMemoryRegion> regions)
        {
            var anomalies = new List<PeAnomalyInfo>();

            if (string.IsNullOrEmpty(module.FullDllName) || !File.Exists(module.FullDllName))
                return anomalies;

            try
            {
                // 1. Golden Image laden
                byte[] rawFile = File.ReadAllBytes(module.FullDllName);
                byte[] localImage = PeLoader.MapRawToVirtual(rawFile);
                if (localImage == null) return anomalies;

                // Metadaten
                bool is64Bit = Is64BitPe(localImage);
                bool isDotNet = IsDotNetModule(localImage);

                // 2. Relocations
                if (!RelocationsFixer.ApplyRelocations(localImage, (ulong)module.DllBase.ToInt64())) { }

                // 3. Remote Image lesen
                byte[] remoteImage = process.ReadMemory(module.DllBase, localImage.Length);
                if (remoteImage == null || remoteImage.Length < 512) return anomalies;

                // 4. Header Scan (Stomping)
                byte[] localNorm = NormalizeHeaders(localImage, is64Bit);
                byte[] remoteNorm = NormalizeHeaders(remoteImage, is64Bit);
                var headerAnomaly = CompareHeaders(localNorm, remoteNorm, isDotNet);

                if (headerAnomaly != HeaderAnomalyType.None)
                {
                    // (Hier dein bestehender Code für Header Anomalies...)
                    anomalies.Add(new PeAnomalyInfo
                    {
                        ModuleName = module.BaseDllName,
                        AnomalyType = headerAnomaly.ToString(),
                        Severity = "High"
                    });
                }

                // --- NEU: 5. Structural Section Scan (PE-sieve Logic) ---
                // Prüft auf RWX, Overlaps und Memory-Expansion (Unpacking)
                var structAnomalies = ScanSectionStructure(module, localImage, regions);
                anomalies.AddRange(structAnomalies);

                // 6. Content Scan (Inline Hooks)
                // Wir übergeben die Liste der Anomalien, damit wir nicht doppelt scannen 
                // (z.B. wenn Structural Scan schon sagt "Critical", brauchen wir keinen Byte-Vergleich mehr)
                CheckSectionsContent(module, localImage, remoteImage, anomalies);
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, $"Scan failed for {module.BaseDllName}", ex);
            }

            return anomalies;
        }

        /// <summary>
        /// Implementiert PE-sieve Phase 2.2 bis 2.4: Validierung der Sektions-Struktur im Speicher.
        /// </summary>
        private List<PeAnomalyInfo> ScanSectionStructure(ProcessModuleInfo module, byte[] localImage, List<VirtualMemoryRegion> regions)
        {
            var results = new List<PeAnomalyInfo>();

            GCHandle handle = GCHandle.Alloc(localImage, GCHandleType.Pinned);
            try
            {
                IntPtr basePtr = handle.AddrOfPinnedObject();
                var dos = Marshal.PtrToStructure<PeHeaders.IMAGE_DOS_HEADER>(basePtr);
                if (!dos.IsValid) return results;

                IntPtr ntPtr = IntPtr.Add(basePtr, dos.e_lfanew);
                IntPtr fileHeaderPtr = IntPtr.Add(ntPtr, 4);
                var fileHeader = Marshal.PtrToStructure<PeHeaders.IMAGE_FILE_HEADER>(fileHeaderPtr);
                IntPtr optHeaderPtr = IntPtr.Add(fileHeaderPtr, Marshal.SizeOf<PeHeaders.IMAGE_FILE_HEADER>());
                ushort magic = (ushort)Marshal.ReadInt16(optHeaderPtr);

                int sectionHeadersOffset = dos.e_lfanew + 4 + Marshal.SizeOf<PeHeaders.IMAGE_FILE_HEADER>() + fileHeader.SizeOfOptionalHeader;
                int sectionSize = Marshal.SizeOf<PeHeaders.IMAGE_SECTION_HEADER>();

                uint prevSectionEnd = 0;

                for (int i = 0; i < fileHeader.NumberOfSections; i++)
                {
                    IntPtr secPtr = IntPtr.Add(basePtr, sectionHeadersOffset + (i * sectionSize));
                    var section = Marshal.PtrToStructure<PeHeaders.IMAGE_SECTION_HEADER>(secPtr);

                    // 1. Overlap Check
                    // PE-sieve: 2.3 Erkennung überlappender Sections
                    if (section.VirtualAddress < prevSectionEnd)
                    {
                        results.Add(new PeAnomalyInfo
                        {
                            ModuleName = module.BaseDllName,
                            AnomalyType = "Malformed PE (Overlapping Sections)",
                            Details = $"Section '{section.Name}' starts at 0x{section.VirtualAddress:X}, but previous ended at 0x{prevSectionEnd:X}.",
                            Severity = "High"
                        });
                    }

                    // VirtualSize vs RawSize Korrektur (wie Windows Loader)
                    uint virtualSize = section.VirtualSize;
                    if (virtualSize == 0) virtualSize = section.SizeOfRawData;

                    prevSectionEnd = section.VirtualAddress + virtualSize;

                    // 2. RWX Check (Characteristics)
                    // PE-sieve: Phase 3
                    bool isWrite = (section.Characteristics & 0x80000000) != 0;
                    bool isExec = (section.Characteristics & 0x20000000) != 0;

                    if (isWrite && isExec)
                    {
                        results.Add(new PeAnomalyInfo
                        {
                            ModuleName = module.BaseDllName,
                            AnomalyType = "RWX Section Permission",
                            Details = $"Section '{section.Name}' is Readable, Writable and Executable. Typical for unpackers or shellcode buffers.",
                            Severity = "High"
                        });
                    }

                    // 3. Real Memory Size Check
                    // PE-sieve: 2.2 Virtuelle Größe vs realer Speicherbereich
                    // Wir berechnen die absolute Adresse der Sektion im Prozess
                    long sectionAbsStart = module.DllBase.ToInt64() + section.VirtualAddress;

                    // Finde die VAD Region, die zu dieser Sektion gehört
                    var region = regions.FirstOrDefault(r =>
                        sectionAbsStart >= r.BaseAddress.ToInt64() &&
                        sectionAbsStart < (r.BaseAddress.ToInt64() + r.RegionSize));

                    if (region != null)
                    {
                        // Berechne die tatsächliche Größe der Region ab dem Sektionsstart
                        long offsetInRegion = sectionAbsStart - region.BaseAddress.ToInt64();
                        long realSizeAvailable = region.RegionSize - offsetInRegion;

                        // PE-sieve Logik: Wenn Memory > Header Größe (signifikant) -> Suspicious
                        // Wir geben etwas Toleranz (Page Alignment 4KB)
                        if (realSizeAvailable > (virtualSize + 0x2000))
                        {
                            // Filter: BSS Sektionen (.data?) wachsen oft legitim. Code (.text) nicht.
                            if (isExec)
                            {
                                results.Add(new PeAnomalyInfo
                                {
                                    ModuleName = module.BaseDllName,
                                    AnomalyType = "Memory Expansion (Unpacking)",
                                    Details = $"Section '{section.Name}' header size: {virtualSize:N0}, but mapped memory is {realSizeAvailable:N0}. Potential in-memory unpacking.",
                                    Severity = "Medium"
                                });
                            }
                        }
                    }
                }
            }
            finally
            {
                handle.Free();
            }

            return results;
        }
        private void CheckSectionsContent(ProcessModuleInfo module, byte[] local, byte[] remote, List<PeAnomalyInfo> anomalies)
        {
            // Dieser Teil entspricht deinem bisherigen "CheckSectionsWithExclusions"
            // Er wurde nur umbenannt, um logisch zu passen.
            // Der Inhalt bleibt identisch zu deiner vorherigen, korrekten Implementierung
            // (Inklusive .NET EntryPoint Skipping in CompareHeaders).

            // ... (Hier dein existierender Code für Byte-Vergleich) ...
            GCHandle handle = GCHandle.Alloc(local, GCHandleType.Pinned);
            try
            {
                IntPtr basePtr = handle.AddrOfPinnedObject();
                var dos = Marshal.PtrToStructure<PeHeaders.IMAGE_DOS_HEADER>(basePtr);
                if (!dos.IsValid) return;

                IntPtr ntPtr = IntPtr.Add(basePtr, dos.e_lfanew);
                IntPtr fileHeaderPtr = IntPtr.Add(ntPtr, 4);
                var fileHeader = Marshal.PtrToStructure<PeHeaders.IMAGE_FILE_HEADER>(fileHeaderPtr);
                IntPtr optHeaderPtr = IntPtr.Add(fileHeaderPtr, Marshal.SizeOf<PeHeaders.IMAGE_FILE_HEADER>());
                ushort magic = (ushort)Marshal.ReadInt16(optHeaderPtr);

                // --- EXCLUSION ZONES BERECHNEN ---
                // Wir ignorieren Bereiche, die sich legal ändern (IAT, Exports, etc.)
                var exclusions = GetExclusionRanges(optHeaderPtr, magic);

                int sectionHeadersOffset = dos.e_lfanew + 4 + Marshal.SizeOf<PeHeaders.IMAGE_FILE_HEADER>() + fileHeader.SizeOfOptionalHeader;
                int sectionSize = Marshal.SizeOf<PeHeaders.IMAGE_SECTION_HEADER>();

                for (int i = 0; i < fileHeader.NumberOfSections; i++)
                {
                    IntPtr secPtr = IntPtr.Add(basePtr, sectionHeadersOffset + (i * sectionSize));
                    var section = Marshal.PtrToStructure<PeHeaders.IMAGE_SECTION_HEADER>(secPtr);

                    // Wir scannen nur Executable Sektionen (.text) nach Patches
                    // Daten-Sektionen (.data) ändern sich ständig, das ist kein Hook.
                    bool isExecutable = (section.Characteristics & 0x20000000) != 0;
                    bool isWritable = (section.Characteristics & 0x80000000) != 0;

                    if (isExecutable)
                    {
                        int start = (int)section.VirtualAddress;
                        int size = (int)Math.Min(section.VirtualSize, section.SizeOfRawData);

                        if (start + size > local.Length || start + size > remote.Length) continue;

                        int diffCount = 0;

                        for (int k = 0; k < size; k++)
                        {
                            int rva = start + k;

                            // Liegt das Byte in einer ignorierten Zone?
                            if (IsInExclusionZone(rva, exclusions)) continue;

                            if (local[rva] != remote[rva])
                            {
                                diffCount++;
                            }
                        }

                        if (diffCount > 0)
                        {
                            string severity = isWritable ? "High" : "Medium";
                            if (diffCount > 50) severity = "Critical"; // Viele Änderungen -> Inline Hooking oder Patching

                            anomalies.Add(new PeAnomalyInfo
                            {
                                ModuleName = module.BaseDllName,
                                AnomalyType = "Code Patching / Inline Hooks",
                                Details = $"Found {diffCount} patched bytes in section '{section.Name}' (excluding volatile data).",
                                Severity = severity
                            });
                        }
                    }
                }
            }
            finally { handle.Free(); }
        }
        private void CheckSectionsWithExclusions(ProcessModuleInfo module, byte[] local, byte[] remote, List<PeAnomalyInfo> anomalies)
        {
            GCHandle handle = GCHandle.Alloc(local, GCHandleType.Pinned);
            try
            {
                IntPtr basePtr = handle.AddrOfPinnedObject();
                var dos = Marshal.PtrToStructure<PeHeaders.IMAGE_DOS_HEADER>(basePtr);
                if (!dos.IsValid) return;

                IntPtr ntPtr = IntPtr.Add(basePtr, dos.e_lfanew);
                IntPtr fileHeaderPtr = IntPtr.Add(ntPtr, 4);
                var fileHeader = Marshal.PtrToStructure<PeHeaders.IMAGE_FILE_HEADER>(fileHeaderPtr);
                IntPtr optHeaderPtr = IntPtr.Add(fileHeaderPtr, Marshal.SizeOf<PeHeaders.IMAGE_FILE_HEADER>());
                ushort magic = (ushort)Marshal.ReadInt16(optHeaderPtr);

                // --- EXCLUSION ZONES BERECHNEN ---
                // Wir ignorieren Bereiche, die sich legal ändern (IAT, Exports, etc.)
                var exclusions = GetExclusionRanges(optHeaderPtr, magic);

                int sectionHeadersOffset = dos.e_lfanew + 4 + Marshal.SizeOf<PeHeaders.IMAGE_FILE_HEADER>() + fileHeader.SizeOfOptionalHeader;
                int sectionSize = Marshal.SizeOf<PeHeaders.IMAGE_SECTION_HEADER>();

                for (int i = 0; i < fileHeader.NumberOfSections; i++)
                {
                    IntPtr secPtr = IntPtr.Add(basePtr, sectionHeadersOffset + (i * sectionSize));
                    var section = Marshal.PtrToStructure<PeHeaders.IMAGE_SECTION_HEADER>(secPtr);

                    // Wir scannen nur Executable Sektionen (.text) nach Patches
                    // Daten-Sektionen (.data) ändern sich ständig, das ist kein Hook.
                    bool isExecutable = (section.Characteristics & 0x20000000) != 0;
                    bool isWritable = (section.Characteristics & 0x80000000) != 0;

                    if (isExecutable)
                    {
                        int start = (int)section.VirtualAddress;
                        int size = (int)Math.Min(section.VirtualSize, section.SizeOfRawData);

                        if (start + size > local.Length || start + size > remote.Length) continue;

                        int diffCount = 0;
                        int hookCount = 0;

                        for (int k = 0; k < size; k++)
                        {
                            int rva = start + k;

                            // Ignorierte Bereiche überspringen
                            if (IsInExclusionZone(rva, exclusions)) continue;

                            // Everything.exe Fix (E8 -> E9 Thunks ignorieren, PE-sieve macht das auch)
                            if (local[rva] == 0xE8 && remote[rva] == 0xE9) continue;

                            if (local[rva] != remote[rva])
                            {
                                // Wenn wir einen Unterschied finden, prüfen wir, ob es ein Hook ist
                                var hookType = IdentifyHook(remote, rva, Is64BitPe(remote), out int hSize, out long target);

                                if (hookType != HookType.None)
                                {
                                    hookCount++;

                                    // Wir können hier detailliert berichten
                                    anomalies.Add(new PeAnomalyInfo
                                    {
                                        ModuleName = module.BaseDllName,
                                        AnomalyType = "Inline Hook Detected",
                                        Details = $"Found {hookType} at +0x{rva:X}. Original byte: {local[rva]:X2}, Patched: {remote[rva]:X2}",
                                        Severity = "Critical" // Hooks sind fast immer böse (oder AV)
                                    });

                                    // Den Rest des Hooks überspringen, um nicht jedes Byte einzeln zu melden
                                    if (hSize > 1) k += (hSize - 1);
                                }
                                else
                                {
                                    diffCount++;
                                }
                            }
                        }

                        if (diffCount > 0)
                        {
                            // Generische Patches (nicht als Hook erkannt)
                            string severity = isWritable ? "High" : "Medium";
                            if (diffCount > 50) severity = "Critical";

                            // Nur melden, wenn wir nicht schon Hooks gemeldet haben (um Spam zu vermeiden),
                            // oder wenn es SEHR viele sind.
                            if (hookCount == 0 || diffCount > 20)
                            {
                                anomalies.Add(new PeAnomalyInfo
                                {
                                    ModuleName = module.BaseDllName,
                                    AnomalyType = "Code Patching / Modification",
                                    Details = $"Found {diffCount} modified bytes in section '{section.Name}' (non-hook pattern).",
                                    Severity = severity
                                });
                            }
                        }
                    }
                }
            }
            finally { handle.Free(); }
        }

        private struct Range { public uint Start; public uint End; }

        private bool IsInExclusionZone(int rva, List<Range> exclusions)
        {
            foreach (var range in exclusions)
            {
                if (rva >= range.Start && rva < range.End) return true;
            }
            return false;
        }
        // In PeAnomalyScanner.cs
        private byte[] NormalizeHeaders(byte[] originalBuffer, bool is64Bit)
        {
            // Wir erstellen eine Kopie nur vom Header (erste 1024 Bytes reichen meist, oder SizeOfHeaders)
            // Hier nehmen wir vereinfacht die ersten 0x400 Bytes oder bis zur ersten Section.
            int headerSize = 0x400;
            if (headerSize > originalBuffer.Length) headerSize = originalBuffer.Length;

            byte[] buffer = new byte[headerSize];
            Array.Copy(originalBuffer, buffer, headerSize);

            int e_lfanew = BitConverter.ToInt32(buffer, 0x3C);
            int ntHeader = e_lfanew;
            int fileHeader = ntHeader + 4;
            int optHeader = fileHeader + 20;

            if (optHeader + 200 > buffer.Length) return buffer; // Safety

            // 1. CheckSum nullen (Offset 64 in OptHeader für 32&64 Bit gleich)
            Array.Clear(buffer, optHeader + 64, 4);

            // 2. Section Table bereinigen
            ushort sizeOfOptHeader = BitConverter.ToUInt16(buffer, fileHeader + 16);
            ushort numberOfSections = BitConverter.ToUInt16(buffer, fileHeader + 2);
            int sectionTableStart = optHeader + sizeOfOptHeader;
            int sectionEntrySize = 40;

            for (int i = 0; i < numberOfSections; i++)
            {
                int secOffset = sectionTableStart + (i * sectionEntrySize);
                if (secOffset + 40 > buffer.Length) break;

                // Offset 16: SizeOfRawData
                // Offset 20: PointerToRawData
                uint sizeRaw = BitConverter.ToUInt32(buffer, secOffset + 16);

                // Wenn SizeOfRawData 0 ist (BSS), ist der Pointer im RAM irrelevant -> Nullen
                if (sizeRaw == 0)
                {
                    Array.Clear(buffer, secOffset + 20, 4);
                }

                // PointerToRelocations (24) und PointerToLinenumbers (28) werden vom OS Loader oft genullt
                Array.Clear(buffer, secOffset + 24, 8);
            }

            return buffer;
        }
        //private void NormalizeHeaders(byte[] peBuffer, bool is64Bit)
        //{
        //    // PE-sieve: zeroUnusedFields
        //    // Im RAM ist PointerToRawData oft irrelevant oder 0, auf Disk aber gesetzt.
        //    // Wir nullen es in beiden Puffern (oder zumindest im lokalen), um False Positives zu vermeiden.

        //    int e_lfanew = BitConverter.ToInt32(peBuffer, 0x3C);
        //    int ntHeader = e_lfanew;
        //    int fileHeader = ntHeader + 4;

        //    // OptionalHeader beginnt nach FileHeader (20 Bytes)
        //    int optHeader = fileHeader + 20;
        //    ushort sizeOfOptHeader = BitConverter.ToUInt16(peBuffer, fileHeader + 16);
        //    ushort numberOfSections = BitConverter.ToUInt16(peBuffer, fileHeader + 2);

        //    int sectionTableStart = optHeader + sizeOfOptHeader;
        //    int sectionEntrySize = 40; // IMAGE_SECTION_HEADER size

        //    for (int i = 0; i < numberOfSections; i++)
        //    {
        //        int secOffset = sectionTableStart + (i * sectionEntrySize);

        //        // Offset 20 in SectionHeader ist PointerToRawData (DWORD)
        //        // Offset 16 ist SizeOfRawData (DWORD)

        //        // PE-sieve Logik: Wenn SizeOfRawData == 0, dann ist PointerToRawData egal -> Nullen.
        //        uint sizeRaw = BitConverter.ToUInt32(peBuffer, secOffset + 16);
        //        if (sizeRaw == 0)
        //        {
        //            // PointerToRawData (Offset 20) nullen
        //            Array.Clear(peBuffer, secOffset + 20, 4);
        //        }

        //        // Optional: Windows Loader nullt oft PointerToRelocations/Linenumbers im RAM
        //        // Offset 24 (Relocs), Offset 28 (Linenumbers)
        //        Array.Clear(peBuffer, secOffset + 24, 8);
        //    }

        //    // CheckSum im Optional Header (Offset 64) ist im RAM oft 0
        //    // Wir nullen es immer.
        //    Array.Clear(peBuffer, optHeader + 64, 4);
        //}

     

        private HeaderAnomalyType CompareHeaders(byte[] local, byte[] remote, bool isDotNet)
        {
            // 1. DOS Header Check
            // Vergleiche nur die ersten 64 Bytes (Standard DOS Header)
            if (!CompareBytes(local, remote, 0, 64)) return HeaderAnomalyType.DosHeaderModified;

            int e_lfanew = BitConverter.ToInt32(local, 0x3C);

            // 2. NT Signature Check
            if (BitConverter.ToUInt32(remote, e_lfanew) != 0x00004550) // PE\0\0
                return HeaderAnomalyType.NtSignatureMissing;

            // 3. File Header Check (20 Bytes nach Sig)
            // Hier prüfen wir Machine, NumberOfSections etc.
            if (!CompareBytes(local, remote, e_lfanew + 4, 20))
                return HeaderAnomalyType.FileHeaderModified;

            // 4. Optional Header Check
            // Hier wird es tricky. Wir müssen AddressOfEntryPoint separat behandeln.
            int optHeaderOffset = e_lfanew + 24;
            ushort sizeOfOpt = BitConverter.ToUInt16(local, e_lfanew + 4 + 16);

            // Kopien erstellen für Vergleich, um EntryPoint auszumaskieren
            byte[] localOpt = new byte[sizeOfOpt];
            byte[] remoteOpt = new byte[sizeOfOpt];
            Array.Copy(local, optHeaderOffset, localOpt, 0, sizeOfOpt);
            Array.Copy(remote, optHeaderOffset, remoteOpt, 0, sizeOfOpt);

            // .NET Filter für EntryPoint (Offset 16)
            if (isDotNet)
            {
                // Setze EntryPoint in beiden Kopien auf 0
                Array.Clear(localOpt, 16, 4);
                Array.Clear(remoteOpt, 16, 4);

                // Setze auch BaseAddress auf 0 (Offset 28 bei 32-bit, 24 bei 64-bit), da Relocations schon passiert sein sollten,
                // aber manchmal leichte Abweichungen existieren.
            }

            if (!localOpt.SequenceEqual(remoteOpt))
            {
                // Prüfen ob es NUR der EntryPoint war (falls nicht .NET)
                uint epLocal = BitConverter.ToUInt32(local, optHeaderOffset + 16);
                uint epRemote = BitConverter.ToUInt32(remote, optHeaderOffset + 16);

                if (epLocal != epRemote && !isDotNet)
                    return HeaderAnomalyType.EntryPointModified;

                return HeaderAnomalyType.OptionalHeaderModified;
            }

            // 5. Section Headers
            // ... (Vergleich der Sektionstabelle)

            return HeaderAnomalyType.None;
        }

        private bool CompareBytes(byte[] a, byte[] b, int offset, int length)
        {
            for (int i = 0; i < length; i++)
                if (a[offset + i] != b[offset + i]) return false;
            return true;
        }

        private List<Range> GetExclusionRanges(IntPtr optHeaderPtr, ushort magic)
        {
            var ranges = new List<Range>();
            int dataDirBase = (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC) ? 112 : 96;

            void AddRange(int index)
            {
                int offset = dataDirBase + (index * 8);
                uint rva = (uint)Marshal.ReadInt32(optHeaderPtr, offset);
                uint size = (uint)Marshal.ReadInt32(optHeaderPtr, offset + 4);
                if (rva > 0 && size > 0) ranges.Add(new Range { Start = rva, End = rva + size });
            }

            // Wir ignorieren alle Directories, die im Speicher vom OS Loader angefasst werden.
            // Referenz: pe-sieve code_scanner.cpp
            AddRange(PeHeaders.IMAGE_DIRECTORY_ENTRY_EXPORT);      // Exports
            AddRange(PeHeaders.IMAGE_DIRECTORY_ENTRY_IMPORT);      // Import Descriptors
            AddRange(PeHeaders.IMAGE_DIRECTORY_ENTRY_RESOURCE);    // Resources
            AddRange(PeHeaders.IMAGE_DIRECTORY_ENTRY_EXCEPTION);   // Exceptions
            AddRange(PeHeaders.IMAGE_DIRECTORY_ENTRY_SECURITY);    // Certs
            AddRange(PeHeaders.IMAGE_DIRECTORY_ENTRY_BASERELOC);   // Relocations
            AddRange(PeHeaders.IMAGE_DIRECTORY_ENTRY_DEBUG);       // Debug
            AddRange(PeHeaders.IMAGE_DIRECTORY_ENTRY_TLS);         // TLS
            AddRange(PeHeaders.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG); // Security Cookie
            AddRange(PeHeaders.IMAGE_DIRECTORY_ENTRY_IAT);         // IAT (Wichtig!)
            AddRange(PeHeaders.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);// Delay Imports

            return ranges;
        }
    }
    public enum HeaderAnomalyType
    {
        None,
        DosHeaderModified,
        NtSignatureMissing,
        FileHeaderModified,
        OptionalHeaderModified,
        EntryPointModified, // Spezifisch!
        SectionTableModified,
        FullReplacement // Hollowing
    }
}