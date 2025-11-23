/*
   NativeProcesses Framework
   PeReconstructor.cs - Fixes Imports AND Exports in memory dumps.
*/
using NativeProcesses.Core.Engine;
using NativeProcesses.Core.Models;
using NativeProcesses.Core.Native;
using NativeProcesses.Core.PE;
using NativeProcesses.Core.PE.Export;
using NativeProcesses.Core.PeConv;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NativeProcesses.Core.PE.Reconstruction
{
    public class PeReconstructor
    {
        private readonly IEngineLogger _logger;

        public PeReconstructor(IEngineLogger logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Repariert einen Memory Dump: Baut Import- und Export-Tabellen neu auf und fügt sie als neue Sektion an.
        /// </summary>
        public byte[] ReconstructPe(byte[] rawDump, List<ProcessModuleInfo> modules, ManagedProcess process, bool is64Bit)
        {
            try
            {
                // Wir pinnen den Raw Dump, um Exports daraus zu lesen (falls wir keine Live-Connection nutzen wollen/können)
                // Alternativ könnte man 'process' nutzen, aber wir arbeiten hier lieber auf dem Dump.
                GCHandle handle = GCHandle.Alloc(rawDump, GCHandleType.Pinned);
                IntPtr dumpBase = handle.AddrOfPinnedObject();

                try
                {
                    // ----------------------------------------------------
                    // 1. Analyse: Daten sammeln
                    // ----------------------------------------------------

                    // A. Imports finden (Scan nach Pointern im Dump)
                    var iatBlocks = FindIatBlocks(rawDump, modules, is64Bit);

                    // B. Exports finden (Parse existierende Strukturen im Dump)
                    // Wir nutzen PeExports.EnumExportedFunctions auf unserem Pinned Buffer
                    var exports = PeExports.EnumExportedFunctions(dumpBase);

                    if (iatBlocks.Count == 0 && exports.Count == 0)
                    {
                        _logger?.Log(LogLevel.Debug, "PeReconstructor: No Imports/Exports to rebuild.");
                        return rawDump;
                    }

                    // ----------------------------------------------------
                    // 2. Layout berechnen
                    // ----------------------------------------------------
                    uint sectionAlignment = 0x1000;
                    uint currentVirtualSize = (uint)rawDump.Length;

                    // Neue Sektion beginnt am nächsten Alignment
                    uint newSectionRva = (currentVirtualSize + sectionAlignment - 1) & ~(sectionAlignment - 1);
                    int paddingSize = (int)(newSectionRva - currentVirtualSize);

                    // ----------------------------------------------------
                    // 3. Tabellen bauen (in MemoryStream)
                    // ----------------------------------------------------
                    using (var ms = new MemoryStream())
                    using (var writer = new BinaryWriter(ms))
                    {
                        // Padding schreiben
                        writer.Write(new byte[paddingSize]);

                        // A. IMPORT TABLE schreiben
                        uint importDirRva = 0;
                        uint importDirSize = 0;
                        if (iatBlocks.Count > 0)
                        {
                            importDirRva = newSectionRva + (uint)ms.Position; // Relativ zum Start des neuen Blocks
                            // Wir ziehen das Padding ab, da ms.Position bei 0 startet (relativ zum Stream), 
                            // aber RVA absolut ist. 
                            // Korrektur: ms enthält schon Padding. 
                            // Position im Stream ist Padding + Data. 
                            // Rva = newSectionRva + (Position - PaddingSize). Nein.
                            // Rva = currentVirtualSize + Position.
                            importDirRva = (uint)(currentVirtualSize + ms.Position);

                            BuildImportTable(writer, iatBlocks, newSectionRva, is64Bit, out importDirSize);
                        }

                        // Alignment zwischen Import und Export
                        while (ms.Position % 16 != 0) writer.Write((byte)0);

                        // B. EXPORT TABLE schreiben
                        uint exportDirRva = 0;
                        uint exportDirSize = 0;
                        if (exports.Count > 0)
                        {
                            exportDirRva = (uint)(currentVirtualSize + ms.Position);
                            // DLL Name holen (aus ProcessModuleInfo oder Header)
                            string dllName = "dumped_module.dll";
                            // Versuche Namen aus Export Directory zu retten, sonst Default

                            BuildExportTable(writer, exports, dllName, newSectionRva, (uint)(ms.Position - paddingSize), out exportDirSize);
                        }

                        // ----------------------------------------------------
                        // 4. Zusammenfügen und Patchen
                        // ----------------------------------------------------
                        byte[] appendedData = ms.ToArray();

                        // Finales Array erstellen
                        byte[] finalPe = new byte[currentVirtualSize + appendedData.Length];
                        Array.Copy(rawDump, 0, finalPe, 0, rawDump.Length);
                        Array.Copy(appendedData, 0, finalPe, rawDump.Length, appendedData.Length);

                        // C. Header Patchen
                        if (importDirRva > 0)
                            PatchDataDirectory(finalPe, PeHeaders.IMAGE_DIRECTORY_ENTRY_IMPORT, importDirRva, importDirSize, is64Bit);

                        if (exportDirRva > 0)
                            PatchDataDirectory(finalPe, PeHeaders.IMAGE_DIRECTORY_ENTRY_EXPORT, exportDirRva, exportDirSize, is64Bit);

                        // D. Section Table erweitern (VirtualSize)
                        PatchLastSectionVirtualSize(finalPe, (uint)finalPe.Length);

                        _logger?.Log(LogLevel.Info, $"PeReconstructor: Rebuilt Imports ({iatBlocks.Count} blocks) and Exports ({exports.Count} funcs).");
                        return finalPe;
                    }
                }
                finally
                {
                    if (handle.IsAllocated) handle.Free();
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, "PeReconstructor failed.", ex);
                return rawDump;
            }
        }

        /// <summary>
        /// Schreibt die Export-Tabelle in den Stream.
        /// Layout: [Dir] [Funcs] [Ordinals] [NamesPtrs] [NamesStrings]
        /// </summary>
        private void BuildExportTable(BinaryWriter writer, List<ExportedFunction> exports, string dllName, uint sectionBaseRva, uint offsetInNewSection, out uint dirSize)
        {
            long startPos = writer.BaseStream.Position;

            // Sortieren nach Ordinal für Function Table, nach Name für Names Table
            var sortedByOrdinal = exports.OrderBy(x => x.Ordinal).ToList();
            var namedExports = exports.Where(x => !string.IsNullOrEmpty(x.Name)).OrderBy(x => x.Name).ToList();

            uint ordinalBase = sortedByOrdinal.FirstOrDefault()?.Ordinal ?? 1;
            uint numFuncs = (uint)sortedByOrdinal.Count;
            uint numNames = (uint)namedExports.Count;

            // Berechne RVAs für die Tabellen
            // Wir müssen wissen, wo wir RELATIV zur ImageBase sind.
            // ImageBase + sectionBaseRva + offsetInNewSection = Start des Export Blocks
            uint baseRva = sectionBaseRva + offsetInNewSection;

            uint sizeOfDir = (uint)Marshal.SizeOf<PeHeaders.IMAGE_EXPORT_DIRECTORY>();
            uint funcTableOffset = sizeOfDir;
            uint nameTableOffset = funcTableOffset + (numFuncs * 4);
            uint ordinalTableOffset = nameTableOffset + (numNames * 4);
            uint stringsStartOffset = ordinalTableOffset + (numNames * 2);

            // 1. Directory schreiben
            var dir = new PeHeaders.IMAGE_EXPORT_DIRECTORY();
            dir.Characteristics = 0;
            dir.TimeDateStamp = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            dir.MajorVersion = 0;
            dir.MinorVersion = 0;
            dir.Name = baseRva + stringsStartOffset; // DLL Name kommt als erstes in den String-Block
            dir.Base = ordinalBase;
            dir.NumberOfFunctions = numFuncs;
            dir.NumberOfNames = numNames;
            dir.AddressOfFunctions = baseRva + funcTableOffset;
            dir.AddressOfNames = baseRva + nameTableOffset;
            dir.AddressOfNameOrdinals = baseRva + ordinalTableOffset;

            // Struct Marshalling (manuell schreiben)
            writer.Write(dir.Characteristics);
            writer.Write(dir.TimeDateStamp);
            writer.Write(dir.MajorVersion);
            writer.Write(dir.MinorVersion);
            writer.Write(dir.Name);
            writer.Write(dir.Base);
            writer.Write(dir.NumberOfFunctions);
            writer.Write(dir.NumberOfNames);
            writer.Write(dir.AddressOfFunctions);
            writer.Write(dir.AddressOfNames);
            writer.Write(dir.AddressOfNameOrdinals);

            // 2. AddressOfFunctions (EAT)
            foreach (var func in sortedByOrdinal)
            {
                writer.Write(func.FunctionRva);
            }

            // Um später die Namen-RVAs zu schreiben, brauchen wir Platzhalter.
            // Wir speichern die Positionen, um sie nach dem Schreiben der Strings zu patchen.
            long namesTablePos = writer.BaseStream.Position;
            writer.Write(new byte[numNames * 4]); // Platzhalter Names

            long ordinalsTablePos = writer.BaseStream.Position;
            // 4. AddressOfNameOrdinals
            // Das sind Indizes in die Function Table!
            foreach (var func in namedExports)
            {
                // Berechne Index: Ordinal - Base
                ushort idx = (ushort)(func.Ordinal - ordinalBase);
                writer.Write(idx);
            }

            // 5. Strings schreiben
            long stringsPos = writer.BaseStream.Position;

            // DLL Name
            uint dllNameRva = (uint)(baseRva + (stringsPos - startPos));
            writer.Write(Encoding.ASCII.GetBytes(dllName));
            writer.Write((byte)0);

            // Fixup Directory Name RVA (optional, haben wir oben schon geschätzt, aber korrigieren ist besser)
            // (Lassen wir, da wir 'stringsStartOffset' für DLL Name genutzt haben, was meist passt)

            // Funktionsnamen
            var nameRvas = new List<uint>();
            foreach (var func in namedExports)
            {
                uint nameRva = (uint)(baseRva + (writer.BaseStream.Position - startPos));
                nameRvas.Add(nameRva);
                writer.Write(Encoding.ASCII.GetBytes(func.Name));
                writer.Write((byte)0);
            }

            // 6. Fixup AddressOfNames
            long endPos = writer.BaseStream.Position;
            writer.BaseStream.Position = namesTablePos;
            foreach (var rva in nameRvas)
            {
                writer.Write(rva);
            }
            writer.BaseStream.Position = endPos;

            dirSize = (uint)(endPos - startPos);
        }

        private void BuildImportTable(BinaryWriter writer, List<IatBlock> blocks, uint baseRva, bool is64Bit, out uint dirSize)
        {
            long startPos = writer.BaseStream.Position;
            // Wir berechnen die RVAs relativ zum Anfang der Section
            // Da writer.BaseStream.Position absolute Position im Stream ist (inkl. Padding), 
            // aber 'baseRva' der Start der NEUEN Daten (ohne Padding?) ist...
            // Vorsicht: Wir haben 'baseRva' als (currentVirtualSize + Padding) definiert im Aufrufer.
            // Also ist baseRva der RVA von writer.BaseStream.Position = paddingSize.

            // Offset innerhalb dieses Blocks berechnen:
            long blockStartOffset = startPos;

            // 1. Descriptors
            int descriptorSize = 20;
            int descriptorsTotalSize = (blocks.Count + 1) * descriptorSize;

            long descriptorsStartPos = writer.BaseStream.Position;
            writer.Write(new byte[descriptorsTotalSize]); // Platzhalter

            for (int i = 0; i < blocks.Count; i++)
            {
                var block = blocks[i];

                // String RVA berechnen
                uint currentOffset = (uint)(writer.BaseStream.Position - blockStartOffset);
                uint nameRva = baseRva + currentOffset; // HIER muss baseRva der RVA dieses BLOCKS sein!
                // Im Aufrufer haben wir importDirRva als (currentVirtualSize + ms.Position) berechnet.
                // Das passt.

                writer.Write(Encoding.ASCII.GetBytes(block.ModuleName));
                writer.Write((byte)0);

                // Zurück zum Descriptor
                long tempPos = writer.BaseStream.Position;
                writer.BaseStream.Position = descriptorsStartPos + (i * descriptorSize);

                // Import Descriptor schreiben
                // Wir verweisen auf die originale IAT (FirstThunk) im Dump!
                // OriginalFirstThunk lassen wir 0, da wir keine INT haben (Bound Import Style).
                writer.Write((uint)0); // INT
                writer.Write((uint)0); // Time
                writer.Write((uint)0); // Fwd
                writer.Write(nameRva); // Name
                writer.Write((uint)block.StartOffset); // IAT (Original RVA)

                writer.BaseStream.Position = tempPos;
            }

            dirSize = (uint)(writer.BaseStream.Position - blockStartOffset);
        }

        private bool PatchDataDirectory(byte[] pe, int directoryIndex, uint rva, uint size, bool is64Bit)
        {
            try
            {
                int e_lfanew = BitConverter.ToInt32(pe, 0x3C);
                int optHeaderOffset = e_lfanew + 24;

                // DataDir Offset berechnen
                // 32: 96 + (idx * 8)
                // 64: 112 + (idx * 8)
                int dirOffset = optHeaderOffset + (is64Bit ? 112 : 96) + (directoryIndex * 8);

                if (dirOffset + 8 > pe.Length) return false;

                Array.Copy(BitConverter.GetBytes(rva), 0, pe, dirOffset, 4);
                Array.Copy(BitConverter.GetBytes(size), 0, pe, dirOffset + 4, 4);
                return true;
            }
            catch { return false; }
        }

        private void PatchLastSectionVirtualSize(byte[] pe, uint newTotalSize)
        {
            try
            {
                int e_lfanew = BitConverter.ToInt32(pe, 0x3C);
                int fileHeaderOffset = e_lfanew + 4;
                ushort numberOfSections = BitConverter.ToUInt16(pe, fileHeaderOffset + 2);
                ushort sizeOfOptionalHeader = BitConverter.ToUInt16(pe, fileHeaderOffset + 16);
                int sectionTableOffset = fileHeaderOffset + 20 + sizeOfOptionalHeader;
                int sectionSize = 40;

                if (numberOfSections == 0) return;

                int lastSectionOffset = sectionTableOffset + ((numberOfSections - 1) * sectionSize);

                uint virtualAddr = BitConverter.ToUInt32(pe, lastSectionOffset + 12);
                uint newVirtualSize = newTotalSize - virtualAddr;

                // VirtualSize und RawSize updaten
                Array.Copy(BitConverter.GetBytes(newVirtualSize), 0, pe, lastSectionOffset + 8, 4);
                Array.Copy(BitConverter.GetBytes(newVirtualSize), 0, pe, lastSectionOffset + 16, 4);

                // Rechte auf RWX setzen (damit Loader keine Probleme hat)
                uint chars = 0xE0000020;
                Array.Copy(BitConverter.GetBytes(chars), 0, pe, lastSectionOffset + 36, 4);
            }
            catch { }
        }

        private List<IatBlock> FindIatBlocks(byte[] dump, List<ProcessModuleInfo> modules, bool is64Bit)
        {
            // (Code von vorhin übernehmen - siehe unten)
            var blocks = new List<IatBlock>();
            int ptrSize = is64Bit ? 8 : 4;
            int step = ptrSize;

            var moduleRanges = modules.Select(m => new
            {
                Start = (ulong)m.DllBase.ToInt64(),
                End = (ulong)m.DllBase.ToInt64() + m.SizeOfImage,
                Name = m.BaseDllName
            }).ToList();

            IatBlock currentBlock = null;

            for (int i = 0; i < dump.Length - ptrSize; i += step)
            {
                ulong ptrVal = is64Bit ? BitConverter.ToUInt64(dump, i) : BitConverter.ToUInt32(dump, i);
                var targetMod = moduleRanges.FirstOrDefault(m => ptrVal >= m.Start && ptrVal < m.End);

                if (targetMod != null)
                {
                    if (currentBlock == null)
                    {
                        currentBlock = new IatBlock { StartOffset = i, ModuleName = targetMod.Name };
                    }
                    else if (currentBlock.ModuleName != targetMod.Name)
                    {
                        currentBlock.EndOffset = i;
                        blocks.Add(currentBlock);
                        currentBlock = new IatBlock { StartOffset = i, ModuleName = targetMod.Name };
                    }
                    currentBlock.Functions.Add(new ImportedFunction { Address = ptrVal, OffsetInDump = i });
                }
                else
                {
                    if (currentBlock != null)
                    {
                        currentBlock.EndOffset = i;
                        if (currentBlock.Functions.Count > 1) blocks.Add(currentBlock);
                        currentBlock = null;
                    }
                }
            }
            return blocks;
        }
        // In FoundPeHeaderInfo.cs oder PeReconstructor.cs

        public bool ScanForShiftedHeaders(byte[] memoryDump, out int foundNtOffset)
        {
            // PE-sieve sucht nach dem NT-Header (PE\0\0), wenn am Anfang (0) kein DOS-Header ist.
            // Wenn wir PE\0\0 finden, prüfen wir rückwärts, ob wir einen DOS-Header rekonstruieren können.

            foundNtOffset = -1;

            // Wir suchen alle 4 Bytes (Alignment)
            for (int i = 0; i < memoryDump.Length - 256; i += 4)
            {
                if (memoryDump[i] == 0x50 && memoryDump[i + 1] == 0x45 && memoryDump[i + 2] == 0 && memoryDump[i + 3] == 0)
                {
                    // Kandidat gefunden. Ist es valide?
                    // Prüfe Machine Type (Offset 4)
                    ushort machine = BitConverter.ToUInt16(memoryDump, i + 4);
                    if (machine == 0x14C || machine == 0x8664)
                    {
                        // JA! Wir haben einen verschobenen NT Header gefunden.
                        foundNtOffset = i;
                        return true;
                    }
                }
            }
            return false;
        }
        private class IatBlock
        {
            public int StartOffset;
            public int EndOffset;
            public string ModuleName;
            public List<ImportedFunction> Functions = new List<ImportedFunction>();
        }

        private class ImportedFunction
        {
            public ulong Address;
            public int OffsetInDump;
        }
    }
}