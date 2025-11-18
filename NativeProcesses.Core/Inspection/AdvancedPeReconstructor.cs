using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using NativeProcesses.Core.Engine;
using NativeProcesses.Core.Models;
using NativeProcesses.Core.Native;

namespace NativeProcesses.Core.Inspection
{
    public class AdvancedPeReconstructor
    {
        private readonly IEngineLogger _logger;

        public AdvancedPeReconstructor(IEngineLogger logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Rekonstruiert die Import Table basierend auf gefundenen IAT-Blöcken.
        /// Portierung von PE-sieve imp_reconstructor.cpp
        /// </summary>
        public byte[] Reconstruct(byte[] rawPe, List<IatBlock> foundIats, bool is64Bit)
        {
            try
            {
                if (foundIats == null || foundIats.Count == 0)
                    return rawPe;

                // 1. Berechne benötigten Platz und Layout
                // Layout: [Descriptors] [Null-Desc] [Thunks (INT)] [Names/Hints] [DLL Strings]

                using (var ms = new MemoryStream())
                using (var writer = new BinaryWriter(ms))
                {
                    // Wir müssen wissen, wo wir im virtuellen Speicher landen.
                    // Wir hängen das ans Ende der Datei an.
                    // ACHTUNG: Wir gehen davon aus, dass rawPe ein Memory Dump ist (Virtual Alignment).
                    // Wir müssen das Alignment der letzten Sektion prüfen.

                    uint currentVirtualSize = (uint)rawPe.Length;
                    uint sectionAlignment = 0x1000; // Standard Page Size
                    uint fileAlignment = 0x200;

                    // Wir runden auf das nächste Section Alignment auf
                    uint newImportRva = AlignUp(currentVirtualSize, sectionAlignment);

                    // Padding berechnen (Lücke zwischen altem Ende und neuer Sektion)
                    int paddingSize = (int)(newImportRva - currentVirtualSize);

                    // Wir bauen den neuen Import-Block separat im MemoryStream

                    // A. Import Descriptors (1 pro DLL + 1 Null-Terminator)
                    int descriptorSize = 20; // sizeof(IMAGE_IMPORT_DESCRIPTOR)
                    int descriptorsCount = foundIats.Count;
                    int descriptorsTotalSize = (descriptorsCount + 1) * descriptorSize;

                    // Platzhalter für Descriptors schreiben (werden später gefüllt)
                    long descriptorsStartOffset = 0;
                    writer.Write(new byte[descriptorsTotalSize]);

                    // Wir speichern, wo wir Daten hinschreiben, relativ zum Start des neuen Blocks
                    var descriptorFixups = new List<Action<BinaryWriter, uint>>();

                    // B. Daten schreiben (Thunks, Namen, Strings)
                    for (int i = 0; i < foundIats.Count; i++)
                    {
                        var iat = foundIats[i];

                        // 1. DLL Name schreiben
                        long dllNameOffset = ms.Position;
                        byte[] dllNameBytes = Encoding.ASCII.GetBytes(iat.ModuleName);
                        writer.Write(dllNameBytes);
                        writer.Write((byte)0); // Null-Terminator

                        // Alignment für Thunks (muss oft Pointer-Aligned sein)
                        AlignStream(ms, is64Bit ? 8 : 4);

                        // 2. OriginalFirstThunk Array (INT) schreiben
                        // Das ist eine Kopie der IAT, zeigt aber auf die Namen
                        long intStartOffset = ms.Position;
                        var nameRvas = new List<uint>(); // Speichert RVAs der Namen für die Thunks

                        // Platzhalter für das INT Array
                        int ptrSize = is64Bit ? 8 : 4;
                        int thunkCount = iat.Functions.Count;
                        long intSize = (thunkCount + 1) * ptrSize; // +1 für Null-Terminator
                        writer.Write(new byte[intSize]);

                        // 3. Import By Name Strukturen schreiben
                        long currentPosAfterInt = ms.Position;

                        // Jetzt füllen wir die Namen und merken uns deren Offsets
                        for (int f = 0; f < iat.Functions.Count; f++)
                        {
                            var func = iat.Functions[f];

                            // Alignment (2 Byte für Hint)
                            if (ms.Position % 2 != 0) writer.Write((byte)0);

                            long nameStructOffset = ms.Position;

                            // IMAGE_IMPORT_BY_NAME: Hint (2 Bytes) + Name (ASCIIZ)
                            writer.Write((ushort)0); // Hint (egal)

                            // Funktionsname holen (hier vereinfacht, in Realität brauchen wir den Namen aus dem Export-Scan)
                            string funcName = func.ResolvedName ?? $"Func_{func.Address:X}";
                            writer.Write(Encoding.ASCII.GetBytes(funcName));
                            writer.Write((byte)0);

                            // RVA berechnen: NewBase + Offset
                            nameRvas.Add((uint)nameStructOffset);
                        }

                        // 4. INT (OriginalFirstThunk) Array nachträglich befüllen
                        long endPos = ms.Position;
                        ms.Position = intStartOffset;

                        foreach (var nameOffset in nameRvas)
                        {
                            // RVA zum Namen = BaseRva + Offset im Stream
                            ulong rvaVal = newImportRva + nameOffset;
                            if (is64Bit)
                                writer.Write((ulong)rvaVal);
                            else
                                writer.Write((uint)rvaVal);
                        }
                        // Null-Terminator ist schon da (durch new byte[])
                        ms.Position = endPos;

                        // 5. Descriptor Fixup vorbereiten
                        // Wir schreiben die RVA-Werte in die Descriptor-Tabelle am Anfang
                        int currentDescIdx = i;
                        descriptorFixups.Add((w, baseRva) =>
                        {
                            w.BaseStream.Position = descriptorsStartOffset + (currentDescIdx * descriptorSize);

                            // IMAGE_IMPORT_DESCRIPTOR schreiben
                            w.Write((uint)(baseRva + intStartOffset)); // OriginalFirstThunk (RVA zu INT)
                            w.Write((uint)0); // TimeDateStamp
                            w.Write((uint)0); // ForwarderChain
                            w.Write((uint)(baseRva + dllNameOffset)); // Name (RVA zu DLL String)
                            w.Write((uint)iat.FirstThunkRva); // FirstThunk (RVA zur IAT im Original-Dump!)
                        });
                    }

                    // C. Fixups anwenden
                    foreach (var fixup in descriptorFixups)
                    {
                        fixup(writer, newImportRva);
                    }

                    // Fertiger neuer Block
                    byte[] importBlock = ms.ToArray();

                    // D. Zusammenfügen
                    // 1. Original Dump
                    // 2. Padding
                    // 3. Neuer Import Block

                    using (var finalMs = new MemoryStream())
                    using (var finalWriter = new BinaryWriter(finalMs))
                    {
                        finalWriter.Write(rawPe);
                        finalWriter.Write(new byte[paddingSize]);
                        finalWriter.Write(importBlock);

                        byte[] resultPe = finalMs.ToArray();

                        // E. PE Header Patchen (Data Directory)
                        PatchDataDirectory(resultPe, newImportRva, (uint)descriptorsTotalSize);

                        // F. Section Header anpassen (VirtualSize der letzten Sektion erhöhen)
                        PatchLastSection(resultPe, newImportRva + (uint)importBlock.Length);

                        return resultPe;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, "PeReconstruction failed", ex);
                return rawPe; // Fallback auf Original
            }
        }

        private void PatchDataDirectory(byte[] pe, uint rva, uint size)
        {
            // Finde PE Header Offset
            int e_lfanew = BitConverter.ToInt32(pe, 0x3C);

            // Optional Header Magic
            ushort magic = BitConverter.ToUInt16(pe, e_lfanew + 24);
            bool is64 = (magic == 0x20B);

            // Offset zum Import Directory (Index 1)
            // 32-Bit: OptionalHeader(96) + DataDir[1](8) = 104 + 24(FileHeader) + 4(Sig) = 132
            // 64-Bit: OptionalHeader(112) + DataDir[1](8) = 120 + 24(FileHeader) + 4(Sig) = 148
            // Check offsets dynamically based on header size

            int optionalHeaderOffset = e_lfanew + 24;
            int dataDirsOffset = is64 ? optionalHeaderOffset + 112 : optionalHeaderOffset + 96;
            int importDirOffset = dataDirsOffset + 8; // Index 1 (Export=0, Import=1)

            using (var ms = new MemoryStream(pe))
            using (var w = new BinaryWriter(ms))
            {
                ms.Position = importDirOffset;
                w.Write(rva);
                w.Write(size);
            }
        }

        private void PatchLastSection(byte[] pe, uint newVirtualEnd)
        {
            // Wir müssen die VirtualSize der letzten Sektion erweitern, damit unser neuer Anhang gültig ist.
            // PE-sieve macht das in pe_buffer.cpp -> resizeLastSection

            int e_lfanew = BitConverter.ToInt32(pe, 0x3C);
            int fileHeaderOffset = e_lfanew + 4;
            ushort numberOfSections = BitConverter.ToUInt16(pe, fileHeaderOffset + 2);
            ushort sizeOfOptionalHeader = BitConverter.ToUInt16(pe, fileHeaderOffset + 16);

            int sectionTableOffset = fileHeaderOffset + 20 + sizeOfOptionalHeader;
            int sectionSize = 40;

            // Letzte Sektion finden
            int lastSectionOffset = sectionTableOffset + ((numberOfSections - 1) * sectionSize);

            // IMAGE_SECTION_HEADER lesen
            // 0x08: VirtualSize
            // 0x0C: VirtualAddress
            // 0x10: SizeOfRawData

            uint virtualAddress = BitConverter.ToUInt32(pe, lastSectionOffset + 12);
            uint oldVirtualSize = BitConverter.ToUInt32(pe, lastSectionOffset + 8);

            uint newVirtualSize = newVirtualEnd - virtualAddress;

            // Patchen
            using (var ms = new MemoryStream(pe))
            using (var w = new BinaryWriter(ms))
            {
                ms.Position = lastSectionOffset + 8; // VirtualSize
                w.Write(newVirtualSize);

                // Wir setzen auch SizeOfRawData hoch, da wir es ja physikalisch angehängt haben
                ms.Position = lastSectionOffset + 16; // SizeOfRawData
                w.Write(newVirtualSize); // AlignUp wäre sauberer, aber Windows ist tolerant

                // Optional: Characteristics auf Read/Write setzen, falls nötig
            }
        }

        private uint AlignUp(uint value, uint alignment)
        {
            return (value + alignment - 1) & ~(alignment - 1);
        }

        private void AlignStream(MemoryStream ms, int alignment)
        {
            while (ms.Position % alignment != 0)
            {
                ms.WriteByte(0);
            }
        }
    }

    // Hilfsklassen (DTOs)
    public class IatBlock
    {
        public string ModuleName;
        public uint FirstThunkRva; // Wo im Original-PE die IAT für diese DLL beginnt
        public List<ImportedFunc> Functions = new List<ImportedFunc>();
    }

    public class ImportedFunc
    {
        public ulong Address;
        public string ResolvedName; // Name der Funktion, falls aufgelöst
    }
}