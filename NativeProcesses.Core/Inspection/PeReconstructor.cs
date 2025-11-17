/*
   NativeProcesses Framework  |
   © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using NativeProcesses.Core.Native;
using NativeProcesses.Core.Models;
using NativeProcesses.Core.Engine;

namespace NativeProcesses.Core.Inspection
{
    public class PeReconstructor
    {
        private readonly IEngineLogger _logger;

        public PeReconstructor(IEngineLogger logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Versucht, einen rohen Speicher-Dump in eine ausführbare PE-Datei zu reparieren (ImpRec).
        /// Portierung der Logik aus imp_reconstructor.cpp
        /// </summary>
        public byte[] ReconstructPe(byte[] rawDump, List<ProcessModuleInfo> modules, Native.ManagedProcess process, bool is64Bit)
        {
            try
            {
                // 1. IAT Suche: Finde Blöcke von Pointern, die auf Export-Funktionen anderer Module zeigen
                var iatBlocks = FindIatBlocks(rawDump, modules, is64Bit);

                if (iatBlocks.Count == 0)
                {
                    _logger?.Log(LogLevel.Debug, "PeReconstructor: No IAT blocks found to reconstruct.");
                    return rawDump; // Nichts zu tun
                }

                // 2. Baue eine neue Import-Tabelle aus den gefundenen Blöcken
                byte[] newImportSection;
                uint importSectionRva;
                uint importSectionSize;

                // Wir hängen die neue Sektion am Ende des Dumps an (Alignment beachten!)
                uint fileAlignment = 0x200;
                uint sectionAlignment = 0x1000;

                // Aktuelle Größe auf Section Alignment runden
                uint currentVirtualSize = (uint)rawDump.Length;
                uint newSectionRva = AlignUp(currentVirtualSize, sectionAlignment);

                // Lücke mit Nullen füllen
                int paddingSize = (int)(newSectionRva - currentVirtualSize);
                var paddedDump = rawDump.Concat(new byte[paddingSize]).ToList();

                // Import Table bauen
                BuildImportTable(iatBlocks, newSectionRva, out newImportSection, out uint iatDirectorySize);

                // 3. Header Patchen (Data Directory & Section Table)
                // Wir müssen den PE-Header parsen, um das DataDirectory zu finden
                int e_lfanew = BitConverter.ToInt32(rawDump, 0x3C);
                int optionalHeaderOffset = e_lfanew + 24;
                int dataDirOffset = is64Bit ? optionalHeaderOffset + 112 : optionalHeaderOffset + 96; // Import ist Index 1
                int importDirOffset = dataDirOffset + 8; // Index 1 (8 Bytes pro Eintrag)

                // Neue Sektion anhängen
                paddedDump.AddRange(newImportSection);
                byte[] finalPe = paddedDump.ToArray();

                // Pointer auf Import Table im Header aktualisieren
                // VirtualAddress
                BitConverter.GetBytes(newSectionRva).CopyTo(finalPe, importDirOffset);
                // Size
                BitConverter.GetBytes(iatDirectorySize).CopyTo(finalPe, importDirOffset + 4);

                // Optional: Neue Section Header ("idatan") hinzufügen, falls Platz im Header ist.
                // Das ist komplex, da oft kein Platz ist. Wir begnügen uns hier mit dem DataDirectory-Fix,
                // was für Analyse-Tools (IDA, Pe-Bear) oft reicht, wenn der Dump "Raw" geladen wird.

                _logger?.Log(LogLevel.Info, $"PeReconstructor: Reconstructed Import Table at RVA 0x{newSectionRva:X} with {iatBlocks.Count} blocks.");
                return finalPe;
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, "PeReconstructor failed.", ex);
                return rawDump;
            }
        }

        private List<IatBlock> FindIatBlocks(byte[] dump, List<ProcessModuleInfo> modules, bool is64Bit)
        {
            var blocks = new List<IatBlock>();
            int ptrSize = is64Bit ? 8 : 4;
            int step = ptrSize;

            // Cache für Module-Ranges (für O(1) Lookup)
            var moduleRanges = modules.Select(m => new
            {
                Start = (ulong)m.DllBase.ToInt64(),
                End = (ulong)m.DllBase.ToInt64() + m.SizeOfImage,
                Name = m.BaseDllName
            }).ToList();

            IatBlock currentBlock = null;

            // Scan durch den Dump
            for (int i = 0; i < dump.Length - ptrSize; i += step)
            {
                ulong ptrVal = is64Bit ? BitConverter.ToUInt64(dump, i) : BitConverter.ToUInt32(dump, i);

                // Prüfen, ob der Pointer in ein geladenes Modul zeigt
                var targetMod = moduleRanges.FirstOrDefault(m => ptrVal >= m.Start && ptrVal < m.End);

                if (targetMod != null)
                {
                    // Valid Pointer found!
                    if (currentBlock == null)
                    {
                        currentBlock = new IatBlock { StartOffset = i, ModuleName = targetMod.Name };
                    }
                    else
                    {
                        // Gehört er zum gleichen Modul? (ImpRec Logik: Imports sind meist nach DLL gruppiert)
                        if (currentBlock.ModuleName != targetMod.Name)
                        {
                            // Block-Wechsel. Alten speichern.
                            currentBlock.EndOffset = i;
                            blocks.Add(currentBlock);
                            currentBlock = new IatBlock { StartOffset = i, ModuleName = targetMod.Name };
                        }
                    }

                    // Adresse speichern für Rekonstruktion
                    currentBlock.Functions.Add(new ImportedFunction { Address = ptrVal, OffsetInDump = i });
                }
                else
                {
                    // Kein Pointer oder zeigt ins Nirvana -> Block Ende
                    if (currentBlock != null)
                    {
                        currentBlock.EndOffset = i;
                        // Filter: Zu kleine Blöcke (weniger als 2 Funktionen) ignorieren wir oft als False Positive
                        if (currentBlock.Functions.Count > 1)
                        {
                            blocks.Add(currentBlock);
                        }
                        currentBlock = null;
                    }
                }
            }

            return blocks;
        }

        private void BuildImportTable(List<IatBlock> blocks, uint baseRva, out byte[] sectionData, out uint dirSize)
        {
            // Struktur der neuen Section:
            // [Import Descriptors Array] (null terminated)
            // [OriginalFirstThunks (INT)] 
            // [FirstThunks (IAT) - Optional, wir verweisen oft auf die originalen im Dump]
            // [Dll Names Strings]
            // [Function Names / Hints]

            // Für eine einfache Rekonstruktion erstellen wir Import Descriptors, 
            // die auf die GEFUNDENEN Thunks im Original-Dump (FirstThunk) verweisen.
            // Das Problem: Wir kennen die Funktionsnamen nicht ohne EAT-Lookup im Remote Process.
            // Wir bauen hier eine "Synthetic IAT", die für Analyse-Tools sichtbar ist.

            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                // 1. Import Descriptors berechnen
                int descriptorSize = 20; // IMAGE_IMPORT_DESCRIPTOR size
                int descriptorsCount = blocks.Count;
                int descriptorsTotalSize = (descriptorsCount + 1) * descriptorSize; // +1 für Null-Terminator

                // Wir schreiben zuerst Platzhalter für die Descriptors
                long descriptorsStartPos = 0;
                writer.Write(new byte[descriptorsTotalSize]);

                // Jetzt die Daten (Namen) schreiben und Descriptors updaten
                long dataStartPos = ms.Position;

                for (int i = 0; i < blocks.Count; i++)
                {
                    var block = blocks[i];

                    // DLL Name schreiben
                    long nameRvaOffset = ms.Position;
                    writer.Write(Encoding.ASCII.GetBytes(block.ModuleName));
                    writer.Write((byte)0);

                    // Descriptor an Position i updaten
                    long currentPos = ms.Position;
                    ms.Position = descriptorsStartPos + (i * descriptorSize);

                    // IMAGE_IMPORT_DESCRIPTOR schreiben:
                    // OriginalFirstThunk (INT) = 0 (Wir nutzen nur IAT Binding)
                    writer.Write((uint)0);
                    // TimeDateStamp = 0
                    writer.Write((uint)0);
                    // ForwarderChain = 0
                    writer.Write((uint)0);
                    // Name (RVA)
                    writer.Write((uint)(baseRva + nameRvaOffset));
                    // FirstThunk (IAT) - RVA im Original-Dump!
                    // Achtung: Hier nehmen wir an, Dump Offset == RVA (bei Memory Dumps oft so)
                    writer.Write((uint)block.StartOffset);

                    ms.Position = currentPos;
                }

                sectionData = ms.ToArray();
                dirSize = (uint)descriptorsTotalSize;
            }
        }

        private uint AlignUp(uint value, uint alignment)
        {
            return (value + alignment - 1) & ~(alignment - 1);
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