/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using NativeProcesses.Core.Inspection;
using NativeProcesses.Core.Models;
using NativeProcesses.Core.Native;

namespace NativeProcesses.Core.PeConv
{
    public static class PeImports
    {
        public class ImportEntry
        {
            public uint IatRva;          // Wo im Speicher steht der Pointer? (Die Adresse, die wir scannen wollen)
            public string ModuleName;    // Aus welcher DLL kommt die Funktion?
            public string FunctionName;  // Wie heißt die Funktion?
            public uint Ordinal;         // Falls Import by Ordinal
            public bool IsOrdinal;
            public IntPtr ExpectedAddress; // Die aufgelöste, "echte" Adresse (unser Golden Value)
        }

        /// <summary>
        /// Scannt die Import-Tabelle eines gemappten Moduls und löst die erwarteten Ziele auf.
        /// </summary>
        /// <param name="process">Der Zielprozess (für Architektur-Checks)</param>
        /// <param name="moduleToScan">Das Modul, dessen Imports wir prüfen (Memory Base)</param>
        /// <param name="mappedImage">Das Golden Image dieses Moduls (von Disk, via PeMapper)</param>
        /// <param name="allModules">Liste aller geladenen Module im Zielprozess (zum Auflösen der Ziele)</param>
        public static List<ImportEntry> GetResolvedImports(
            ManagedProcess process,
            ProcessModuleInfo moduleToScan,
            byte[] mappedImage,
            List<ProcessModuleInfo> allModules)
        {
            var imports = new List<ImportEntry>();
            if (mappedImage == null) return imports;

            try
            {
                // Header Parsing (Analog zu PeExports/PeMapper)
                int e_lfanew = BitConverter.ToInt32(mappedImage, 0x3C);
                ushort magic = BitConverter.ToUInt16(mappedImage, e_lfanew + 24);
                bool is64 = (magic == PE.PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC);
                int ptrSize = is64 ? 8 : 4;

                int importDirOffset = e_lfanew + 24 + (is64 ? 112 : 96) + 8; // DataDirectory[1]

                uint importRva = BitConverter.ToUInt32(mappedImage, importDirOffset);
                uint importSize = BitConverter.ToUInt32(mappedImage, importDirOffset + 4);

                if (importRva == 0 || importSize == 0) return imports;

                // Iteration durch die Import Descriptors
                int descOffset = (int)importRva;
                int descSize = 20; // IMAGE_IMPORT_DESCRIPTOR

                while (descOffset + descSize <= mappedImage.Length)
                {
                    // Manuelles Lesen der Struktur aus dem Byte-Array
                    // OriginalFirstThunk (INT) @ 0
                    // Name @ 12
                    // FirstThunk (IAT) @ 16
                    uint originalFirstThunk = BitConverter.ToUInt32(mappedImage, descOffset);
                    uint nameRva = BitConverter.ToUInt32(mappedImage, descOffset + 12);
                    uint firstThunk = BitConverter.ToUInt32(mappedImage, descOffset + 16);

                    if (nameRva == 0 && firstThunk == 0) break; // Terminator

                    string dllName = ReadString(mappedImage, (int)nameRva);
                    if (string.IsNullOrEmpty(dllName))
                    {
                        descOffset += descSize;
                        continue;
                    }

                    // Finde das Ziel-Modul in der Modul-Liste des Prozesses
                    var targetMod = allModules.FirstOrDefault(m => m.BaseDllName.Equals(dllName, StringComparison.OrdinalIgnoreCase));

                    // Wir iterieren durch die Thunks.
                    // WICHTIG: Wir nutzen OriginalFirstThunk (INT), um den NAMEN zu finden.
                    // Wenn INT 0 ist (selten, z.B. Borland Compiler), nutzen wir FirstThunk.
                    uint thunkRva = (originalFirstThunk != 0) ? originalFirstThunk : firstThunk;
                    uint iatRva = firstThunk; // Das ist die Adresse, wo der Pointer zur Laufzeit steht

                    int thunkOffset = (int)thunkRva;
                    int iatOffset = (int)iatRva;

                    while (thunkOffset + ptrSize <= mappedImage.Length)
                    {
                        ulong rawVal = is64
                            ? BitConverter.ToUInt64(mappedImage, thunkOffset)
                            : BitConverter.ToUInt32(mappedImage, thunkOffset);

                        if (rawVal == 0) break; // Ende der Thunks

                        var entry = new ImportEntry
                        {
                            IatRva = (uint)iatOffset, // Hier muss später im RAM geprüft werden
                            ModuleName = dllName
                        };

                        // Ordinal Check
                        bool isOrdinal = is64
                            ? (rawVal & 0x8000000000000000) != 0
                            : (rawVal & 0x80000000) != 0;

                        if (isOrdinal)
                        {
                            entry.IsOrdinal = true;
                            entry.Ordinal = (uint)(rawVal & 0xFFFF);
                            entry.FunctionName = $"#{entry.Ordinal}";
                        }
                        else
                        {
                            // Name Import: RVA zeigt auf IMAGE_IMPORT_BY_NAME
                            // Hint (2 Bytes) + Name (ASCII)
                            int nameStructOffset = (int)(rawVal & 0x7FFFFFFF);
                            if (nameStructOffset + 2 < mappedImage.Length)
                            {
                                entry.FunctionName = ReadString(mappedImage, nameStructOffset + 2);
                            }
                        }

                        // --- AUFLÖSUNG (RESOLVING) ---
                        // Hier verknüpfen wir PeImports mit PeExports!
                        if (targetMod != null && !string.IsNullOrEmpty(entry.FunctionName))
                        {
                            // Rekursive Auflösung via PeExports und Dateisystem
                            entry.ExpectedAddress = ResolveImportAddress(targetMod, entry.FunctionName, allModules);
                        }

                        imports.Add(entry);

                        thunkOffset += ptrSize;
                        iatOffset += ptrSize;
                    }

                    descOffset += descSize;
                }
            }
            catch { }

            return imports;
        }

        private static IntPtr ResolveImportAddress(ProcessModuleInfo module, string funcName, List<ProcessModuleInfo> allModules, int depth = 0)
        {
            if (depth > 10) return IntPtr.Zero;

            // 1. Wir laden das "Golden Image" der Ziel-DLL (nicht aus dem RAM, sondern von Disk!)
            // Das garantiert Integrität.
            string path = module.FullDllName;
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
            {
                // Versuch über System32
                path = Path.Combine(Environment.SystemDirectory, module.BaseDllName);
                if (!File.Exists(path)) return IntPtr.Zero;
            }

            byte[] targetImage = PeMapper.MapFile(path); // Unser Mapper aus Schritt 1
            if (targetImage == null) return IntPtr.Zero;

            // 2. Export suchen
            var export = PE.Export.PeExports.GetExportEntry(targetImage, funcName); // Unser Mapper aus Schritt 2

            if (export.FunctionRva == 0 && !export.IsForwarder) return IntPtr.Zero; // Nicht gefunden

            // 3. Forwarder Handling (Rekursion)
            if (export.IsForwarder)
            {
                string fwd = export.ForwarderString; // "NTDLL.RtlAllocateHeap"
                int dot = fwd.IndexOf('.');
                if (dot > 0)
                {
                    string nextDll = fwd.Substring(0, dot);
                    string nextFunc = fwd.Substring(dot + 1);
                    if (!nextDll.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) nextDll += ".dll";

                    var nextModInfo = allModules.FirstOrDefault(m => m.BaseDllName.Equals(nextDll, StringComparison.OrdinalIgnoreCase));
                    if (nextModInfo != null)
                    {
                        return ResolveImportAddress(nextModInfo, nextFunc, allModules, depth + 1);
                    }
                }
                return IntPtr.Zero;
            }

            // 4. Echte Adresse berechnen
            return IntPtr.Add(module.DllBase, (int)export.FunctionRva);
        }

        private static string ReadString(byte[] buffer, int offset)
        {
            int end = offset;
            while (end < buffer.Length && buffer[end] != 0) end++;
            return Encoding.ASCII.GetString(buffer, offset, end - offset);
        }
    }
}