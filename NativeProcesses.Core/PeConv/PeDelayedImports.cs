/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using NativeProcesses.Core.Inspection;
using NativeProcesses.Core.Models;
using NativeProcesses.Core.Native;

namespace NativeProcesses.Core.PeConv
{
    public static class PeDelayedImports
    {
        // Struktur für Delayed Import Descriptor (vereinfacht für manuelles Lesen)
        // Offset 0: Attributes
        // Offset 4: Name RVA (DllName)
        // Offset 8: ModuleHandle RVA
        // Offset 12: ImportAddressTable (IAT) RVA  <-- Hier wird die echte Adresse zur Laufzeit hingeschrieben
        // Offset 16: ImportNameTable (INT) RVA     <-- Hier stehen die Namen
        // Offset 20: BoundImportAddressTable RVA
        // Offset 24: UnloadInformationTable RVA
        // Offset 28: TimeDateStamp

        public static List<PeImports.ImportEntry> GetResolvedDelayedImports(
            ManagedProcess process,
            ProcessModuleInfo moduleToScan,
            byte[] mappedImage,
            List<ProcessModuleInfo> allModules)
        {
            var imports = new List<PeImports.ImportEntry>();
            if (mappedImage == null) return imports;

            try
            {
                int e_lfanew = BitConverter.ToInt32(mappedImage, 0x3C);
                ushort magic = BitConverter.ToUInt16(mappedImage, e_lfanew + 24);
                bool is64 = (magic == PE.PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC);
                int ptrSize = is64 ? 8 : 4;

                // DataDirectory Index 13 = Delay Import Descriptor
                int dataDirSize = 8;
                int delayImportDirOffset = e_lfanew + 24 + (is64 ? 112 : 96) + (13 * dataDirSize);

                uint dirRva = BitConverter.ToUInt32(mappedImage, delayImportDirOffset);
                uint dirSize = BitConverter.ToUInt32(mappedImage, delayImportDirOffset + 4);

                if (dirRva == 0 || dirSize == 0) return imports;

                int descOffset = (int)dirRva;
                int descSize = 32; // sizeof(ImgDelayDescr)

                while (descOffset + descSize <= mappedImage.Length)
                {
                    // Wir lesen manuell, um Struct-Probleme zu vermeiden
                    uint nameRva = BitConverter.ToUInt32(mappedImage, descOffset + 4);
                    uint iatRva = BitConverter.ToUInt32(mappedImage, descOffset + 12);
                    uint intRva = BitConverter.ToUInt32(mappedImage, descOffset + 16);

                    // Terminator Check (Alles 0)
                    if (nameRva == 0 && iatRva == 0 && intRva == 0) break;

                    string dllName = ReadString(mappedImage, (int)nameRva);
                    if (string.IsNullOrEmpty(dllName))
                    {
                        descOffset += descSize;
                        continue;
                    }

                    // Zielmodul finden
                    var targetMod = allModules.FirstOrDefault(m => m.BaseDllName.Equals(dllName, StringComparison.OrdinalIgnoreCase));

                    int iatOffset = (int)iatRva;
                    int intOffset = (int)intRva; // Namen kommen aus der INT

                    while (intOffset + ptrSize <= mappedImage.Length)
                    {
                        // Lese Name Pointer (INT) und aktuellen Wert (IAT)
                        ulong nameVal = is64
                            ? BitConverter.ToUInt64(mappedImage, intOffset)
                            : BitConverter.ToUInt32(mappedImage, intOffset);

                        if (nameVal == 0) break; // Ende der Tabelle

                        var entry = new PeImports.ImportEntry
                        {
                            IatRva = (uint)iatOffset,
                            ModuleName = dllName
                        };

                        // Ordinal Check
                        bool isOrdinal = is64
                            ? (nameVal & 0x8000000000000000) != 0
                            : (nameVal & 0x80000000) != 0;

                        if (isOrdinal)
                        {
                            entry.IsOrdinal = true;
                            entry.Ordinal = (uint)(nameVal & 0xFFFF);
                            entry.FunctionName = $"#{entry.Ordinal}";
                        }
                        else
                        {
                            // Name RVA + 2 (Hint überspringen)
                            int pName = (int)(nameVal & 0x7FFFFFFF);
                            if (pName + 2 < mappedImage.Length)
                            {
                                entry.FunctionName = ReadString(mappedImage, pName + 2);
                            }
                        }

                        // Auflösung (Nur wenn Modul geladen ist!)
                        // Bei Delayed Imports ist es normal, dass das Modul NICHT geladen ist.
                        // In dem Fall ist ExpectedAddress 0, und wir ignorieren es später.
                        if (targetMod != null && !string.IsNullOrEmpty(entry.FunctionName))
                        {
                            // Wir nutzen unsere bestehende Logik aus PeImports/PeExports (Rekursion etc.)
                            // Dazu müssen wir ResolveImportAddress "public" machen oder hier duplizieren.
                            // Da wir sauber arbeiten, duplizieren wir die Logik hier minimal über PeExports.

                            // Wir rufen hier die Helper Methode auf, die wir gleich definieren
                            entry.ExpectedAddress = ResolveDelayImport(targetMod, entry.FunctionName, allModules);
                        }

                        imports.Add(entry);

                        iatOffset += ptrSize;
                        intOffset += ptrSize;
                    }

                    descOffset += descSize;
                }
            }
            catch { }

            return imports;
        }

        private static IntPtr ResolveDelayImport(ProcessModuleInfo module, string funcName, List<ProcessModuleInfo> allModules, int depth = 0)
        {
            if (depth > 5) return IntPtr.Zero;

            string path = module.FullDllName;
            if (string.IsNullOrEmpty(path) || !System.IO.File.Exists(path))
            {
                path = System.IO.Path.Combine(Environment.SystemDirectory, module.BaseDllName);
                if (!System.IO.File.Exists(path)) return IntPtr.Zero;
            }

            // Wieder: Golden Image laden
            byte[] targetImage = PeMapper.MapFile(path);
            if (targetImage == null) return IntPtr.Zero;

            var export = PE.Export.PeExports.GetExportEntry(targetImage, funcName);

            if (export.FunctionRva == 0 && !export.IsForwarder) return IntPtr.Zero;

            if (export.IsForwarder)
            {
                // Forwarder Auflösung (Kopie der Logik, um Abhängigkeiten gering zu halten)
                string fwd = export.ForwarderString;
                int dot = fwd.IndexOf('.');
                if (dot > 0)
                {
                    string nextDll = fwd.Substring(0, dot);
                    string nextFunc = fwd.Substring(dot + 1);
                    if (!nextDll.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) nextDll += ".dll";

                    var nextMod = allModules.FirstOrDefault(m => m.BaseDllName.Equals(nextDll, StringComparison.OrdinalIgnoreCase));
                    if (nextMod != null)
                    {
                        return ResolveDelayImport(nextMod, nextFunc, allModules, depth + 1);
                    }
                }
                return IntPtr.Zero;
            }

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