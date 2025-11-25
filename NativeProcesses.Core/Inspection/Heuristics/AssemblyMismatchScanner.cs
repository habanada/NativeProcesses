/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Microsoft.Diagnostics.Runtime;
using NativeProcesses.Core.PE;
using NativeProcesses.Core.PE.Loader;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NativeProcesses.Core.Inspection.Heuristics
{
    public class AssemblyMismatchScanner
    {
        public IEnumerable<HeuristicResult> Scan(ClrRuntime runtime)
        {
            var results = new List<HeuristicResult>();
            var dataReader = runtime.DataTarget.DataReader;

            foreach (var module in runtime.EnumerateModules())
            {
                // Wir prüfen nur Module mit Datei-Bindung (keine Dynamic/Floating Modules)
                if (module.IsDynamic || module.Layout == ModuleLayout.Flat) continue;

                string path = module.Name;
                if (string.IsNullOrEmpty(path) || !File.Exists(path)) continue;

                // Optimierung: System-Assemblies überspringen (außer im Paranoid-Mode)
                // Malware versteckt sich selten IN mscorlib.dll selbst, sondern ersetzt den Prozess.
                // Aber RunPE auf System-Binaries ist häufig -> Wir scannen alles außer dem Framework-Kern, wenn möglich.
                // Hier scannen wir alles, was wir lesen können.

                try
                {
                    // 1. Golden Image laden (Disk -> Virtual Memory Layout)
                    byte[] rawFile = File.ReadAllBytes(path);
                    byte[] goldenImage = PeLoader.MapRawToVirtual(rawFile);

                    if (goldenImage == null) continue;

                    // 2. Relocations anwenden (auf die Speicheradresse im Prozess anpassen)
                    // Wenn wir das nicht tun, sind alle Pointer unterschiedlich und wir kriegen False Positives.
                    RelocationsFixer.ApplyRelocations(goldenImage, module.ImageBase);

                    // 3. Speicher aus dem Prozess lesen
                    // Wir lesen nur so viel, wie das Image groß sein sollte
                    int imageSize = goldenImage.Length;
                    byte[] memoryImage = new byte[imageSize];
                    int bytesRead = dataReader.Read(module.ImageBase, new Span<byte>(memoryImage));

                    if (bytesRead < 512) continue; // Read Error

                    // 4. Vergleich: Header (RunPE Detection)
                    // Wenn der Header im Speicher anders ist als auf Disk -> Hollowing!
                    if (!CompareHeaders(goldenImage, memoryImage))
                    {
                        results.Add(new HeuristicResult(
                           "Process Hollowing / RunPE",
                           ScanCategory.CodeInjection,
                           ThreatScore.Critical,
                           $"Module header in memory does not match disk file. Process has been hollowed out or replaced.",
                           module.ImageBase.ToString("X"),
                           $"File: {Path.GetFileName(path)}"
                       ));
                        continue; // Wenn Header schon falsch ist, brauchen wir Sections nicht prüfen
                    }

                    // 5. Vergleich: Code Sections (.text) (Patching / Unpacking Detection)
                    var anomalies = CheckSections(goldenImage, memoryImage);
                    if (anomalies != null)
                    {
                        results.Add(new HeuristicResult(
                            "In-Memory Patching / Unpacked Code",
                            ScanCategory.CodeInjection,
                            ThreatScore.High,
                            $"Code section (.text) modified in memory. {anomalies}",
                            module.ImageBase.ToString("X"),
                            $"File: {Path.GetFileName(path)}"
                        ));
                    }
                }
                catch
                {
                    // Zugriffsprobleme auf Datei oder Speicher -> Ignorieren
                }
            }

            return results;
        }

        private bool CompareHeaders(byte[] disk, byte[] mem)
        {
            // Wir vergleichen DOS Header und NT Signature
            // Das reicht für RunPE Erkennung (dort wird meist der ganze Header überschrieben)
            // Wir ignorieren volatile Felder wie CheckSum oder TimeDateStamp, 
            // aber EntryPoint und SizeOfImage müssen stimmen.

            int e_lfanew = BitConverter.ToInt32(disk, 0x3C);

            // Vergleich DOS Header (erste 64 Bytes)
            if (!CompareBlock(disk, mem, 0, 64)) return false;

            // Vergleich NT Header Signature (PE\0\0)
            if (!CompareBlock(disk, mem, e_lfanew, 4)) return false;

            // OptionalHeader: EntryPoint vergleichen (Offset 16 in OptionalHeader)
            // OptionalHeader start = e_lfanew + 4 (Sig) + 20 (FileHeader) = +24
            int epOffset = e_lfanew + 24 + 16;

            // Bei .NET Assemblies ist der EntryPoint im Header oft nur ein Stub, 
            // aber er sollte zwischen Disk und Memory identisch sein (nach Relocs).
            // Wenn RunPE passiert, zeigt der EntryPoint woanders hin.
            if (!CompareBlock(disk, mem, epOffset, 4)) return false;

            return true;
        }

        private string CheckSections(byte[] disk, byte[] mem)
        {
            // Wir parsen die Sektionen vom DISK Image (dem vertrauen wir)
            int e_lfanew = BitConverter.ToInt32(disk, 0x3C);
            int fileHeaderOffset = e_lfanew + 4;
            ushort numberOfSections = BitConverter.ToUInt16(disk, fileHeaderOffset + 2);
            ushort sizeOfOptionalHeader = BitConverter.ToUInt16(disk, fileHeaderOffset + 16);
            int sectionTableStart = fileHeaderOffset + 20 + sizeOfOptionalHeader;
            int sectionSize = 40; // IMAGE_SECTION_HEADER

            for (int i = 0; i < numberOfSections; i++)
            {
                int offset = sectionTableStart + (i * sectionSize);

                // Name lesen (8 Bytes)
                string name = System.Text.Encoding.UTF8.GetString(disk, offset, 8).TrimEnd('\0');
                uint virtualAddr = BitConverter.ToUInt32(disk, offset + 12);
                uint virtualSize = BitConverter.ToUInt32(disk, offset + 8);
                uint characteristics = BitConverter.ToUInt32(disk, offset + 36);

                // Wir prüfen nur EXECUTABLE Sections (.text)
                // Data-Sections (.data) ändern sich natürlich, das ist kein Alarm.
                bool isExec = (characteristics & 0x20000000) != 0;

                if (isExec)
                {
                    // Vergleich
                    int diffCount = 0;
                    int scanLen = (int)Math.Min(virtualSize, 10000); // Performance Limit (erste 10KB reichen oft)

                    for (int k = 0; k < scanLen; k++)
                    {
                        int idx = (int)virtualAddr + k;
                        if (idx >= disk.Length || idx >= mem.Length) break;

                        if (disk[idx] != mem[idx]) diffCount++;
                    }

                    // Toleranz: Ein paar Bytes können durch Runtime-Patches (JIT Hooks etc.) anders sein.
                    // Aber wenn > 5% oder > 50 Bytes anders sind -> Alarm.
                    if (diffCount > 50)
                    {
                        return $"Section '{name}' has {diffCount} modified bytes (potential inline hooks/unpacking).";
                    }
                }
            }
            return null;
        }

        private bool CompareBlock(byte[] a, byte[] b, int offset, int len)
        {
            if (offset + len > a.Length || offset + len > b.Length) return false;
            for (int i = 0; i < len; i++)
            {
                if (a[offset + i] != b[offset + i]) return false;
            }
            return true;
        }
    }
}