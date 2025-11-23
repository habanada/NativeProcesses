///*
//   NativeProcesses Framework
//   PeAnomalyScanner.cs - Advanced In-Memory Scanner (pe-sieve style)
//   Uses the new PeLoader Core for 1:1 comparison of Disk vs Memory.
//*/
//using System;
//using System.Collections.Generic;
//using System.IO;
//using System.Linq;
//using System.Runtime.InteropServices;
//using NativeProcesses.Core.Engine;
//using NativeProcesses.Core.Models;
//using NativeProcesses.Core.Native;
//using NativeProcesses.Core.PE;
//using NativeProcesses.Core.PE.Loader;

//namespace NativeProcesses.Core.Inspection
//{
//    public class PeAnomalyScanner
//    {
//        private readonly IEngineLogger _logger;

//        public PeAnomalyScanner(IEngineLogger logger)
//        {
//            _logger = logger;
//        }

//        /// <summary>
//        /// Vergleicht das Modul im Speicher mit der Datei auf der Festplatte.
//        /// Erkennt Inline Hooks, Code Patches und Header Stomping.
//        /// </summary>
//        public List<PeAnomalyInfo> ScanModule(ManagedProcess process, ProcessModuleInfo module)
//        {
//            var anomalies = new List<PeAnomalyInfo>();

//            // 1. Validierung
//            if (string.IsNullOrEmpty(module.FullDllName) || !File.Exists(module.FullDllName))
//            {
//                return anomalies; // Können wir nicht scannen (z.B. Phantom Module ohne Disk-Backing werden vom VadScanner erkannt)
//            }

//            byte[] rawFile = null;
//            byte[] localImage = null;
//            byte[] remoteImage = null;

//            try
//            {
//                // 2. Referenz erstellen (Golden Image)
//                // A. Datei lesen
//                try
//                {
//                    rawFile = File.ReadAllBytes(module.FullDllName);
//                }
//                catch (IOException)
//                {
//                    // Datei gesperrt -> Versuche Schattenkopie oder Skip
//                    return anomalies;
//                }

//                // B. Mappen (Raw -> Virtual)
//                localImage = PeLoader.MapRawToVirtual(rawFile);
//                if (localImage == null) return anomalies; // Kaputte PE Datei

//                // C. Relocaten (An die Remote-Adresse anpassen)
//                // Das ist der Trick: Wir tun so, als wäre unsere lokale Kopie an der Adresse des Remote-Prozesses geladen.
//                if (!RelocationsFixer.ApplyRelocations(localImage, (ulong)module.DllBase.ToInt64()))
//                {
//                    // Relocs fehlgeschlagen oder nicht nötig (z.B. ASLR deaktiviert oder ImageBase passt zufällig).
//                    // Wir machen weiter, aber markieren das Risiko.
//                }

//                // 3. Remote Image lesen
//                // Wir lesen so viel, wie das lokale Image groß ist (SizeOfImage Header vs Realität)
//                remoteImage = process.ReadMemory(module.DllBase, localImage.Length);

//                if (remoteImage == null || remoteImage.Length < 512)
//                {
//                    anomalies.Add(new PeAnomalyInfo
//                    {
//                        ModuleName = module.BaseDllName,
//                        AnomalyType = "Read Error / Protected",
//                        Details = "Could not read module memory. Possible Anti-Cheats or Protected Process.",
//                        Severity = "Low"
//                    });
//                    return anomalies;
//                }

//                // 4. Header Scan (Stomping Detection)
//                // Vergleich der ersten 1024 Bytes (Header Bereich)
//                CheckHeaders(module, localImage, remoteImage, anomalies);

//                // 5. Section Scan (Code Patching / Inline Hooks)
//                // Wir müssen die Sektions-Tabelle parsen, um zu wissen, wo Code (.text) und wo Daten (.data) sind.
//                CheckSections(module, localImage, remoteImage, anomalies);

//            }
//            catch (Exception ex)
//            {
//                _logger?.Log(LogLevel.Debug, $"Deep Scan failed for {module.BaseDllName}", ex);
//            }

//            return anomalies;
//        }

//        private void CheckHeaders(ProcessModuleInfo module, byte[] local, byte[] remote, List<PeAnomalyInfo> anomalies)
//        {
//            // Einfacher Check: Wurde der MZ-Header überschrieben? (Häufige Malware-Technik "Header Stomping")
//            // Wir prüfen die ersten 2 Bytes.
//            if (remote[0] != 'M' || remote[1] != 'Z')
//            {
//                // Ist es komplett genullt?
//                bool isZero = remote.Take(32).All(b => b == 0);

//                anomalies.Add(new PeAnomalyInfo
//                {
//                    ModuleName = module.BaseDllName,
//                    AnomalyType = "Header Stomping",
//                    Details = isZero ? "PE Header erased (Zeroed out)." : "PE Header overwritten with garbage/shellcode.",
//                    Severity = "High"
//                });
//            }
//            else
//            {
//                // Wenn MZ da ist, prüfen wir auf Modifikationen im NT Header (z.B. EntryPoint Change)
//                // Hier könnten wir tiefer gehen, aber MZ-Check fängt 90% ab.
//            }
//        }

//        private void CheckSections(ProcessModuleInfo module, byte[] local, byte[] remote, List<PeAnomalyInfo> anomalies)
//        {
//            // Wir müssen die Sektionen aus dem LOKALEN Image parsen (da wir dem Remote Header nicht trauen)
//            GCHandle handle = GCHandle.Alloc(local, GCHandleType.Pinned);
//            try
//            {
//                IntPtr basePtr = handle.AddrOfPinnedObject();
//                var dos = Marshal.PtrToStructure<PeHeaders.IMAGE_DOS_HEADER>(basePtr);

//                if (!dos.IsValid) return; // Sollte nicht passieren, da MapRawToVirtual erfolgreich war

//                IntPtr ntPtr = IntPtr.Add(basePtr, dos.e_lfanew);
//                IntPtr fileHeaderPtr = IntPtr.Add(ntPtr, 4);
//                var fileHeader = Marshal.PtrToStructure<PeHeaders.IMAGE_FILE_HEADER>(fileHeaderPtr);

//                IntPtr optHeaderPtr = IntPtr.Add(fileHeaderPtr, Marshal.SizeOf<PeHeaders.IMAGE_FILE_HEADER>());
//                ushort magic = (ushort)Marshal.ReadInt16(optHeaderPtr);

//                // Bereich der IAT (Import Address Table) finden, um False Positives zu vermeiden
//                // Die IAT ändert sich IMMER zur Laufzeit (vom OS Loader gefüllt), daher dürfen wir sie nicht vergleichen.
//                Range iatRange = GetIatRange(basePtr, optHeaderPtr, magic);

//                // Sektionen finden
//                int sectionHeadersOffset = dos.e_lfanew + 4 + Marshal.SizeOf<PeHeaders.IMAGE_FILE_HEADER>() + fileHeader.SizeOfOptionalHeader;
//                int sectionSize = Marshal.SizeOf<PeHeaders.IMAGE_SECTION_HEADER>();

//                for (int i = 0; i < fileHeader.NumberOfSections; i++)
//                {
//                    IntPtr secPtr = IntPtr.Add(basePtr, sectionHeadersOffset + (i * sectionSize));
//                    var section = Marshal.PtrToStructure<PeHeaders.IMAGE_SECTION_HEADER>(secPtr);

//                    // FILTER: Wir scannen nur EXECUTABLE Sektionen (.text)
//                    // Änderungen in .data oder .rsrc sind normal (Variablen).
//                    // IMAGE_SCN_MEM_EXECUTE = 0x20000000
//                    bool isExecutable = (section.Characteristics & 0x20000000) != 0;
//                    bool isWritable = (section.Characteristics & 0x80000000) != 0;

//                    // Ausnahme: Wenn eine Sektion Executable UND Writable ist, ist das per se verdächtig, aber wir vergleichen trotzdem.
//                    if (isExecutable)
//                    {
//                        int start = (int)section.VirtualAddress;
//                        int size = (int)Math.Min(section.VirtualSize, section.SizeOfRawData);

//                        // Sicherstellen, dass wir nicht out-of-bounds lesen
//                        if (start + size > local.Length || start + size > remote.Length) continue;

//                        // Byte-Vergleich
//                        int diffCount = 0;
//                        // Wir nehmen an, dass Inline Hooks meist am Anfang von Funktionen stehen (JMP = 0xE9)
//                        // Ein vollständiger Diff ist teuer, wir scannen linear.

//                        for (int k = 0; k < size; k++)
//                        {
//                            int offset = start + k;

//                            // IGNORIEREN: IAT Bereich (Loader-spezifische Adressen)
//                            if (offset >= iatRange.Start && offset < iatRange.End) continue;

//                            // IGNORIEREN: Export Table (manchmal gepatcht von Loadern) - Optional

//                            if (local[offset] != remote[offset])
//                            {
//                                diffCount++;
//                            }
//                        }

//                        if (diffCount > 0)
//                        {
//                            // Heuristik: Ein paar Bytes Unterschied können Relocations sein, die wir falsch berechnet haben 
//                            // (sehr unwahrscheinlich mit RelocationsFixer) oder Padding.
//                            // Aber Inline Hooks sind meist 5 Bytes (JMP) oder 12 Bytes (MOV RAX, JMP RAX).

//                            string severity = "Medium";
//                            string type = "Code Patching";

//                            if (isWritable)
//                            {
//                                type += " (RWX Section)";
//                                severity = "High";
//                            }

//                            // Wenn sehr viele Bytes anders sind, wurde die Sektion vielleicht komplett überschrieben (Hollowing light)
//                            if (diffCount > 100)
//                            {
//                                severity = "Critical";
//                                type = "Section Replcaement / Hollowing";
//                            }

//                            anomalies.Add(new PeAnomalyInfo
//                            {
//                                ModuleName = module.BaseDllName,
//                                AnomalyType = type,
//                                Details = $"Found {diffCount} modified bytes in section '{section.Name}'. Potential Inline Hook or Shellcode injection.",
//                                Severity = severity
//                            });
//                        }
//                    }
//                }
//            }
//            finally
//            {
//                handle.Free();
//            }
//        }

//        private struct Range { public uint Start; public uint End; }

//        private Range GetIatRange(IntPtr basePtr, IntPtr optHeaderPtr, ushort magic)
//        {
//            uint iatRva = 0;
//            uint iatSize = 0;

//            // IMAGE_DIRECTORY_ENTRY_IAT ist Index 12
//            int directoryOffset = 12 * 8;

//            if (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
//            {
//                // OptionalHeader64: DataDirectories starten bei Offset 112
//                var opt64 = Marshal.PtrToStructure<PeHeaders.IMAGE_OPTIONAL_HEADER64>(optHeaderPtr);
//                if (opt64.NumberOfRvaAndSizes > 12)
//                {
//                    iatRva = opt64.DataDirectory[12].VirtualAddress;
//                    iatSize = opt64.DataDirectory[12].Size;
//                }
//            }
//            else
//            {
//                // OptionalHeader32: DataDirectories starten bei Offset 96
//                var opt32 = Marshal.PtrToStructure<PeHeaders.IMAGE_OPTIONAL_HEADER32>(optHeaderPtr);
//                if (opt32.NumberOfRvaAndSizes > 12)
//                {
//                    iatRva = opt32.DataDirectory[12].VirtualAddress;
//                    iatSize = opt32.DataDirectory[12].Size;
//                }
//            }

//            return new Range { Start = iatRva, End = iatRva + iatSize };
//        }
//    }
//}