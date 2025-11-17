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
using NativeProcesses.Core.Engine;
using NativeProcesses.Core.Models;
using NativeProcesses.Core.Native;

namespace NativeProcesses.Core.Inspection
{
    public class PeAnomalyInfo
    {
        public string ModuleName { get; set; }
        public string AnomalyType { get; set; }
        public string Details { get; set; }
        public string Severity { get; set; }
    }

    public class PeAnomalyScanner
    {
        private readonly IEngineLogger _logger;

        public PeAnomalyScanner(IEngineLogger logger)
        {
            _logger = logger;
        }

        public List<PeAnomalyInfo> ScanModule(ManagedProcess process, ProcessModuleInfo module)
        {
            var anomalies = new List<PeAnomalyInfo>();

            if (string.IsNullOrEmpty(module.FullDllName) || !File.Exists(module.FullDllName))
            {
                return anomalies;
            }

            try
            {
                // 1. Header Reading (Disk vs Memory)
                byte[] diskHeaderBuffer = ReadHeaderFromDisk(module.FullDllName);
                byte[] memoryHeaderBuffer = process.ReadMemory(module.DllBase, 4096); // Read first page

                if (diskHeaderBuffer == null || memoryHeaderBuffer == null || diskHeaderBuffer.Length < 512 || memoryHeaderBuffer.Length < 512)
                {
                    return anomalies;
                }

                // 2. Check Header Stomping (MZ Signature)
                CheckHeaderStomping(module, diskHeaderBuffer, memoryHeaderBuffer, anomalies);

                // 3. Parse NT Headers for both
                var diskNtHeaders = ParseNtHeaders(diskHeaderBuffer);
                var memoryNtHeaders = ParseNtHeaders(memoryHeaderBuffer);

                if (diskNtHeaders.IsValid && memoryNtHeaders.IsValid)
                {
                    // 4. Check Section Anomalies (Phantom Sections / Count Mismatch)
                    CheckSectionCountMismatch(module, diskNtHeaders, memoryNtHeaders, anomalies);

                    // 5. Check EntryPoint Deviation
                    CheckEntryPointDeviation(module, diskNtHeaders, memoryNtHeaders, anomalies);

                    // 6. Scan Memory Sections for RWX (Read-Write-Execute)
                    CheckForRwxSections(process, module, memoryHeaderBuffer, memoryNtHeaders, anomalies);
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, $"PeAnomalyScanner failed for module {module.BaseDllName}", ex);
            }

            return anomalies;
        }

        private byte[] ReadHeaderFromDisk(string path)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var br = new BinaryReader(fs))
                {
                    return br.ReadBytes(4096);
                }
            }
            catch
            {
                return null;
            }
        }

        private void CheckHeaderStomping(ProcessModuleInfo module, byte[] disk, byte[] memory, List<PeAnomalyInfo> anomalies)
        {
            if (disk[0] == 'M' && disk[1] == 'Z')
            {
                if (memory[0] != 'M' || memory[1] != 'Z')
                {
                    anomalies.Add(new PeAnomalyInfo
                    {
                        ModuleName = module.BaseDllName,
                        AnomalyType = "Header Stomping",
                        Details = $"MZ signature missing in memory (0x{memory[0]:X} 0x{memory[1]:X}), but present on disk.",
                        Severity = "High"
                    });
                }
                else
                {
                    // Advanced Stomping Check: Compare PE Header Checksum or e_lfanew
                    int e_lfanew_disk = BitConverter.ToInt32(disk, 0x3C);
                    int e_lfanew_mem = BitConverter.ToInt32(memory, 0x3C);

                    if (e_lfanew_disk != e_lfanew_mem)
                    {
                        anomalies.Add(new PeAnomalyInfo
                        {
                            ModuleName = module.BaseDllName,
                            AnomalyType = "Header Modification",
                            Details = $"PE Header offset (e_lfanew) modified. Disk: 0x{e_lfanew_disk:X}, Memory: 0x{e_lfanew_mem:X}",
                            Severity = "Medium"
                        });
                    }
                }
            }
        }

        private void CheckSectionCountMismatch(ProcessModuleInfo module, NtHeaderInfo disk, NtHeaderInfo memory, List<PeAnomalyInfo> anomalies)
        {
            if (memory.NumberOfSections != disk.NumberOfSections)
            {
                anomalies.Add(new PeAnomalyInfo
                {
                    ModuleName = module.BaseDllName,
                    AnomalyType = "Section Count Mismatch",
                    Details = $"Sections in Memory: {memory.NumberOfSections}, Sections on Disk: {disk.NumberOfSections}. Potential Process Hollowing.",
                    Severity = "High"
                });
            }
        }

        private void CheckEntryPointDeviation(ProcessModuleInfo module, NtHeaderInfo disk, NtHeaderInfo memory, List<PeAnomalyInfo> anomalies)
        {
            if (memory.AddressOfEntryPoint != disk.AddressOfEntryPoint)
            {
                anomalies.Add(new PeAnomalyInfo
                {
                    ModuleName = module.BaseDllName,
                    AnomalyType = "Entry Point Redirection",
                    Details = $"EP Memory: 0x{memory.AddressOfEntryPoint:X}, EP Disk: 0x{disk.AddressOfEntryPoint:X}. Code Injection Indicator.",
                    Severity = "High"
                });
            }
        }

        private void CheckForRwxSections(ManagedProcess process, ProcessModuleInfo module, byte[] memoryBuffer, NtHeaderInfo headerInfo, List<PeAnomalyInfo> anomalies)
        {
            try
            {
                int sectionHeaderOffset = headerInfo.SectionHeaderOffset;
                int numberOfSections = headerInfo.NumberOfSections;
                int sectionSize = 40; // IMAGE_SECTION_HEADER size

                for (int i = 0; i < numberOfSections; i++)
                {
                    int currentOffset = sectionHeaderOffset + (i * sectionSize);
                    if (currentOffset + sectionSize > memoryBuffer.Length) break;

                    // IMAGE_SECTION_HEADER:
                    // 0x08: VirtualSize (uint)
                    // 0x0C: VirtualAddress (uint)
                    // 0x24: Characteristics (uint)

                    uint virtualAddress = BitConverter.ToUInt32(memoryBuffer, currentOffset + 12);
                    uint virtualSize = BitConverter.ToUInt32(memoryBuffer, currentOffset + 8);
                    uint characteristics = BitConverter.ToUInt32(memoryBuffer, currentOffset + 36);

                    // IMAGE_SCN_MEM_EXECUTE (0x20000000) | IMAGE_SCN_MEM_WRITE (0x80000000)
                    bool isExecute = (characteristics & 0x20000000) != 0;
                    bool isWrite = (characteristics & 0x80000000) != 0;

                    if (isExecute && isWrite)
                    {
                        string name = System.Text.Encoding.ASCII.GetString(memoryBuffer, currentOffset, 8).TrimEnd('\0');

                        // --- NEU: SHELLCODE HEURISTIK (Hasherezade-Style) ---
                        // Wir lesen den Inhalt der Sektion, um False Positives zu vermeiden.
                        // Wir lesen nur die ersten 4096 Bytes der Sektion, das reicht meist für Signaturen.

                        try
                        {
                            long readSize = Math.Min(virtualSize, 4096);
                            if (readSize > 0)
                            {
                                // Berechne absolute Adresse im Prozess: DllBase + VirtualAddress
                                IntPtr sectionAddress = IntPtr.Add(module.DllBase, (int)virtualAddress);
                                byte[] sectionContent = process.ReadMemory(sectionAddress, (int)readSize);

                                // Nutze den neuen Detector
                                if (ShellcodeDetector.IsLikelyShellcode(sectionContent, out string reason))
                                {
                                    anomalies.Add(new PeAnomalyInfo
                                    {
                                        ModuleName = module.BaseDllName,
                                        AnomalyType = "Malicious RWX Section",
                                        Details = $"Section '{name}' is RWX and contains suspicious data: {reason}",
                                        Severity = "Critical"
                                    });
                                }
                                else
                                {
                                    // Wenn es RWX ist, aber leer oder harmlos, loggen wir es als "Warning" statt Critical
                                    // Das ist typisch für .NET JIT oder leere Padding-Sektionen
                                    /* Optional: Wir könnten das hier ganz weglassen, um noch weniger Noise zu haben.
                                       Aber RWX ist prinzipiell schlecht, daher behalte ich es als Low/Medium bei.
                                    */
                                   
                                    anomalies.Add(new PeAnomalyInfo
                                    {
                                        ModuleName = module.BaseDllName,
                                        AnomalyType = "RWX Section (Benign?)",
                                        Details = $"Section '{name}' is RWX but appears empty or clean. (JIT?)",
                                        Severity = "Low"
                                    });
                                    
                                }
                            }
                        }
                        catch
                        {
                            // Lesen fehlgeschlagen, wir melden es sicherheitshalber trotzdem
                            anomalies.Add(new PeAnomalyInfo
                            {
                                ModuleName = module.BaseDllName,
                                AnomalyType = "RWX Section (Unreadable)",
                                Details = $"Section '{name}' is RWX but could not be scanned.",
                                Severity = "Medium"
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, "Error parsing sections for RWX check.", ex);
            }
        }
        // Helper to parse essential NT Header fields
        private NtHeaderInfo ParseNtHeaders(byte[] buffer)
        {
            var info = new NtHeaderInfo { IsValid = false };
            try
            {
                int e_lfanew = BitConverter.ToInt32(buffer, 0x3C);
                if (e_lfanew > buffer.Length - 256) return info;

                uint signature = BitConverter.ToUInt32(buffer, e_lfanew);
                if (signature != 0x00004550) return info; // "PE\0\0"

                // File Header starts at e_lfanew + 4
                // NumberOfSections is at offset 2 inside File Header
                info.NumberOfSections = BitConverter.ToUInt16(buffer, e_lfanew + 4 + 2);

                // SizeOfOptionalHeader is at offset 16 inside File Header
                ushort sizeOfOptionalHeader = BitConverter.ToUInt16(buffer, e_lfanew + 4 + 16);

                // Optional Header starts at e_lfanew + 4 + 20 (FileHeader Size)
                int optionalHeaderOffset = e_lfanew + 24;

                // Magic is first 2 bytes of Optional Header
                ushort magic = BitConverter.ToUInt16(buffer, optionalHeaderOffset);
                bool is64Bit = (magic == 0x20B);

                // AddressOfEntryPoint offset: 
                // 32-bit: 16 bytes into OptionalHeader
                // 64-bit: 16 bytes into OptionalHeader
                info.AddressOfEntryPoint = BitConverter.ToUInt32(buffer, optionalHeaderOffset + 16);

                // Calculate where Section Headers start
                info.SectionHeaderOffset = optionalHeaderOffset + sizeOfOptionalHeader;
                info.IsValid = true;
            }
            catch
            {
                info.IsValid = false;
            }
            return info;
        }

        private class NtHeaderInfo
        {
            public bool IsValid;
            public int NumberOfSections;
            public uint AddressOfEntryPoint;
            public int SectionHeaderOffset;
        }
    }
}