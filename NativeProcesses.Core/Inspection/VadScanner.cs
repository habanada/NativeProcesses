/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
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
using static NativeProcesses.Core.Native.ManagedProcess;
using static NativeProcesses.Core.Native.NativeDefinitions;

namespace NativeProcesses.Core.Inspection
{
    public class PhantomModuleInfo
    {
        public IntPtr BaseAddress;
        public long Size;
        public string NtPath;
        public bool IsExecutable;
        public string DetectionMethod;
        public string Severity;
        public string Details;
    }

    public class VadScanner
    {
        private readonly IEngineLogger _logger;

        public VadScanner(IEngineLogger logger)
        {
            _logger = logger;
        }

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            int MemoryInformationClass,
            IntPtr MemoryInformation,
            UIntPtr MemoryInformationLength,
            out UIntPtr ReturnLength);

        /// <summary>
        /// Führt einen tiefen VAD-Walk durch (NtQueryVirtualMemory Loop).
        /// </summary>
        public List<VirtualMemoryRegion> GetDeepMemoryRegions(ManagedProcess process)
        {
            var regions = new List<VirtualMemoryRegion>();
            long currentAddress = 0;
            long maxAddress = Environment.Is64BitProcess ? 0x7FFFFFFFFFFF : 0x7FFFFFFF;

            int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            IntPtr buffer = Marshal.AllocHGlobal(mbiSize);

            try
            {
                while (currentAddress < maxAddress)
                {
                    int status = NtQueryVirtualMemory(
                        process.Handle,
                        (IntPtr)currentAddress,
                        NativeDefinitions.MemoryInformationClass.MemoryBasicInformation,
                        buffer,
                        (UIntPtr)mbiSize,
                        out _
                    );

                    if (status != 0) break;

                    var mbi = Marshal.PtrToStructure<MEMORY_BASIC_INFORMATION>(buffer);
                    long size = (long)mbi.RegionSize;
                    if (size <= 0) break;

                    // Nur committed Pages interessieren uns
                    if (mbi.State == (uint)MemoryState.MEM_COMMIT)
                    {
                        regions.Add(new VirtualMemoryRegion(
                            mbi.BaseAddress,
                            mbi.AllocationBase,
                            size,
                            mbi.State,
                            mbi.Type,
                            mbi.Protect,
                            mbi.AllocationProtect
                        ));
                    }

                    long nextAddress = (long)mbi.BaseAddress + size;
                    if (nextAddress <= currentAddress) break; // Overflow Schutz
                    currentAddress = nextAddress;
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, "VadScanner.GetDeepMemoryRegions failed.", ex);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return regions;
        }
        /// <summary>
        /// Scannt nach manuellen Syscall-Stubs (Hell's Gate / JIT Trampolines).
        /// Sucht nach dem Muster: MOV R10, RCX; MOV EAX, <SSN>; SYSCALL
        /// </summary>
        public List<PeAnomalyInfo> ScanForSyscallStubs(ManagedProcess process)
        {
            var anomalies = new List<PeAnomalyInfo>();
            // Syscall Signature: 
            // 4C 8B D1         (mov r10, rcx)
            // B8 ?? ?? ?? ??   (mov eax, SSN)
            // 0F 05            (syscall) - ODER - CD 2E (int 2e, alt)

            // Wir suchen nach "4C 8B D1 B8" gefolgt von "0F 05" in kurzem Abstand.

            try
            {
                // Nur Private/Commit und Executable (JIT Memory)
                var regions = process.GetVirtualMemoryRegions()
                    .Where(r => r.State == "Commit" &&
                                r.Type == "Private" &&
                                r.Protection.Contains("EXECUTE"))
                    .ToList();

                foreach (var region in regions)
                {
                    // Optimierung: JIT Methoden sind oft klein, aber der Heap ist groß.
                    // Wir lesen in Chunks oder scannen nur, wenn die Region "verdächtig" klein ist?
                    // Nein, JIT Heap ist riesig. Wir lesen Samples oder suchen gezielt.
                    // Für diesen Proof-of-Concept lesen wir die ganze Region (Vorsicht bei Performance!).

                    // Limit: Max 1MB pro Region scannen, um Performance zu schonen
                    int bytesToRead = (int)Math.Min(region.RegionSize, 1024 * 1024);
                    byte[] buffer = process.ReadMemory(region.BaseAddress, bytesToRead);
                    if (buffer == null) continue;

                    for (int i = 0; i < buffer.Length - 10; i++)
                    {
                        // Check 1: MOV R10, RCX; MOV EAX...
                        if (buffer[i] == 0x4C && buffer[i + 1] == 0x8B && buffer[i + 2] == 0xD1 && buffer[i + 3] == 0xB8)
                        {
                            // Check 2: SYSCALL (0F 05) an Offset +8 (4C 8B D1 + B8 SSN_4byte)
                            // Stub: [4C 8B D1] [B8 xx xx xx xx] [0F 05]
                            // Index: 0..2       3..7             8..9

                            if (i + 9 < buffer.Length)
                            {
                                if (buffer[i + 8] == 0x0F && buffer[i + 9] == 0x05)
                                {
                                    anomalies.Add(new PeAnomalyInfo
                                    {
                                        ModuleName = "JIT Heap / Private Memory",
                                        AnomalyType = "Direct Syscall Stub Detected",
                                        Details = $"Found 'Hell's Gate' pattern at +0x{i:X} in region 0x{region.BaseAddress.ToString("X")}. This is a manually crafted syscall wrapper.",
                                        Severity = "Critical",
                                        Address = (long)region.BaseAddress + i,
                                        Size = 10
                                    });
                                    // Ein Treffer pro Region reicht
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, "Syscall scan failed.", ex);
            }

            return anomalies;
        }


        /// <summary>
        /// Scannt nach Phantom-Modulen (nicht im PEB) und bösartigem privaten Code (Shellcode/Manual Map).
        /// </summary>
        public List<PhantomModuleInfo> ScanForPhantoms(ManagedProcess process, List<ProcessModuleInfo> pebModules, string processName)
        {
            var results = new List<PhantomModuleInfo>();

            // Hole alle Memory Regions (VAD Walk)
            var regions = process.GetVirtualMemoryRegions();

            // Cache für PEB-Lookups (um "Unlinked" zu erkennen)
            var pebLookup = new HashSet<long>();
            foreach (var mod in pebModules) pebLookup.Add(mod.DllBase.ToInt64());

            IntPtr nameBuffer = Marshal.AllocHGlobal(1024);

            try
            {
                foreach (var region in regions)
                {
                    bool isImage = region.Type.Contains("Image");
                    bool isMapped = region.Type.Contains("Mapped");
                    bool isPrivate = region.Type.Contains("Private");
                    bool isExec = region.Protection.ToUpper().Contains("EXECUTE");

                    // ------------------------------------------------------------
                    // CASE 1: Unlinked Module (Hollowing / Doppelgänging)
                    // Kernel sagt "Das ist ein Image", aber PEB kennt es nicht.
                    // ------------------------------------------------------------
                    if (isImage)
                    {
                        if (!pebLookup.Contains(region.BaseAddress.ToInt64()))
                        {
                            string mappedFileName = GetMappedFileName(process.Handle, region.BaseAddress, nameBuffer, 1024);

                            // Filter: NLS Dateien sind harmlos
                            if (!string.IsNullOrEmpty(mappedFileName) && !mappedFileName.EndsWith(".nls", StringComparison.OrdinalIgnoreCase))
                            {
                                results.Add(new PhantomModuleInfo
                                {
                                    BaseAddress = region.BaseAddress,
                                    Size = region.RegionSize,
                                    NtPath = mappedFileName,
                                    IsExecutable = isExec,
                                    DetectionMethod = "Phantom Module (Unlinked)",
                                    Severity = "Critical",
                                    Details = "Module found in VAD but hidden from Process Environment Block (PEB)."
                                });
                            }
                        }
                    }
                    // ------------------------------------------------------------
                    // CASE 2: Private Executable (Code Injection / Shellcode / JIT)
                    // ------------------------------------------------------------
                    // CASE 4: Memory-Only Module (Mapped as Image, but strange path or no path)
                    if (isImage)
                    {
                        string mappedFileName = GetMappedFileName(process.Handle, region.BaseAddress, nameBuffer, 1024);

                        // Prüfe, ob der Pfad valide ist
                        bool fileExists = false;
                        try
                        {
                            string win32Path = process.ConvertNtPathToWin32Path(mappedFileName); // Du brauchst diese Helper-Methode in ManagedProcess
                            fileExists = File.Exists(win32Path);
                        }
                        catch { }

                        if (!string.IsNullOrEmpty(mappedFileName) && !fileExists)
                        {
                            // Das ist ein "Zombie Modul" oder manuell gemappt mit falschem Pfad
                            results.Add(new PhantomModuleInfo
                            {
                                BaseAddress = region.BaseAddress,
                                Size = region.RegionSize,
                                NtPath = mappedFileName,
                                IsExecutable = isExec,
                                DetectionMethod = "Unreachable File (Memory Image)",
                                Severity = "High",
                                Details = $"Memory region is mapped as IMAGE from '{mappedFileName}', but file does not exist on disk."
                            });
                        }
                    }
                    else if ((isPrivate || isMapped) && isExec)
                    {
                        // Wir lesen den Anfang der Region
                        byte[] content = null;
                        try { content = process.ReadMemory(region.BaseAddress, 4096); } catch { continue; }
                        if (content == null || content.Length < 64) continue;

                        // A. Check auf PE-Header (MZ) -> Floating Code
                        if (content[0] == 'M' && content[1] == 'Z')
                        {
                            results.Add(new PhantomModuleInfo
                            {
                                BaseAddress = region.BaseAddress,
                                Size = region.RegionSize,
                                NtPath = "Private Memory",
                                IsExecutable = true,
                                DetectionMethod = "Floating PE (MZ Header)",
                                Severity = "Critical",
                                Details = "Private memory contains a PE Header. This is a Reflective DLL Injection."
                            });
                            continue;
                        }

                        // B. Kein PE Header -> Shellcode oder JIT
                        // Wir nutzen die Heuristik, um Browser nicht rot zu markieren
                        bool isJit = ProcessHeuristics.IsLikelyJitMemory(processName, region.Protection, content);

                        // Wir können zusätzlich unseren ShellcodeDetector nutzen
                        bool hasShellcodePattern = ShellcodeDetector.IsLikelyShellcode(content, out string reason);

                        if (hasShellcodePattern && reason.Contains("CRITICAL"))
                        {
                            // Eindeutige Malware-Signatur -> IMMER Melden
                            results.Add(new PhantomModuleInfo
                            {
                                BaseAddress = region.BaseAddress,
                                Size = region.RegionSize,
                                NtPath = "Private Memory",
                                IsExecutable = true,
                                DetectionMethod = "Shellcode Pattern",
                                Severity = "Critical",
                                Details = reason
                            });
                        }
                        else if (!isJit)
                        {
                            // Kein JIT-Prozess, kein PE, aber Executable -> Verdächtig (Shellcode ohne Pattern)
                            results.Add(new PhantomModuleInfo
                            {
                                BaseAddress = region.BaseAddress,
                                Size = region.RegionSize,
                                NtPath = "Private Memory",
                                IsExecutable = true,
                                DetectionMethod = "Unbacked Executable Code",
                                Severity = "High",
                                Details = $"Anonymous executable memory in {processName}. Potential Shellcode."
                            });
                        }
                        else
                        {
                            // JIT in Browser -> Ignorieren oder als "Info" (Low) loggen
                        }
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(nameBuffer);
            }

            return results;
        }

        private string GetMappedFileName(IntPtr hProcess, IntPtr baseAddr, IntPtr buffer, int bufferSize)
        {
            int status = NtQueryVirtualMemory(hProcess, baseAddr, NativeDefinitions.MemoryInformationClass.MemoryMappedFilenameInformation, buffer, (UIntPtr)bufferSize, out _);
            if (status == 0)
            {
                var info = Marshal.PtrToStructure<NativeDefinitions.MEMORY_MAPPED_FILENAME_INFORMATION>(buffer);
                if (info.Name.Buffer != IntPtr.Zero && info.Name.Length > 0)
                    return Marshal.PtrToStringUni(info.Name.Buffer, info.Name.Length / 2);
            }
            return "";
        }
        //public List<PhantomModuleInfo> ScanForPhantoms(ManagedProcess process, List<ProcessModuleInfo> pebModules, List<VirtualMemoryRegion> regions = null)
        //{
        //    // Falls keine Regionen übergeben wurden, selbst laden
        //    if (regions == null)
        //    {
        //        regions = GetDeepMemoryRegions(process);
        //    }

        //    var results = new List<PhantomModuleInfo>();

        //    // 1. Cache für schnelle PEB-Lookups (Base Addresses)
        //    var pebLookup = new HashSet<long>();
        //    foreach (var mod in pebModules) pebLookup.Add(mod.DllBase.ToInt64());

        //    IntPtr nameBuffer = Marshal.AllocHGlobal(1024);

        //    try
        //    {
        //        foreach (var region in regions)
        //        {
        //            bool isImage = region.Type.IndexOf("Image", StringComparison.OrdinalIgnoreCase) >= 0;
        //            bool isMapped = region.Type.IndexOf("Mapped", StringComparison.OrdinalIgnoreCase) >= 0;
        //            bool isPrivate = region.Type.IndexOf("Private", StringComparison.OrdinalIgnoreCase) >= 0;
        //            bool isExec = region.Protection.IndexOf("EXECUTE", StringComparison.OrdinalIgnoreCase) >= 0;

        //            // --- CASE 1: Unlinked Module (Phantom / Doppelgänging) ---
        //            // Der Kernel sagt "Hier ist ein Image (DLL)", aber der PEB kennt es nicht.
        //            if (isImage)
        //            {
        //                long allocBase = region.AllocationBase.ToInt64();

        //                // Deduplizierung: Ein Modul besteht aus vielen Chunks, wir melden nur den ersten (Header)
        //                if (results.Any(r => r.BaseAddress.ToInt64() == allocBase)) continue;

        //                if (!pebLookup.Contains(allocBase))
        //                {
        //                    string mappedFileName = GetMappedFileName(process.Handle, region.AllocationBase, nameBuffer, 1024);

        //                    // Filtern von harmlosen Images (z.B. sprachabhängige Ressourcen)
        //                    if (!mappedFileName.EndsWith(".nls", StringComparison.OrdinalIgnoreCase))
        //                    {
        //                        results.Add(new PhantomModuleInfo
        //                        {
        //                            BaseAddress = region.AllocationBase,
        //                            Size = region.RegionSize,
        //                            NtPath = mappedFileName,
        //                            IsExecutable = isExec,
        //                            DetectionMethod = "Phantom Module (Unlinked from PEB)",
        //                            Details = "Module exists in kernel VAD but is hidden from PEB list (Hollowing/Doppelgänging)."
        //                        });
        //                    }
        //                }
        //            }
        //            // --- CASE 2: Private/Mapped Executable Memory (Injection / Shellcode) ---
        //            else if ((isPrivate || isMapped) && isExec)
        //            {
        //                // Wir scannen nur den Anfang der Region (Shellcode Entrypoint ist meist vorne)
        //                if (results.Any(r => r.BaseAddress == region.BaseAddress)) continue;

        //                // Inhalt lesen für Analyse
        //                byte[] content = null;
        //                try
        //                {
        //                    // Lese max 4KB für Signaturen
        //                    content = process.ReadMemory(region.BaseAddress, 4096);
        //                }
        //                catch { continue; }

        //                if (content == null || content.Length < 64) continue;

        //                // A. Check auf "MZ" Header (Manual Mapped PE / Reflective DLL)
        //                if (content[0] == 'M' && content[1] == 'Z')
        //                {
        //                    string mappedFileName = GetMappedFileName(process.Handle, region.BaseAddress, nameBuffer, 1024);
        //                    results.Add(new PhantomModuleInfo
        //                    {
        //                        BaseAddress = region.BaseAddress,
        //                        Size = region.RegionSize,
        //                        NtPath = mappedFileName,
        //                        IsExecutable = true,
        //                        DetectionMethod = "Manually Mapped PE",
        //                        Details = "Private memory contains PE Header (MZ). Reflective DLL Injection detected."
        //                    });
        //                    continue;
        //                }

        //                // B. Check auf Shellcode (mit neuem Detector)
        //                // Wir filtern JIT Code (Browsers, .NET) hier aus, um False Positives zu vermeiden.
        //                if (ShellcodeDetector.IsLikelyShellcode(content, out string reason))
        //                {
        //                    if (reason != "Clean")
        //                    {
        //                        results.Add(new PhantomModuleInfo
        //                        {
        //                            BaseAddress = region.BaseAddress,
        //                            Size = region.RegionSize,
        //                            NtPath = "Private Memory",
        //                            IsExecutable = true,
        //                            DetectionMethod = "Malicious Shellcode Pattern",
        //                            Details = reason // z.B. "Metasploit Pattern" oder "High Entropy"
        //                        });
        //                    }
        //                }
        //            }
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        _logger?.Log(LogLevel.Error, "ScanForPhantoms failed.", ex);
        //    }
        //    finally
        //    {
        //        Marshal.FreeHGlobal(nameBuffer);
        //    }

        //    return results;
        //}

        private string GetMappedFileName_Old(IntPtr hProcess, IntPtr baseAddr, IntPtr buffer, int bufferSize)
        {
            int status = NtQueryVirtualMemory(
                hProcess,
                baseAddr,
                NativeDefinitions.MemoryInformationClass.MemoryMappedFilenameInformation,
                buffer,
                (UIntPtr)bufferSize,
                out _
            );

            if (status == 0)
            {
                // UNICODE_STRING Struktur
                short length = Marshal.ReadInt16(buffer);
                IntPtr stringBufferPtr = Marshal.ReadIntPtr(buffer, IntPtr.Size == 8 ? 8 : 4);

                if (stringBufferPtr != IntPtr.Zero && length > 0)
                {
                    return Marshal.PtrToStringUni(stringBufferPtr, length / 2);
                }
            }
            return "";
        }
    }
}