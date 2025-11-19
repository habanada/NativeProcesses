/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Collections.Generic;
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
        /// Scannt nach Phantom-Modulen (nicht im PEB) und bösartigem privaten Code (Shellcode/Manual Map).
        /// </summary>
        public List<PhantomModuleInfo> ScanForPhantoms(ManagedProcess process, List<ProcessModuleInfo> pebModules, List<VirtualMemoryRegion> regions = null)
        {
            // Falls keine Regionen übergeben wurden, selbst laden
            if (regions == null)
            {
                regions = GetDeepMemoryRegions(process);
            }

            var results = new List<PhantomModuleInfo>();

            // 1. Cache für schnelle PEB-Lookups (Base Addresses)
            var pebLookup = new HashSet<long>();
            foreach (var mod in pebModules) pebLookup.Add(mod.DllBase.ToInt64());

            IntPtr nameBuffer = Marshal.AllocHGlobal(1024);

            try
            {
                foreach (var region in regions)
                {
                    bool isImage = region.Type.IndexOf("Image", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool isMapped = region.Type.IndexOf("Mapped", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool isPrivate = region.Type.IndexOf("Private", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool isExec = region.Protection.IndexOf("EXECUTE", StringComparison.OrdinalIgnoreCase) >= 0;

                    // --- CASE 1: Unlinked Module (Phantom / Doppelgänging) ---
                    // Der Kernel sagt "Hier ist ein Image (DLL)", aber der PEB kennt es nicht.
                    if (isImage)
                    {
                        long allocBase = region.AllocationBase.ToInt64();

                        // Deduplizierung: Ein Modul besteht aus vielen Chunks, wir melden nur den ersten (Header)
                        if (results.Any(r => r.BaseAddress.ToInt64() == allocBase)) continue;

                        if (!pebLookup.Contains(allocBase))
                        {
                            string mappedFileName = GetMappedFileName(process.Handle, region.AllocationBase, nameBuffer, 1024);

                            // Filtern von harmlosen Images (z.B. sprachabhängige Ressourcen)
                            if (!mappedFileName.EndsWith(".nls", StringComparison.OrdinalIgnoreCase))
                            {
                                results.Add(new PhantomModuleInfo
                                {
                                    BaseAddress = region.AllocationBase,
                                    Size = region.RegionSize,
                                    NtPath = mappedFileName,
                                    IsExecutable = isExec,
                                    DetectionMethod = "Phantom Module (Unlinked from PEB)",
                                    Details = "Module exists in kernel VAD but is hidden from PEB list (Hollowing/Doppelgänging)."
                                });
                            }
                        }
                    }
                    // --- CASE 2: Private/Mapped Executable Memory (Injection / Shellcode) ---
                    else if ((isPrivate || isMapped) && isExec)
                    {
                        // Wir scannen nur den Anfang der Region (Shellcode Entrypoint ist meist vorne)
                        if (results.Any(r => r.BaseAddress == region.BaseAddress)) continue;

                        // Inhalt lesen für Analyse
                        byte[] content = null;
                        try
                        {
                            // Lese max 4KB für Signaturen
                            content = process.ReadMemory(region.BaseAddress, 4096);
                        }
                        catch { continue; }

                        if (content == null || content.Length < 64) continue;

                        // A. Check auf "MZ" Header (Manual Mapped PE / Reflective DLL)
                        if (content[0] == 'M' && content[1] == 'Z')
                        {
                            string mappedFileName = GetMappedFileName(process.Handle, region.BaseAddress, nameBuffer, 1024);
                            results.Add(new PhantomModuleInfo
                            {
                                BaseAddress = region.BaseAddress,
                                Size = region.RegionSize,
                                NtPath = mappedFileName,
                                IsExecutable = true,
                                DetectionMethod = "Manually Mapped PE",
                                Details = "Private memory contains PE Header (MZ). Reflective DLL Injection detected."
                            });
                            continue;
                        }

                        // B. Check auf Shellcode (mit neuem Detector)
                        // Wir filtern JIT Code (Browsers, .NET) hier aus, um False Positives zu vermeiden.
                        if (ShellcodeDetector.IsLikelyShellcode(content, out string reason))
                        {
                            if (reason != "Clean")
                            {
                                results.Add(new PhantomModuleInfo
                                {
                                    BaseAddress = region.BaseAddress,
                                    Size = region.RegionSize,
                                    NtPath = "Private Memory",
                                    IsExecutable = true,
                                    DetectionMethod = "Malicious Shellcode Pattern",
                                    Details = reason // z.B. "Metasploit Pattern" oder "High Entropy"
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, "ScanForPhantoms failed.", ex);
            }
            finally
            {
                Marshal.FreeHGlobal(nameBuffer);
            }

            return results;
        }

        private string GetMappedFileName(IntPtr hProcess, IntPtr baseAddr, IntPtr buffer, int bufferSize)
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