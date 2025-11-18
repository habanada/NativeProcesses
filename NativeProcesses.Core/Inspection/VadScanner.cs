/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
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
        /// Das entspricht der Logik deines "alten" Codes, gibt aber eine Liste zurück,
        /// damit andere Scanner (wie ProcessManager) die Regionen wiederverwenden können.
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

                    // Wir übernehmen nur "Commit" Pages, genau wie im alten Code
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
        /// Überladung 1: Für Aufrufe ohne vor-geladene Regionen.
        /// Holt die Regionen selbst (Deep Scan) und ruft dann die Analyse auf.
        /// </summary>
        public List<PhantomModuleInfo> ScanForPhantoms(ManagedProcess process, List<ProcessModuleInfo> pebModules)
        {
            // Führe den VAD-Walk durch (entspricht dem while-Loop im alten Code)
            var regions = GetDeepMemoryRegions(process);
            // Rufe die Analyse-Logik auf
            return ScanForPhantoms(process, pebModules, regions);
        }

        /// <summary>
        /// Akzeptiert bereits geladene Regionen (Performance-Optimierung im ProcessManager).
        /// Enthält exakt deine alte Detektions-Logik (Case 1 & Case 2).
        /// </summary>
        public List<PhantomModuleInfo> ScanForPhantoms(ManagedProcess process, List<ProcessModuleInfo> pebModules, List<VirtualMemoryRegion> regions)
        {
            var results = new List<PhantomModuleInfo>();

            // Cache für schnelle PEB-Lookups
            var pebLookup = new HashSet<long>();
            foreach (var mod in pebModules) pebLookup.Add(mod.DllBase.ToInt64());

            // Buffer für Dateinamen (wird wiederverwendet)
            IntPtr nameBuffer = Marshal.AllocHGlobal(1024);

            try
            {
                foreach (var region in regions)
                {
                    // Da VirtualMemoryRegion Strings speichert, müssen wir hier prüfen.
                    // Das entspricht den uint-Checks (MEM_IMAGE, MEM_MAPPED) aus dem alten Code.

                    bool isCommit = region.State.IndexOf("Commit", StringComparison.OrdinalIgnoreCase) >= 0;
                    if (!isCommit) continue;

                    bool isImage = region.Type.IndexOf("Image", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool isMapped = region.Type.IndexOf("Mapped", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool isPrivate = region.Type.IndexOf("Private", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool isExec = region.Protection.IndexOf("EXECUTE", StringComparison.OrdinalIgnoreCase) >= 0;

                    // --- CASE 1: Unlinked Module (Doppelgänging / Herpaderping) ---
                    // Alter Code: if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE)
                    if (isImage)
                    {
                        long allocBase = region.AllocationBase.ToInt64();

                        // Deduplizierung (damit wir nicht jeden Chunk des gleichen Moduls melden)
                        if (results.Any(r => r.BaseAddress.ToInt64() == allocBase)) continue;

                        if (!pebLookup.Contains(allocBase))
                        {
                            // ALARM: Kernel sagt Image, PEB sagt nix.
                            string mappedFileName = GetMappedFileName(process.Handle, region.AllocationBase, nameBuffer, 1024);

                            results.Add(new PhantomModuleInfo
                            {
                                BaseAddress = region.AllocationBase,
                                Size = region.RegionSize,
                                NtPath = mappedFileName,
                                IsExecutable = isExec,
                                DetectionMethod = "Phantom Module (Unlinked from PEB)"
                            });
                        }
                    }
                    // --- CASE 2: Shamtom / Manual Mapping ---
                    // Alter Code: else if (mbi.State == MEM_COMMIT && mbi.Type == MEM_MAPPED && Protect == EXECUTE)
                    // Wir haben hier 'isPrivate' ergänzt, um noch besser zu sein (Standard Manual Mapping ist oft Private).
                    else if ((isMapped || isPrivate) && isExec)
                    {
                        // Nur scannen, wenn wir nicht schon einen Treffer an dieser Basisadresse haben
                        if (results.Any(r => r.BaseAddress == region.BaseAddress)) continue;

                        // Header Check (MZ)
                        // Hier müssen wir lesen. 
                        byte[] header = new byte[2];
                        try
                        {
                            header = process.ReadMemory(region.BaseAddress, 2);
                        }
                        catch { continue; } // Lesen fehlgeschlagen

                        if (header[0] == 'M' && header[1] == 'Z')
                        {
                            string mappedFileName = GetMappedFileName(process.Handle, region.BaseAddress, nameBuffer, 1024);

                            string detectionType = isMapped ? "Shamtom (Manually Mapped PE)" : "Shellcode/Manual Map (Private RWX)";

                            results.Add(new PhantomModuleInfo
                            {
                                BaseAddress = region.BaseAddress,
                                Size = region.RegionSize,
                                NtPath = mappedFileName,
                                IsExecutable = true,
                                DetectionMethod = detectionType
                            });
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

        // Dein alter Helper, exakt übernommen (angepasst für Pointers)
        private string GetMappedFileName(IntPtr hProcess, IntPtr baseAddr, IntPtr buffer, int bufferSize)
        {
            // Struktur ist UNICODE_STRING gefolgt vom Buffer
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
                // Manuelles Auslesen des UNICODE_STRING Structs aus dem Pointer
                // Auf x64: Length(2) + MaxLen(2) + Padding(4) + Ptr(8) = 16 Bytes
                // Auf x86: Length(2) + MaxLen(2) + Ptr(4) = 8 Bytes

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