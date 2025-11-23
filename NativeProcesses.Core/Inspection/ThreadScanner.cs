using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using NativeProcesses.Core.Engine;
using NativeProcesses.Core.Models;
using NativeProcesses.Core.Native;
using static NativeProcesses.Core.Native.NativeDefinitions;

namespace NativeProcesses.Core.Inspection
{
    public class ThreadScanner
    {
        private readonly IEngineLogger _logger;

        [DllImport("kernel32.dll")]
        private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationThread(
            IntPtr ThreadHandle,
            int ThreadInformationClass,
            IntPtr ThreadInformation,
            int ThreadInformationLength,
            out int ReturnLength);

        public ThreadScanner(IEngineLogger logger)
        {
            _logger = logger;
        }

        public List<ThreadScanReport> ScanThreads(ManagedProcess process, List<ProcessModuleInfo> modules, List<VirtualMemoryRegion> regions)
        {
            var results = new List<ThreadScanReport>();
            var threads = GetThreadsForProcess(process.Pid);

            foreach (var tid in threads)
            {
                var report = ScanSingleThread(process, tid, modules, regions);
                if (report.Status != ThreadScanStatus.Clean)
                {
                    results.Add(report);
                }
            }
            return results;
        }

        private ThreadScanReport ScanSingleThread(ManagedProcess process, int tid, List<ProcessModuleInfo> modules, List<VirtualMemoryRegion> regions)
        {
            var report = new ThreadScanReport { ThreadId = tid };

            try
            {
                // Wir brauchen GetContext für Stack/RIP und QueryInformation für StartAddress
                using (var thread = new ManagedThread(tid, ManagedThread.ThreadAccessFlags.QueryInformation | ManagedThread.ThreadAccessFlags.GetContext | ManagedThread.ThreadAccessFlags.SuspendResume))
                {
                    // Um den Context sicher zu lesen, sollte der Thread suspended sein (optional, aber besser)
                    // thread.Suspend(); 
                    // (Achtung: Suspend kann Deadlocks verursachen, wenn wir den eigenen Prozess scannen. 
                    // Für Remote Scans ist es sicherer, aber wir lassen es für Performance erstmal weg und hoffen auf einen stabilen Read.)

                    // A. Startadresse holen
                    IntPtr startAddress = GetThreadStartAddress(thread.Handle);
                    report.StartAddress = startAddress;

                    // B. Startadresse analysieren
                    var region = FindRegion(regions, startAddress);
                    var module = FindModule(modules, startAddress);

                    if (module != null)
                    {
                        report.StartAddressModule = module.BaseDllName;
                    }
                    else
                    {
                        report.StartAddressModule = "Unbacked/Unknown";

                        if (region != null && (region.Protection.Contains("EXECUTE") || region.Type == "Private"))
                        {
                            report.Status = ThreadScanStatus.SuspiciousStart;
                            report.Details = $"Thread starts in private executable memory at 0x{startAddress:X} ({region.Protection}). Potential Shellcode/Injection.";
                        }
                        else if (startAddress != IntPtr.Zero)
                        {
                            report.Status = ThreadScanStatus.SuspiciousStart;
                            report.Details = $"Thread starts at unmapped address 0x{startAddress:X}.";
                        }
                    }

                    // C. Sleeping Beacon Check
                    // (Benötigt SystemThreadInformation via NativeProcessLister für echte KTHREAD_STATE, 
                    // da NtQueryInformationThread(ThreadBasicInformation) das nicht direkt liefert. 
                    // Wir skippen den State-Check hier und prüfen nur den Context, wenn möglich.)

                    // D. Stack Analysis (Heuristic)
                    var ctx = new CONTEXT();
                    ctx.ContextFlags = CONTEXT_CONTROL;

                    if (GetThreadContext(thread.Handle, ref ctx))
                    {
                        // 1. RIP Check (Instruction Pointer)
                        // Wo führt der Thread gerade Code aus?
                        var ripModule = FindModule(modules, (IntPtr)ctx.Rip);
                        if (ripModule == null)
                        {
                            var ripRegion = FindRegion(regions, (IntPtr)ctx.Rip);
                            if (ripRegion != null && (ripRegion.Type == "Private" || ripRegion.Protection.Contains("EXECUTE")))
                            {
                                report.Status = ThreadScanStatus.SuspiciousStart; // Oder Execution
                                report.Details = $"Thread executing code in private memory at 0x{ctx.Rip:X} ({ripRegion.Protection}).";
                            }
                        }

                        // 2. Stack Scan
                        // Lese den Stack-Speicher (z.B. Top 4KB)
                        // Wir lesen ab RSP. Achtung: RSP kann ungültig sein, wenn Thread crasht.
                        if (ctx.Rsp != 0)
                        {
                            byte[] stackData = null;
                            try
                            {
                                stackData = process.ReadMemory((IntPtr)ctx.Rsp, 4096);
                            }
                            catch
                            {
                                // Stack vielleicht am Ende der Page -> kleineren Chunk probieren oder ignorieren
                            }

                            if (stackData != null)
                            {
                                // Scanne nach Pointern (8 Bytes auf x64)
                                for (int i = 0; i < stackData.Length - 8; i += 8)
                                {
                                    ulong ptrVal = BitConverter.ToUInt64(stackData, i);

                                    // Filter: Nur User-Mode Adressen (<= 0x7FFFFFFFFFFF) und Alignment
                                    if (ptrVal < 0x10000 || ptrVal > 0x7FFFFFFFFFFF) continue;

                                    var mod = FindModule(modules, (IntPtr)ptrVal);
                                    if (mod == null)
                                    {
                                        var reg = FindRegion(regions, (IntPtr)ptrVal);
                                        // Wir suchen nach Rücksprungadressen (Return Addresses). 
                                        // Diese liegen auf dem Stack und zeigen in Executable Memory.
                                        // Wenn eine Rücksprungadresse in Private/Unbacked Executable Memory zeigt -> Alarm!
                                        if (reg != null && (reg.Protection.Contains("EXECUTE") && reg.Type == "Private"))
                                        {
                                            // HEURISTIK: Ist das wirklich Code?
                                            // Wir lesen kurz an der Zieladresse (ptrVal), ob dort Code steht.
                                            // (Optional, aber reduziert False Positives bei Random Data auf dem Stack)

                                            report.Status = ThreadScanStatus.SuspiciousStack;
                                            report.Details = $"Stack contains return address to suspicious region: 0x{ptrVal:X} ({reg.Protection})";
                                            report.StackTrace.Add($"0x{ptrVal:X} (Shellcode/Unbacked)");

                                            // Wir brechen nach dem ersten Fund ab, da ein Shellcode-Frame reicht
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // thread.Resume();
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, $"Failed to scan thread {tid}", ex);
            }

            return report;
        }

        // --- Helper ---

        private List<int> GetThreadsForProcess(int pid)
        {
            var tids = new List<int>();
            try
            {
                foreach (ProcessThread pt in Process.GetProcessById(pid).Threads)
                {
                    tids.Add(pt.Id);
                }
            }
            catch { }
            return tids;
        }

        private VirtualMemoryRegion FindRegion(List<VirtualMemoryRegion> regions, IntPtr addr)
        {
            long a = addr.ToInt64();
            return regions.FirstOrDefault(r => a >= r.BaseAddress.ToInt64() && a < (r.BaseAddress.ToInt64() + r.RegionSize));
        }

        private ProcessModuleInfo FindModule(List<ProcessModuleInfo> modules, IntPtr addr)
        {
            long a = addr.ToInt64();
            return modules.FirstOrDefault(m => a >= m.DllBase.ToInt64() && a < (m.DllBase.ToInt64() + m.SizeOfImage));
        }

        private IntPtr GetThreadStartAddress(IntPtr hThread)
        {
            IntPtr buffer = Marshal.AllocHGlobal(IntPtr.Size);
            try
            {
                // ThreadQuerySetWin32StartAddress = 9
                int status = NtQueryInformationThread(hThread, 9, buffer, IntPtr.Size, out _);
                if (status == 0)
                {
                    return Marshal.ReadIntPtr(buffer);
                }
                return IntPtr.Zero;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }
}