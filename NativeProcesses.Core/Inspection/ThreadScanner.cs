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

            // HIER IST DIE INTEGRATION:
            // Wir erstellen den Resolver EINMAL für den ganzen Scan, das ist performant.
            // Wir nutzen 'using', damit SymCleanup am Ende automatisch aufgerufen wird.
            using (var resolver = new SymbolResolver(process.Handle))
            {
                foreach (var tid in threads)
                {
                    // Wir geben den resolver an die Methode weiter
                    var report = ScanSingleThread(process, tid, modules, regions, resolver);

                    // Wir speichern alle Reports, auch die sauberen, wenn ein Symbol gefunden wurde
                    // oder filtern nur die verdächtigen (wie vorher).
                    // Hier behalten wir deine Logik bei: Nur Status != Clean.
                    if (report.Status != ThreadScanStatus.Clean)
                    {
                        results.Add(report);
                    }
                }
            }
            return results;
        }
        /* Erweiterung für ThreadScanner.cs
   Erkennt ROP-Chains und Stack Pivoting
*/

        private void ScanForRop(ManagedProcess process, int tid, IntPtr threadHandle, List<VirtualMemoryRegion> stacks, List<ThreadScanReport> results)
        {
            CONTEXT ctx = new CONTEXT();
            ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER; // Wir brauchen RSP/RIP

            if (GetThreadContext(threadHandle, ref ctx))
            {
                ulong rsp = ctx.Rsp;
                ulong rip = ctx.Rip;

                // 1. Check: Stack Pivoting
                // Prüfen, ob RSP in einem bekannten Stack-Bereich liegt
                bool validStack = false;
                foreach (var stack in stacks) // Du musst die Stacks vorher via VAD identifizieren (Type=Private, Protection=RW, Größe typisch 1MB)
                {
                    ulong start = (ulong)stack.BaseAddress.ToInt64();
                    ulong end = start + (ulong)stack.RegionSize;
                    if (rsp >= start && rsp < end)
                    {
                        validStack = true;
                        break;
                    }
                }

                if (!validStack)
                {
                    results.Add(new ThreadScanReport
                    {
                        ThreadId = tid,
                        Status = ThreadScanStatus.SuspiciousStack,
                        Details = $"STACK PIVOT DETECTED! RSP (0x{rsp:X}) points outside known thread stacks. Typical for ROP payloads."
                    });
                    return;
                }

                // 2. Check: ROP Gadget Chain (Heuristik)
                // Wir lesen die ersten paar Adressen vom Stack (die ROP Chain)
                byte[] stackContent = process.ReadMemory((IntPtr)rsp, 64); // Lese 8 Adressen (x64)
                if (stackContent == null) return;

                int ropScore = 0;

                for (int i = 0; i < stackContent.Length; i += 8)
                {
                    ulong returnAddr = BitConverter.ToUInt64(stackContent, i);

                    // Ist die Adresse ausführbar? (Muss sie sein für ROP)
                    // (Hier könntest du prüfen, ob returnAddr in einem MEM_IMAGE liegt)

                    // VALIDIERUNG: Gab es einen CALL davor?
                    // Wir lesen 6 Bytes VOR der Return-Adresse
                    if (returnAddr > 6)
                    {
                        byte[] codeBefore = process.ReadMemory((IntPtr)(returnAddr - 6), 6);
                        if (codeBefore != null)
                        {
                            // Prüfe auf typische CALL Opcodes: E8 (Call rel), FF 15 (Call indirect)
                            bool hasCall = false;
                            if (codeBefore[5] == 0xE8) hasCall = true; // CALL rel32 (5 bytes)
                            if (codeBefore[4] == 0xFF && (codeBefore[5] & 0x10) == 0x10) hasCall = true; // CALL r/m (2-6 bytes)

                            if (!hasCall)
                            {
                                ropScore++;
                            }
                        }
                    }
                }

                // Wenn wir mehrere Adressen auf dem Stack haben, die NICHT von einem CALL stammen, ist es eine ROP Chain.
                if (ropScore >= 3)
                {
                    results.Add(new ThreadScanReport
                    {
                        ThreadId = tid,
                        Status = ThreadScanStatus.SuspiciousStack,
                        Details = $"ROP CHAIN DETECTED! Found {ropScore} return addresses on stack without preceding CALL instructions."
                    });
                }
            }
        }
        private ThreadScanReport ScanSingleThread(ManagedProcess process, int tid, List<ProcessModuleInfo> modules, List<VirtualMemoryRegion> regions, SymbolResolver resolver)
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

                    // Symbol auflösen 
                    if (startAddress != IntPtr.Zero)
                    {
                        string symbol = resolver.ResolveAddress(startAddress);
                        if (!string.IsNullOrEmpty(symbol))
                        {
                            report.StartAddressSymbol = symbol;
                        }
                    }

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
                    
                    // Thread kurz anhalten für stabilen Context (Optional, aber sicherer)
                    // thread.Suspend();

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
                                    else
                                    {
                                        // Optional: Symbole für Stack Trace auflösen (nur für Debugging, frisst Performance)
                                        // string sym = resolver.ResolveAddress((IntPtr)ptrVal);
                                        // if (sym != null) report.StackTrace.Add(sym);
                                    }
                                }
                            }
                        }
                    }


                    // Check: StartAddress liegt in Private Memory (Unbacked)  Halosgate 
                    if (region != null && region.Type == "Private")
                    {
                        // Das ist der "Smoking Gun" für Manual Mapping & Shellcode Injection
                        report.Status = ThreadScanStatus.SuspiciousStart;
                        report.Details = $"Thread starts in PRIVATE memory at 0x{startAddress:X}. Legitimate threads usually start in MEM_IMAGE (DLLs).";

                        // Zusatz-Check: Ist der Bereich executable?
                        if (region.Protection.Contains("EXECUTE"))
                        {
                            report.Details += " Region is EXECUTABLE -> Confirmed Code Injection.";
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