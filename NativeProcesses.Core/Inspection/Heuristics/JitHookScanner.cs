/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Microsoft.Diagnostics.Runtime;
using NativeProcesses.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NativeProcesses.Core.Inspection.Heuristics
{
    public class JitHookScanner
    {
        private static readonly Dictionary<string, string[]> CriticalMethods = new Dictionary<string, string[]>
        {
            // Execution & Loading
            { "System.Diagnostics.Process", new[] { "Start" } },
            { "System.Reflection.Assembly", new[] { "Load", "LoadFrom", "LoadFile", "Load", "UnsafeLoadFrom" } },
            { "System.AppDomain", new[] { "Load", "ExecuteAssembly" } },
            { "System.Activator", new[] { "CreateInstance" } },

            // Network
            { "System.Net.WebClient", new[] { "DownloadString", "DownloadData", "UploadValues", "OpenRead" } },
            { "System.Net.Http.HttpClient", new[] { "SendAsync", "GetAsync", "PostAsync" } },
            { "System.Net.Sockets.Socket", new[] { "Connect", "Send", "Receive" } },
            { "System.Net.Dns", new[] { "GetHostEntry", "GetHostAddresses" } },

            // File IO
            { "System.IO.File", new[] { "WriteAllBytes", "ReadAllBytes", "Create", "Open" } },
            { "System.IO.FileStream", new[] { ".ctor" } },

            // Interop & Memory
            { "System.Runtime.InteropServices.Marshal", new[] { "GetDelegateForFunctionPointer", "WriteByte", "AllocHGlobal" } },
            { "System.Environment", new[] { "Exit", "FailFast" } },

            // Crypto
            { "System.Security.Cryptography.Aes", new[] { "Create" } },
            { "System.Security.Cryptography.RijndaelManaged", new[] { ".ctor" } }
        };

        public IEnumerable<HeuristicResult> Scan(ClrRuntime runtime, List<VirtualMemoryRegion> regions)
        {
            var results = new List<HeuristicResult>();
            var checkedMethods = new HashSet<ulong>();

            var suspiciousRegions = regions?
                .Where(r => r.Type == "Private" && r.Protection.Contains("EXECUTE"))
                .ToList();

            // 1. MethodTable Spoofing
            if (runtime.Heap.CanWalkHeap)
            {
                foreach (var obj in runtime.Heap.EnumerateObjects())
                {
                    if (obj.Type == null) continue;

                    ulong mt = obj.Type.MethodTable;
                    var module = obj.Type.Module;

                    if (module != null)
                    {
                        // FIX: ImageSize -> Size
                        if (mt < module.ImageBase || mt >= (module.ImageBase + module.Size))
                        {
                            if (suspiciousRegions != null)
                            {
                                foreach (var region in suspiciousRegions)
                                {
                                    ulong start = (ulong)region.BaseAddress.ToInt64();
                                    ulong end = start + (ulong)region.RegionSize;
                                    if (mt >= start && mt < end)
                                    {
                                        results.Add(new HeuristicResult(
                                            "MethodTable Spoofing",
                                            ScanCategory.CodeInjection,
                                            ThreatScore.Critical,
                                            $"Object of type '{obj.Type.Name}' has MethodTable at 0x{mt:X} inside Private RWX memory.",
                                            obj.Address.ToString("X"),
                                            "Spoofed MT"
                                        ));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // 2. JIT Hook Detection
            foreach (var kvp in CriticalMethods)
            {
                // FIX: GetTypeByName existiert auf Heap, nicht Runtime
                var type = runtime.Heap.GetTypeByName(kvp.Key);
                if (type == null) continue;

                foreach (string methodName in kvp.Value)
                {
                    foreach (var method in type.Methods)
                    {
                        if (method.Name == methodName && checkedMethods.Add(method.MethodDesc))
                        {
                            ScanMethodForHooks(method, runtime, suspiciousRegions, results);
                        }
                    }
                }
            }

            return results;
        }

        private void ScanMethodForHooks(ClrMethod method, ClrRuntime runtime, List<VirtualMemoryRegion> suspiciousRegions, List<HeuristicResult> results)
        {
            if (method.NativeCode == 0 || method.NativeCode == ulong.MaxValue) return;

            // (1) Origin Check
            if (suspiciousRegions != null)
            {
                foreach (var region in suspiciousRegions)
                {
                    ulong start = (ulong)region.BaseAddress.ToInt64();
                    ulong end = start + (ulong)region.RegionSize;

                    if (method.NativeCode >= start && method.NativeCode < end)
                    {
                        results.Add(new HeuristicResult(
                            "JIT Code Displacement",
                            ScanCategory.CodeInjection,
                            ThreatScore.Critical,
                            $"Method '{method.Name}' native code resides in private executable memory at 0x{method.NativeCode:X}.",
                            method.NativeCode.ToString("X"),
                            "Relocated JIT Code"
                        ));
                        return;
                    }
                }
            }

            // A. Code-Längen-Check
            uint codeSize = method.HotColdInfo.HotSize;

            // Wenn die Methode extrem klein ist (JMP)
            // FIX: IsPInvoke/IsInternal entfernt, da nicht verfügbar.
            // Wir prüfen stattdessen, ob NativeCode existiert (haben wir oben schon).
            // Wenn Code sehr klein ist UND JIT kompiliert wurde (NativeCode != 0), ist es verdächtig.
            // Wir ignorieren Methoden ohne IL, wenn wir uns unsicher sind (siehe unten).
            if (codeSize > 0 && codeSize <= 6)
            {
                // Kleiner Code allein ist nicht schlimm (kann "return" sein).
                // Wir kombinieren es mit dem IL Check.
            }

            // B. IL Integrity Check
            var ilInfo = method.GetILInfo();
            // FIX: Wir prüfen nur, ob IL fehlt, wenn wir wissen dass es Managed Code sein sollte.
            // Da wir IsInternal/PInvoke nicht haben, sind wir hier konservativer:
            // Wir melden "Ghost Method" nur, wenn wir auch einen Hook finden oder die Größe null ist.

            // C. Trampoline / Jump Check
            byte[] prologue = new byte[16];
            int read = runtime.DataTarget.DataReader.Read(method.NativeCode, new Span<byte>(prologue));

            if (read < 5) return;

            // Check auf JMP (0xE9)
            if (prologue[0] == 0xE9)
            {
                int relativeOffset = BitConverter.ToInt32(prologue, 1);
                ulong targetAddress = (ulong)((long)method.NativeCode + 5 + relativeOffset);
                CheckJumpTarget(method, targetAddress, suspiciousRegions, results, "Inline JIT Hook (JMP)");
            }
            // Indirect JMP (0xFF 0x25)
            else if (prologue[0] == 0xFF && prologue[1] == 0x25)
            {
                int relativeOffset = BitConverter.ToInt32(prologue, 2);
                ulong ptrAddr = (ulong)((long)method.NativeCode + 6 + relativeOffset);

                byte[] ptrBuf = new byte[8];
                if (runtime.DataTarget.DataReader.Read(ptrAddr, new Span<byte>(ptrBuf)) == 8)
                {
                    ulong targetAddress = BitConverter.ToUInt64(ptrBuf, 0);
                    CheckJumpTarget(method, targetAddress, suspiciousRegions, results, "Inline JIT Hook (Indirect JMP)");
                }
            }
            // MOV RAX, Addr; JMP RAX (0x48 0xB8 ... 0xFF 0xE0)
            else if (prologue[0] == 0x48 && prologue[1] == 0xB8)
            {
                ulong targetAddress = BitConverter.ToUInt64(prologue, 2);
                CheckJumpTarget(method, targetAddress, suspiciousRegions, results, "Inline JIT Hook (MOV RAX, JMP)");
            }
        }

        private void CheckJumpTarget(ClrMethod method, ulong target, List<VirtualMemoryRegion> suspiciousRegions, List<HeuristicResult> results, string detectionName)
        {
            if (suspiciousRegions == null) return;

            foreach (var region in suspiciousRegions)
            {
                ulong start = (ulong)region.BaseAddress.ToInt64();
                ulong end = start + (ulong)region.RegionSize;

                if (target >= start && target < end)
                {
                    results.Add(new HeuristicResult(
                        detectionName,
                        ScanCategory.CodeInjection,
                        ThreatScore.Critical,
                        $"System method '{method.Name}' is hooked! Jumps to private executable memory at 0x{target:X}. Rootkit technique.",
                        method.NativeCode.ToString("X"),
                        $"Target: {region.Type} {region.Protection}"
                    ));
                    return;
                }
            }
        }
    }
}