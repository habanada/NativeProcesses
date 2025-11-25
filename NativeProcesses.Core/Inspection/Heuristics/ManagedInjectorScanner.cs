/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Microsoft.Diagnostics.Runtime;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NativeProcesses.Core.Inspection.Heuristics
{
    public class ManagedInjectorScanner
    {
        private static readonly HashSet<string> Allocators = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "VirtualAlloc", "VirtualAllocEx", "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory"
        };

        private static readonly HashSet<string> Writers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "WriteProcessMemory", "NtWriteVirtualMemory", "ZwWriteVirtualMemory", "RtlMoveMemory", "RtlCopyMemory"
        };

        private static readonly HashSet<string> Executors = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "CreateThread", "CreateRemoteThread", "RtlCreateUserThread", "NtCreateThreadEx", "ZwCreateThreadEx", "QueueUserAPC"
        };

        private static readonly HashSet<string> ProtectionModifiers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "VirtualProtect", "VirtualProtectEx", "NtProtectVirtualMemory", "ZwProtectVirtualMemory"
        };

        private static readonly HashSet<string> ContextManipulators = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "GetThreadContext", "SetThreadContext", "Wow64SetThreadContext", "Wow64GetThreadContext"
        };

        private static readonly HashSet<string> DynamicLoaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "LoadLibrary", "LoadLibraryA", "LoadLibraryW", "LoadLibraryEx", "LdrLoadDll"
        };

        private static readonly HashSet<string> ProcAddressResolvers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "GetProcAddress", "LdrGetProcedureAddress"
        };

        private static readonly HashSet<string> Decompressors = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "RtlDecompressBuffer", "RtlCompressBuffer"
        };

        public IEnumerable<HeuristicResult> Scan(ClrRuntime runtime)
        {
            var results = new List<HeuristicResult>();

            foreach (var module in runtime.EnumerateModules())
            {
                if (module.Name != null && module.Name.StartsWith("System.")) continue;
                if (module.Name != null && module.Name.StartsWith("Microsoft.")) continue;

                var checkedTypes = new HashSet<ClrType>();

                if (runtime.Heap.CanWalkHeap)
                {
                    foreach (var obj in runtime.Heap.EnumerateObjects())
                    {
                        var type = obj.Type;
                        if (type == null || !checkedTypes.Add(type)) continue;
                        if (type.Module != module) continue;

                        ScanTypeForInjectionPatterns(type, results);
                    }
                }
            }

            return results;
        }

        private void ScanTypeForInjectionPatterns(ClrType type, List<HeuristicResult> results)
        {
            bool hasAlloc = false;
            bool hasWrite = false;
            bool hasExec = false;
            bool hasContext = false;
            bool hasProtect = false;
            bool hasLoader = false;
            bool hasProcAddr = false;
            bool hasDecompress = false;
            bool hasPinning = false;
            bool hasFunctionPointer = false;

            foreach (var method in type.Methods)
            {
                string name = method.Name;
                if (string.IsNullOrEmpty(name)) continue;

                if (Allocators.Contains(name)) hasAlloc = true;
                if (Writers.Contains(name)) hasWrite = true;
                if (Executors.Contains(name)) hasExec = true;
                if (ContextManipulators.Contains(name)) hasContext = true;
                if (ProtectionModifiers.Contains(name)) hasProtect = true;
                if (DynamicLoaders.Contains(name)) hasLoader = true;
                if (ProcAddressResolvers.Contains(name)) hasProcAddr = true;
                if (Decompressors.Contains(name)) hasDecompress = true;

                var il = IlExtractor.GetMethodIL(method);
                if (il.Length > 0)
                {
                    if (ContainsPattern(il, new byte[] { 0x19, 0x28 }))
                    {
                        hasPinning = true;
                    }

                    if (ContainsPattern(il, new byte[] { 0xFE, 0x06 }))
                    {
                        hasFunctionPointer = true;
                    }
                }
            }

            if (hasAlloc && hasWrite && hasExec)
            {
                results.Add(new HeuristicResult(
                    "Managed Injector Pattern",
                    ScanCategory.CodeInjection,
                    ThreatScore.Critical,
                    $"Type '{type.Name}' contains full injection suite (Alloc+Write+Exec). Confirmed Dropper/Loader.",
                    type.MethodTable.ToString("X"),
                    "Injection Suite"
                ));
            }

            if (hasLoader && hasProcAddr)
            {
                results.Add(new HeuristicResult(
                    "Dynamic Native Loader",
                    ScanCategory.CodeInjection,
                    ThreatScore.Critical,
                    $"Type '{type.Name}' manually loads DLLs and resolves functions (LoadLibrary+GetProcAddress). Used to bypass static analysis.",
                    type.MethodTable.ToString("X"),
                    "Dynamic API Resolution"
                ));
            }

            if (hasContext && hasWrite)
            {
                results.Add(new HeuristicResult(
                    "Process Hollowing Pattern",
                    ScanCategory.CodeInjection,
                    ThreatScore.Critical,
                    $"Type '{type.Name}' manipulates ThreadContext. Typical for Process Hollowing.",
                    type.MethodTable.ToString("X"),
                    "Hollowing Suite"
                ));
            }

            if (hasDecompress && hasWrite)
            {
                results.Add(new HeuristicResult(
                    "Native Decompression Loader",
                    ScanCategory.CodeInjection,
                    ThreatScore.High,
                    $"Type '{type.Name}' uses RtlDecompressBuffer. Often used to unpack shellcode to memory.",
                    type.MethodTable.ToString("X"),
                    "Unpacking"
                ));
            }

            if (hasProtect && hasWrite)
            {
                results.Add(new HeuristicResult(
                    "Memory Protection Tampering",
                    ScanCategory.CodeInjection,
                    ThreatScore.High,
                    $"Type '{type.Name}' uses VirtualProtect to change memory permissions. Often for Shellcode execution.",
                    type.MethodTable.ToString("X"),
                    "VirtualProtect Usage"
                ));
            }

            if (hasAlloc && hasFunctionPointer)
            {
                results.Add(new HeuristicResult(
                   "Dynamic Delegate Execution",
                   ScanCategory.CodeInjection,
                   ThreatScore.High,
                   $"Type '{type.Name}' allocates memory and manipulates function pointers. Potential 'GetDelegateForFunctionPointer' shellcode runner.",
                   type.MethodTable.ToString("X"),
                   "Alloc + Ldftn"
               ));
            }

            if (hasPinning && hasWrite)
            {
                results.Add(new HeuristicResult(
                   "Pinned Buffer Injection",
                   ScanCategory.CodeInjection,
                   ThreatScore.High,
                   $"Type '{type.Name}' pins objects and performs memory writes. Often used to copy shellcode from byte[] to unmanaged memory.",
                   type.MethodTable.ToString("X"),
                   "Pinning + Write"
               ));
            }
        }

        private bool ContainsPattern(byte[] data, byte[] pattern)
        {
            for (int i = 0; i <= data.Length - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (data[i + j] != pattern[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return true;
            }
            return false;
        }
    }
}