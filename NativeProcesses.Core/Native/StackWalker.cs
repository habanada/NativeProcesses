using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static NativeProcesses.Core.Native.NativeDefinitions;

namespace NativeProcesses.Core.Native
{
    public static class StackWalker
    {
        [DllImport("dbghelp.dll")]
        static extern bool StackWalk64(
            uint MachineType,
            IntPtr hProcess,
            IntPtr hThread,
            ref STACKFRAME64 StackFrame,
            ref CONTEXT ContextRecord,
            IntPtr ReadMemoryRoutine,
            IntPtr FunctionTableAccessRoutine,
            IntPtr GetModuleBaseRoutine,
            IntPtr TranslateAddress);

        [DllImport("dbghelp.dll")]
        static extern bool SymInitialize(IntPtr hProcess, string UserSearchPath, bool fInvadeProcess);

        [DllImport("dbghelp.dll")]
        static extern bool SymCleanup(IntPtr hProcess);

        [DllImport("kernel32.dll")]
        public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        // Konstanten & Structs für x64
        const uint IMAGE_FILE_MACHINE_AMD64 = 0x8664;
        const uint CONTEXT_FULL = 0x100000 | 0x00007; // AMD64 spezifisch, vereinfacht

        // ... (STACKFRAME64 Struct Definition) ...
        // Das hier vollständig in C# zu implementieren ist sehr fehleranfällig und lang.

        // ALTERNATIVE LÖSUNG FÜR DICH:
        // Anstatt StackWalk64 selbst zu machen (was crashen kann), lesen wir den Stack "manuell".
        // Wir lesen RSP (Stack Pointer) und scannen die nächsten 8KB nach Pointern, die in Executable Memory zeigen.
        // Das ist die "Poor Man's Stack Walk" Methode, die Malware-Analysten oft nutzen und die PE-sieve als Fallback hat.
    }
}