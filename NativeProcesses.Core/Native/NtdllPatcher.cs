/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace NativeProcesses.Core.Native
{
    public static class NtdllPatcher
    {
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint STATUS_NOT_SUPPORTED = 0xC00000BB;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);

        /// <summary>
        /// Patcht NtManageHotPatch im Zielprozess, um Hotpatching zu deaktivieren.
        /// Dies verhindert Interferenzen auf Windows 11 24H2+.
        /// </summary>
        public static bool PatchNtManageHotPatch(ManagedProcess process)
        {
            // Wir müssen wissen, ob der Zielprozess 32 oder 64 Bit ist.
            // Aber GetModuleHandle("ntdll") gibt uns das Handle im EIGENEN Prozess.
            // Da Ntdll an derselben Adresse in allen Prozessen liegt (meistens), nutzen wir das.
            // ACHTUNG: Bei 32-Bit Scanner auf 64-Bit Ziel funktioniert das so einfach nicht (WoW64).
            // Wir gehen davon aus, dass Scanner und Ziel gleiche Architektur haben (x64 auf x64).

            IntPtr hNtdll = GetModuleHandle("ntdll.dll");
            if (hNtdll == IntPtr.Zero) return false;

            IntPtr funcAddr = GetProcAddress(hNtdll, "NtManageHotPatch");
            if (funcAddr == IntPtr.Zero) return false; // Funktion existiert nicht (älteres Windows)

            bool isTarget64Bit = !process.GetIsWow64();

            if (isTarget64Bit)
            {
                return Patch64(process.Handle, funcAddr);
            }
            else
            {
                return Patch32(process.Handle, funcAddr);
            }
        }

        private static bool Patch64(IntPtr hProcess, IntPtr funcAddr)
        {
            // MOV EAX, 0xC00000BB (STATUS_NOT_SUPPORTED)
            // RET
            byte[] patch = new byte[] {
                0xB8, 0xBB, 0x00, 0x00, 0xC0,
                0xC3
            };

            // Syscall Stub Check (Pattern Matching)
            // 4C 8B D1 (mov r10, rcx)
            // B8 ...   (mov eax, ...)
            byte[] expectedStart = new byte[] { 0x4C, 0x8B, 0xD1, 0xB8 };

            return ApplyPatch(hProcess, funcAddr, patch, expectedStart);
        }

        private static bool Patch32(IntPtr hProcess, IntPtr funcAddr)
        {
            // MOV EAX, 0xC00000BB
            // RET 0x10
            byte[] patch = new byte[] {
                0xB8, 0xBB, 0x00, 0x00, 0xC0,
                0xC2, 0x10, 0x00
            };

            // 32-Bit Syscalls fangen oft direkt mit B8 an (MOV EAX, ID)
            byte[] expectedStart = new byte[] { 0xB8 };

            return ApplyPatch(hProcess, funcAddr, patch, expectedStart);
        }

        private static bool ApplyPatch(IntPtr hProcess, IntPtr address, byte[] patchBytes, byte[] expectedPattern)
        {
            int size = patchBytes.Length; // 0x20 im Original, wir nehmen exakte Patch-Länge
            if (size < expectedPattern.Length) size = expectedPattern.Length;

            // 1. Berechtigungen ändern
            if (!VirtualProtectEx(hProcess, address, (UIntPtr)size, PAGE_EXECUTE_READWRITE, out uint oldProtect))
            {
                return false;
            }

            try
            {
                // 2. Prüfen, ob es wirklich die Funktion ist (Safety Check)
                byte[] original = new byte[expectedPattern.Length];
                if (!ReadProcessMemory(hProcess, address, original, original.Length, out int bytesRead) || bytesRead != original.Length)
                {
                    return false;
                }

                for (int i = 0; i < expectedPattern.Length; i++)
                {
                    if (original[i] != expectedPattern[i]) return false; // Pattern Mismatch (vielleicht schon gepatcht oder Hook)
                }

                // 3. Patch schreiben
                if (!WriteProcessMemory(hProcess, address, patchBytes, patchBytes.Length, out int bytesWritten) || bytesWritten != patchBytes.Length)
                {
                    return false;
                }

                // 4. Cache flushen (wichtig bei Code-Modifikation!)
                FlushInstructionCache(hProcess, address, (UIntPtr)patchBytes.Length);
                return true;
            }
            finally
            {
                // 5. Berechtigungen wiederherstellen
                VirtualProtectEx(hProcess, address, (UIntPtr)size, oldProtect, out _);
            }
        }
    }
}