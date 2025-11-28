//using System;
//using NativeProcesses.Core.Native; // Zugriff auf SyscallResolver und DirectSyscall

//namespace NativeProcesses.Core.Tests
//{
//    public static class TestRunner
//    {
//        /// <summary>
//        /// Führt einen Test für Direct Syscalls (Hell's Gate / Halo's Gate) durch.
//        /// Versucht Speicher zu allozieren, ohne NTDLL-Exports direkt aufzurufen.
//        /// </summary>
//        public static void TestDirectSyscall()
//        {
//            Console.WriteLine("==========================================");
//            Console.WriteLine("[Test] Starte Direct Syscall Test (Hell's Gate / Halo's Gate)...");
//            Console.WriteLine("==========================================");

//            try
//            {
//                // SCHRITT 1: SSN Auflösen (Dynamisch aus NTDLL im Speicher)
//                // Der SyscallResolver nutzt Halo's Gate, um auch bei EDR-Hooks die Nummer zu finden.
//                Console.WriteLine("[INFO] Suche Syscall-Nummer (SSN) für 'NtAllocateVirtualMemory'...");

//                int ssn = SyscallResolver.ResolveSyscall("NtAllocateVirtualMemory");

//                if (ssn == -1)
//                {
//                    Console.ForegroundColor = ConsoleColor.Red;
//                    Console.WriteLine("[FEHLER] Konnte SSN für NtAllocateVirtualMemory nicht finden!");
//                    Console.ResetColor();
//                    return;
//                }

//                Console.ForegroundColor = ConsoleColor.Green;
//                Console.WriteLine($"[INFO] SSN erfolgreich gefunden: 0x{ssn:X}");
//                Console.ResetColor();

//                // SCHRITT 2: Executor vorbereiten (Stub im Speicher anlegen)
//                using (var syscall = new DirectSyscall())
//                {
//                    // Die gefundene SSN in den Shellcode patchen
//                    syscall.SetSyscall(ssn);

//                    // SCHRITT 3: Delegate holen
//                    // Wir casten den Pointer auf unseren Shellcode in einen C# Delegate
//                    var alloc = syscall.GetDelegate<DirectSyscall.NtAllocateDelegate>();

//                    // SCHRITT 4: Ausführen
//                    // Wir versuchen, 4KB (0x1000) Speicher im aktuellen Prozess (-1) zu allozieren.
//                    IntPtr baseAddr = IntPtr.Zero;
//                    IntPtr regionSize = (IntPtr)0x1000;
//                    IntPtr hProcess = (IntPtr)(-1); // Pseudo-Handle für Current Process

//                    // Parameter: 
//                    // Handle, &BaseAddr, ZeroBits, &RegionSize, AllocationType, Protect
//                    // 0x3000 = MEM_COMMIT | MEM_RESERVE
//                    // 0x40   = PAGE_EXECUTE_READWRITE

//                    Console.WriteLine("[INFO] Führe Syscall aus...");

//                    int status = alloc(hProcess, ref baseAddr, IntPtr.Zero, ref regionSize, 0x3000, 0x40);

//                    // SCHRITT 5: Ergebnis prüfen
//                    if (status == 0) // STATUS_SUCCESS
//                    {
//                        Console.ForegroundColor = ConsoleColor.Cyan;
//                        Console.WriteLine($"[ERFOLG] Speicher via Direct Syscall alloziert!");
//                        Console.WriteLine($"         Adresse: 0x{baseAddr.ToString("X")}");
//                        Console.WriteLine($"         Größe:   0x{regionSize.ToString("X")}");
//                        Console.ResetColor();

//                        // Optional: Speicher wieder freigeben (Cleanup ist guter Stil, auch bei Malware-Simulation)
//                        // Dazu bräuchten wir NtFreeVirtualMemory via Syscall oder nutzen einfach VirtualFree (P/Invoke)
//                    }
//                    else
//                    {
//                        Console.ForegroundColor = ConsoleColor.Red;
//                        Console.WriteLine($"[FEHLER] Syscall fehlgeschlagen. NTSTATUS: 0x{status:X}");
//                        Console.ResetColor();
//                    }
//                }
//            }
//            catch (Exception ex)
//            {
//                Console.ForegroundColor = ConsoleColor.Red;
//                Console.WriteLine($"[EXCEPTION] Kritischer Fehler im Test: {ex.Message}");
//                Console.WriteLine(ex.StackTrace);
//                Console.ResetColor();
//            }

//            Console.WriteLine("==========================================");
//            Console.WriteLine("[Test] Ende.");
//        }
//    }
//}