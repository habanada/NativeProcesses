///*
//   NativeProcesses Framework
//   SyscallResolver.cs - Implements "Hell's Gate" & "Halo's Gate" logic in C#.
//   Dynamically resolves System Service Numbers (SSNs) even if NTDLL is hooked.
//*/
//using System;
//using System.Runtime.InteropServices;
//using NativeProcesses.Core.PE; // Für PeHeaders
//using NativeProcesses.Core.PE.Export; // Für PeExports

//namespace NativeProcesses.Core.Native
//{
//    public static class SyscallResolver
//    {
      

//        // Liest Speicher vom EIGENEN Prozess (sehr schnell und sicher)
//        private static unsafe byte ReadByte(IntPtr address)
//        {
//            return *(byte*)address;
//        }

//        private static unsafe ushort ReadUInt16(IntPtr address)
//        {
//            return *(ushort*)address;
//        }

//        /// <summary>
//        /// Versucht, die Syscall-Nummer (SSN) für eine Funktion in NTDLL zu finden.
//        /// Umgeht User-Mode Hooks durch Halo's Gate Technik.
//        /// </summary>
//        public static int ResolveSyscall(string functionName)
//        {
//            // 1. NTDLL Basis finden
//            IntPtr hNtdll = Kernel32.GetModuleHandle("ntdll.dll");
//            if (hNtdll == IntPtr.Zero) return -1;

//            // 2. Adresse der Funktion finden (über Exports)
//            // Wir nutzen PeExports, um die Adresse zu finden (live im Speicher)
//            IntPtr funcAddress = PeExports.GetExportAddress(hNtdll, functionName);

//            if (funcAddress == IntPtr.Zero) return -1;

//            // 3. Halo's Gate: Suche nach dem Syscall-Opcode
//            // Wir suchen nach dem Muster:
//            // MOV R10, RCX (4C 8B D1)
//            // MOV EAX, <SSN> (B8 <SSN> 00 00)

//            // Wir scannen bis zu 32 Bytes nach unten (für Halo's Gate bei Hooks)
//            for (int offset = 0; offset < 32; offset++)
//            {
//                IntPtr currentAddr = IntPtr.Add(funcAddress, offset);

//                byte b0 = ReadByte(currentAddr);

//                // Abbruchbedingungen (wir sind zu weit gelaufen oder in falscher Instruktion)
//                if (b0 == 0xC3) return -1; // RET
//                if (b0 == 0xCC) return -1; // INT 3

//                // Check auf SYSCALL (0F 05) - Wenn wir das sehen, haben wir das MOV verpasst
//                if (b0 == 0x0F && ReadByte(IntPtr.Add(currentAddr, 1)) == 0x05) return -1;

//                // Check auf MOV R10, RCX (4C 8B D1)
//                // Das ist der Standard-Anfang.
//                if (b0 == 0x4C &&
//                    ReadByte(IntPtr.Add(currentAddr, 1)) == 0x8B &&
//                    ReadByte(IntPtr.Add(currentAddr, 2)) == 0xD1 &&
//                    ReadByte(IntPtr.Add(currentAddr, 3)) == 0xB8) // MOV EAX...
//                {
//                    // Treffer! Das Byte nach B8 ist das Low-Byte der SSN.
//                    // Das Byte danach ist das High-Byte.
//                    byte low = ReadByte(IntPtr.Add(currentAddr, 4));
//                    byte high = ReadByte(IntPtr.Add(currentAddr, 5));

//                    return (high << 8) | low;
//                }

//                // HALO'S GATE LOGIK:
//                // Wenn die Funktion gehookt ist (z.B. durch JMP 0xE9), steht am Anfang kein 4C 8B D1.
//                // Wir scannen weiter. In der originalen C++ Implementierung wird auch geprüft,
//                // ob wir einfach nur ein MOV EAX (0xB8) finden, ohne das MOV R10, RCX davor.
//                // Das passiert oft bei Nachbarfunktionen, deren Code wir "borgen".

//                if (b0 == 0xB8)
//                {
//                    // Prüfen ob es eine SSN ist (High Bytes sollten 0 sein)
//                    byte next1 = ReadByte(IntPtr.Add(currentAddr, 1)); // Low SSN
//                    byte next2 = ReadByte(IntPtr.Add(currentAddr, 2)); // High SSN
//                    byte next3 = ReadByte(IntPtr.Add(currentAddr, 3)); // 00
//                    byte next4 = ReadByte(IntPtr.Add(currentAddr, 4)); // 00

//                    if (next3 == 0x00 && next4 == 0x00)
//                    {
//                        // Plausibilitätscheck: Ist es ein Syscall?
//                        // Syscalls sind meist < 500 (0x1F4)
//                        int ssn = (next2 << 8) | next1;
//                        if (ssn > 0 && ssn < 0x1000)
//                        {
//                            return ssn;
//                        }
//                    }
//                }
//            }

//            return -1;
//        }
//    }
//}