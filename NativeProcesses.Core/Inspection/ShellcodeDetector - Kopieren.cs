///*
//   NativeProcesses Framework  |
//   © 2025 Selahattin Erkoc
//   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
//*/
//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Text;

//namespace NativeProcesses.Core.Inspection
//{
//    public static class ShellcodeDetector
//    {
//        private struct ShellcodePattern
//        {
//            public string Name;
//            public byte[] Bytes;
//            public bool IsStrongIndicator;

//            public ShellcodePattern(string name, byte[] bytes, bool strong = true)
//            {
//                Name = name;
//                Bytes = bytes;
//                IsStrongIndicator = strong;
//            }
//        }

//        // Erweiterte Datenbank basierend auf PE-sieve / SigFinder / Metasploit Patterns
//        private static readonly List<ShellcodePattern> Patterns = new List<ShellcodePattern>
//        {
//            // --- PEB / TEB Access (Klassiker) ---
//            new ShellcodePattern("x86 PEB Access (MOV EAX, FS:[30h])", new byte[] { 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00 }),
//            new ShellcodePattern("x64 PEB Access (MOV RAX, GS:[60h])", new byte[] { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00 }),
//            new ShellcodePattern("x86 TEB Access (FS:[18h])", new byte[] { 0x64, 0xA1, 0x18, 0x00, 0x00, 0x00 }),
//            new ShellcodePattern("x86 SEH Chain Access (FS:[0])", new byte[] { 0x64, 0xA1, 0x00, 0x00, 0x00, 0x00 }),

//            // --- GetPC Techniken (Position Independent Code) ---
//            new ShellcodePattern("GetPC (CALL+0/POP EAX)", new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58 }),
//            new ShellcodePattern("GetPC (CALL+0/POP ECX)", new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x59 }),
//            new ShellcodePattern("GetPC (CALL+0/POP EBX)", new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B }),
            
//            // FPU GetPC (FNSTENV) - Sehr beliebt bei Metasploit/ShikataGaNai
//            new ShellcodePattern("FPU GetPC (FNSTENV)", new byte[] { 0xD9, 0xEE, 0xD9, 0x74, 0x24, 0xF4 }),
//            new ShellcodePattern("FPU GetPC (FNSAVE)", new byte[] { 0xDD, 0x74, 0x24, 0xF4 }),

//            // --- Direct Syscalls / Heaven's Gate ---
//            new ShellcodePattern("Direct Syscall (Generic)", new byte[] { 0x49, 0x89, 0xCA, 0xB8 }, false),
//            new ShellcodePattern("Syscall Opcode", new byte[] { 0x0F, 0x05 }, false),
//            new ShellcodePattern("Heaven's Gate (CS:0x33)", new byte[] { 0x6A, 0x33, 0xE8 }), 

//            // --- Standard Prologues & NOPs ---
//            new ShellcodePattern("Standard Prologue (x86)", new byte[] { 0x55, 0x8B, 0xEC }, false),
//            new ShellcodePattern("NOP Sled (8 bytes)", new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }),

//            // --- KUSER_SHARED_DATA Access ---
//            new ShellcodePattern("KUSER_SHARED_DATA Access", new byte[] { 0x7F, 0xFE, 0x00, 0x00 }, false),

//            // --- 2. NEU: Cobalt Strike & Malware String Indicators ---
//            new ShellcodePattern("String: CobaltStrike Beacon (ASCII)", Encoding.ASCII.GetBytes("beacon.x64.dll"), true),
//            new ShellcodePattern("String: CobaltStrike Beacon (Wide)", Encoding.Unicode.GetBytes("beacon.x64.dll"), true),
//            new ShellcodePattern("String: ReflectiveLoader (ASCII)", Encoding.ASCII.GetBytes("ReflectiveLoader"), true),
//            new ShellcodePattern("String: ReflectiveLoader (Wide)", Encoding.Unicode.GetBytes("ReflectiveLoader"), true),
//            new ShellcodePattern("String: VirtualAlloc (ASCII)", Encoding.ASCII.GetBytes("VirtualAlloc"), false),
//        };

//        public static bool IsLikelyShellcode(byte[] buffer, out string detectionReason)
//        {
//            detectionReason = "Clean";

//            if (buffer == null || buffer.Length == 0)
//                return false;

//            // 1. Empty Check (Performance)
//            if (IsAllZeros(buffer)) return false;

//            // 2. Pattern Scan
//            foreach (var pattern in Patterns)
//            {
//                if (IndexOfSequence(buffer, pattern.Bytes) != -1)
//                {
//                    if (pattern.IsStrongIndicator)
//                    {
//                        detectionReason = $"CRITICAL THREAT: {pattern.Name}";
//                        return true;
//                    }
//                    else
//                    {
//                        // Schwache Indikatoren merken wir uns vorerst nur
//                        detectionReason = $"Suspicious Artifact: {pattern.Name}";
//                    }
//                }
//            }

//            // Wenn wir zumindest einen schwachen Indikator gefunden haben, geben wir True zurück
//            if (detectionReason != "Clean") return true;

//            // 3. High Entropy Check (Packed Code)
//            double entropy = CalculateShannonEntropy(buffer);
//            if (entropy > 6.8)
//            {
//                detectionReason = $"High Entropy ({entropy:F2}) - Potential Packed/Encrypted Code";
//                return true;
//            }

//            return false;
//        }

//        private static bool IsAllZeros(byte[] buffer)
//        {
//            int len = buffer.Length;
//            for (int i = 0; i < len; i++) if (buffer[i] != 0) return false;
//            return true;
//        }

//        private static int IndexOfSequence(byte[] buffer, byte[] pattern)
//        {
//            int len = pattern.Length;
//            int limit = buffer.Length - len;
//            for (int i = 0; i <= limit; i++)
//            {
//                int k = 0;
//                for (; k < len; k++) if (pattern[k] != buffer[i + k]) break;
//                if (k == len) return i;
//            }
//            return -1;
//        }

//        private static double CalculateShannonEntropy(byte[] buffer)
//        {
//            var map = new Dictionary<byte, int>();
//            foreach (byte b in buffer)
//            {
//                if (!map.ContainsKey(b)) map.Add(b, 1);
//                else map[b]++;
//            }

//            double result = 0.0;
//            int len = buffer.Length;
//            foreach (var item in map)
//            {
//                var frequency = (double)item.Value / len;
//                result -= frequency * (Math.Log(frequency) / Math.Log(2));
//            }
//            return result;
//        }
//    }
//}