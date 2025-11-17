/*
   NativeProcesses Framework  |
   © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Collections.Generic;
using System.Linq;

namespace NativeProcesses.Core.Inspection
{
    public static class ShellcodeDetector
    {
        // Klassische Shellcode-Signaturen (Hasherezade / Metasploit Style)
        private static readonly List<byte[]> SuspiciousPatterns = new List<byte[]>
        {
            // x86 PEB Access: MOV EAX, FS:[30h] -> Holt PEB Adresse
            new byte[] { 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00 }, 
            
            // x64 PEB Access: MOV RAX, GS:[60h] -> Holt PEB Adresse
            new byte[] { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00 }, 
            
            // Call Next / Pop (GetPC / Delta Offset Technik)
            // CALL +0 (E8 00 00 00 00), dann POP reg
            new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58 }, // POP RAX
            new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x59 }, // POP RCX
            new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B }, // POP RBX

            // Standard Prologue (Push EBP; Mov EBP, ESP) - oft in generiertem Shellcode
            new byte[] { 0x55, 0x8B, 0xEC },

            // NOP Sleds (lange Ketten von 0x90) - wir suchen nach mind. 8 NOPs
            new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }
        };

        public static bool IsLikelyShellcode(byte[] buffer, out string detectionReason)
        {
            detectionReason = "Clean";

            if (buffer == null || buffer.Length == 0)
                return false;

            // 1. Empty Check (Performance & False Positive Reduction)
            // Wenn der Buffer nur aus Nullen besteht, ist es reservierter Speicher, kein Code.
            if (IsAllZeros(buffer))
                return false;

            // 2. Pattern Matching (Deep Scan)
            // Wir scannen den Buffer nach bekannten Shellcode-Instruktionen.
            foreach (var pattern in SuspiciousPatterns)
            {
                if (IndexOfSequence(buffer, pattern) != -1)
                {
                    detectionReason = "Shellcode Pattern Detected (PEB Access / GetPC / NopSled)";
                    return true;
                }
            }

            // 3. Heuristik für "High Entropy" (Verschlüsselter Payload)
            // Wenn wir keine bekannten Instruktionen finden, aber die Entropie extrem hoch ist
            // UND es ausführbarer Speicher ist (das wird vom Aufrufer geprüft), ist es verdächtig (Packed).
            double entropy = CalculateShannonEntropy(buffer);
            if (entropy > 7.0) // 0.0 bis 8.0.  > 7 ist fast sicher komprimiert oder verschlüsselt.
            {
                detectionReason = $"High Entropy ({entropy:F2}) - Potential Packed Malware";
                return true;
            }

            return false;
        }

        private static bool IsAllZeros(byte[] buffer)
        {
            // Schneller Check, ob alles 0 ist.
            // Wir prüfen in 64-bit Schritten für Speed.
            int len = buffer.Length;
            for (int i = 0; i < len; i++)
            {
                if (buffer[i] != 0) return false;
            }
            return true;
        }

        private static int IndexOfSequence(byte[] buffer, byte[] pattern)
        {
            int len = pattern.Length;
            int limit = buffer.Length - len;
            for (int i = 0; i <= limit; i++)
            {
                int k = 0;
                for (; k < len; k++)
                {
                    if (pattern[k] != buffer[i + k]) break;
                }
                if (k == len) return i;
            }
            return -1;
        }

        private static double CalculateShannonEntropy(byte[] buffer)
        {
            var map = new Dictionary<byte, int>();
            foreach (byte b in buffer)
            {
                if (!map.ContainsKey(b)) map.Add(b, 1);
                else map[b]++;
            }

            double result = 0.0;
            int len = buffer.Length;
            foreach (var item in map)
            {
                var frequency = (double)item.Value / len;
                result -= frequency * (Math.Log(frequency) / Math.Log(2));
            }

            return result;
        }
    }
}