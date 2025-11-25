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
    public class ByteArrayScanner
    {
        public IEnumerable<HeuristicResult> Scan(ClrHeap heap, List<VirtualMemoryRegion> regions = null)
        {
            var results = new List<HeuristicResult>();
            int pointerSize = heap.Runtime.DataTarget.DataReader.PointerSize;

            // Performance: RWX Regionen cachen
            var execRegions = regions?
                .Where(r => r.Protection.ToUpper().Contains("EXECUTE"))
                .ToList();

            foreach (var obj in heap.EnumerateObjects())
            {
                if (obj.Type == null || !obj.IsArray || obj.Type.ElementType != ClrElementType.UInt8)
                    continue;

                int length = obj.AsArray().Length;
                if (length < 256) continue; // Zu klein für Shellcode Pattern

                ulong dataOffset = (ulong)pointerSize + 4;
                ulong dataAddress = obj.Address + dataOffset;

                // 1. VAD Check (Der stärkste Indikator)
                bool isRwx = false;
                if (execRegions != null)
                {
                    foreach (var region in execRegions)
                    {
                        ulong start = (ulong)region.BaseAddress.ToInt64();
                        ulong end = start + (ulong)region.RegionSize;
                        if (dataAddress >= start && dataAddress < end)
                        {
                            results.Add(new HeuristicResult(
                               "Executable Heap Object (RWX)",
                               ScanCategory.CodeInjection,
                               ThreatScore.Critical,
                               $"Byte array found in memory region with EXECUTE permissions ({region.Protection}). Active Shellcode Container.",
                               obj.Address.ToString("X"),
                               "RWX Memory"
                           ));
                            isRwx = true;
                            break;
                        }
                    }
                }

                // Wir lesen max 16KB für Deep Analysis (Sliding Window auf 100MB wäre zu langsam)
                int readLen = Math.Min(length, 16384);
                byte[] buffer = new byte[readLen];
                int bytesRead = heap.Runtime.DataTarget.DataReader.Read(dataAddress, new Span<byte>(buffer));

                if (bytesRead < 64) continue;

                // 2. PE Header Check (MZ)
                if (buffer[0] == 0x4D && buffer[1] == 0x5A)
                {
                    results.Add(new HeuristicResult(
                        "Floating PE Header",
                        ScanCategory.CodeInjection,
                        ThreatScore.Critical,
                        $"Found a raw PE file (DLL/EXE) in a byte[] array. Size: {length:N0} bytes.",
                        obj.Address.ToString("X"),
                        "MZ Header"
                    ));
                    continue;
                }

                // 3. Sliding Window Entropy (Der "Hidden Code" Finder)
                // Findet verschlüsselte Blöcke inmitten von Nullen
                if (ScanSlidingEntropy(buffer, out double maxWindowEntropy, out int entropyOffset))
                {
                    results.Add(new HeuristicResult(
                        "High Local Entropy (Hidden Payload)",
                        ScanCategory.Obfuscation,
                        ThreatScore.High,
                        $"Detected high entropy block ({maxWindowEntropy:F2}) at offset +0x{entropyOffset:X} inside array. Hidden packed data.",
                        obj.Address.ToString("X"),
                        $"MaxEntropy: {maxWindowEntropy:F2}"
                    ));

                    // 4. XOR Probing (Nur bei hoher Entropie prüfen)
                    // Wir prüfen, ob sich hinter der Entropie ein simpler XOR-Schlüssel verbirgt
                    if (ProbeXor(buffer, entropyOffset, out byte key))
                    {
                        results.Add(new HeuristicResult(
                           "XOR Encoded Payload",
                           ScanCategory.Obfuscation,
                           ThreatScore.Critical,
                           $"Detected potential XOR encoding with Key 0x{key:X2}. Decodes to 'This program cannot be run...'.",
                           obj.Address.ToString("X"),
                           $"XOR Key: 0x{key:X2}"
                       ));
                    }
                }

                // 5. Advanced Shellcode Pattern Engine (CALL/POP/SYSCALL)
                if (ScanShellcodePatterns(buffer, out string patternName))
                {
                    ThreatScore score = isRwx ? ThreatScore.Critical : ThreatScore.High;
                    results.Add(new HeuristicResult(
                        "Shellcode Pattern Detected",
                        ScanCategory.CodeInjection,
                        score,
                        $"Found shellcode signature: {patternName}",
                        obj.Address.ToString("X"),
                        patternName
                    ));
                }
            }
            return results;
        }

        // --- Algorithmen ---

        private bool ScanSlidingEntropy(byte[] buffer, out double maxEntropy, out int offset)
        {
            maxEntropy = 0;
            offset = 0;
            int windowSize = 256;
            int step = 128;

            if (buffer.Length < windowSize) return false;

            for (int i = 0; i <= buffer.Length - windowSize; i += step)
            {
                double currentEntropy = EntropyCalculator.Calculate(buffer, windowSize, i); // Braucht Überladung!
                if (currentEntropy > maxEntropy)
                {
                    maxEntropy = currentEntropy;
                    offset = i;
                }
            }

            return maxEntropy > 7.2;
        }

        private bool ProbeXor(byte[] buffer, int offset, out byte key)
        {
            key = 0;
            // Heuristik: Wir suchen nach dem "This program cannot be run in DOS mode" String.
            // Der ist ca. 70 Bytes nach dem Start.
            // Oder einfacher: Wir suchen nach 0-Bytes.
            // In einer PE-Datei sind viele Bytes 0x00. Wenn die Datei mit 0x77 XORed ist, sind viele Bytes 0x77.
            // Wir suchen das häufigste Byte. Das ist oft der XOR-Key (weil 0x00 ^ Key = Key).

            int limit = Math.Min(buffer.Length - offset, 512);
            if (limit < 64) return false;

            // Histogramm erstellen
            int[] counts = new int[256];
            byte mostFrequent = 0;
            int maxCount = 0;

            for (int i = offset; i < offset + limit; i++)
            {
                byte b = buffer[i];
                counts[b]++;
                if (counts[b] > maxCount)
                {
                    maxCount = counts[b];
                    mostFrequent = b;
                }
            }

            // Wenn ein Byte extrem dominiert (>30%), ist es wahrscheinlich der XOR-Key für 0x00 Bereiche
            if ((double)maxCount / limit > 0.3)
            {
                key = mostFrequent;
                // Gegenprüfung: Entschlüsselt das "MZ"?
                // MZ ist 4D 5A. 
                // Wenn am Anfang (Offset) 0x4D ^ Key und 0x5A ^ Key steht, haben wir einen Treffer.
                if (buffer.Length > offset + 1)
                {
                    byte b0 = (byte)(buffer[offset] ^ key);
                    byte b1 = (byte)(buffer[offset + 1] ^ key);
                    if (b0 == 0x4D && b1 == 0x5A) return true;
                }
            }
            return false;
        }

        private bool ScanShellcodePatterns(byte[] buffer, out string name)
        {
            name = null;

            // Pattern 1: CALL NEXT + POP (GetPC) -> E8 00 00 00 00 58 (x86) oder 59 (POP ECX)
            int callPopIndex = IndexOf(buffer, new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00 });
            if (callPopIndex != -1 && callPopIndex + 5 < buffer.Length)
            {
                byte pop = buffer[callPopIndex + 5];
                if (pop == 0x58 || pop == 0x59 || pop == 0x5A || pop == 0x5B) // POP EAX/ECX/EDX/EBX
                {
                    name = "GetPC (CALL 0 + POP)";
                    return true;
                }
            }

            // Pattern 2: Indirect Syscall Stub (Windows 10/11)
            // MOV R10, RCX; MOV EAX, <Syscall>; SYSCALL
            // 4C 8B D1 B8 ... 0F 05
            int syscallIndex = IndexOf(buffer, new byte[] { 0x4C, 0x8B, 0xD1, 0xB8 });
            if (syscallIndex != -1)
            {
                // Suche nach SYSCALL (0F 05) in der Nähe
                for (int i = 0; i < 16; i++)
                {
                    if (syscallIndex + i + 1 < buffer.Length && buffer[syscallIndex + i] == 0x0F && buffer[syscallIndex + i + 1] == 0x05)
                    {
                        name = "Direct Syscall Stub";
                        return true;
                    }
                }
            }

            // Pattern 3: NOP Sled (Massive 0x90)
            // Wir suchen nach 16x 0x90
            if (HasNopSled(buffer))
            {
                name = "NOP Sled (Exploit Payload)";
                return true;
            }

            return false;
        }

        private int IndexOf(byte[] data, byte[] pattern)
        {
            for (int i = 0; i <= data.Length - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (data[i + j] != pattern[j]) { match = false; break; }
                }
                if (match) return i;
            }
            return -1;
        }

        private bool HasNopSled(byte[] data)
        {
            int sequence = 0;
            foreach (byte b in data)
            {
                if (b == 0x90) sequence++;
                else sequence = 0;

                if (sequence >= 16) return true;
            }
            return false;
        }
    }
}