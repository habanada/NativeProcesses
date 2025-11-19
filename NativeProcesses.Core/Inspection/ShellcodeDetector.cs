/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NativeProcesses.Core.Inspection
{
    /// <summary>
    /// Verbesserter Shellcode-Detector basierend auf Heuristiken von PE-sieve und Moneta.
    /// Reduziert False-Positives durch Histogramm-Analyse und Opcodes-Verteilung.
    /// </summary>
    public static class ShellcodeDetector
    {
        private struct ShellcodePattern
        {
            public string Name;
            public byte[] Bytes;
            public bool IsStrongIndicator;

            public ShellcodePattern(string name, byte[] bytes, bool strong = true)
            {
                Name = name;
                Bytes = bytes;
                IsStrongIndicator = strong;
            }
        }

        private struct BufferStats
        {
            public double Entropy;
            public Dictionary<byte, int> Histogram;
            public int Size;
            public double PrintableRatio; // Anteil druckbarer Zeichen
            public byte MostFrequentByte;
        }

        private static List<ShellcodePattern> _patterns;

        static ShellcodeDetector()
        {
            _patterns = new List<ShellcodePattern>();
            // Versuche externe Signaturen zu laden
            try
            {
                var loadedSigs = SignatureLoader.LoadEncryptedSignatures("signatures.dat");
                if (loadedSigs != null && loadedSigs.Count > 0)
                {
                    foreach (var sig in loadedSigs)
                    {
                        byte[] bytes;
                        if (!string.IsNullOrEmpty(sig.PatternString))
                        {
                            bytes = sig.IsStringAscii ? Encoding.ASCII.GetBytes(sig.PatternString) : Encoding.Unicode.GetBytes(sig.PatternString);
                        }
                        else
                        {
                            bytes = StringToByteArray(sig.PatternHex);
                        }
                        _patterns.Add(new ShellcodePattern(sig.Name, bytes, sig.IsStrongIndicator));
                    }
                }
            }
            catch { }

            // Fallback auf interne Pattern, falls Datei fehlt
            if (_patterns.Count == 0)
            {
                AddDefaultPatterns();
            }
        }

        private static void AddDefaultPatterns()
        {
            // Starke Indikatoren (Klassische Malware-Techniken)
            _patterns.Add(new ShellcodePattern("x64 PEB Access (GS:[60h])", new byte[] { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00 }));
            _patterns.Add(new ShellcodePattern("x86 PEB Access (FS:[30h])", new byte[] { 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00 }));
            _patterns.Add(new ShellcodePattern("GetPC (CALL+0/POP)", new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58 }));
            _patterns.Add(new ShellcodePattern("Metasploit ShikataGaNai (FPU)", new byte[] { 0xD9, 0xEE, 0xD9, 0x74, 0x24, 0xF4 }));

            // Cobalt Strike Strings
            _patterns.Add(new ShellcodePattern("String: beacon.x64.dll", Encoding.ASCII.GetBytes("beacon.x64.dll")));
            _patterns.Add(new ShellcodePattern("String: ReflectiveLoader", Encoding.ASCII.GetBytes("ReflectiveLoader")));
        }

        public static bool IsLikelyShellcode(byte[] buffer, out string detectionReason)
        {
            detectionReason = "Clean";
            if (buffer == null || buffer.Length == 0) return false;

            // 1. Performance: Leere Buffer sofort überspringen
            if (IsAllZeros(buffer)) return false;

            // 2. Statistik berechnen (Entropie + Histogramm) - Inspiriert von PE-sieve stats_analyzer
            var stats = CalculateStats(buffer);

            // 3. Heuristik: Text/Daten Filter
            // Wenn es hauptsächlich Text ist (z.B. XML, JSON, Logs), ist es kein Shellcode, auch wenn die Entropie hoch ist.
            if (stats.PrintableRatio > 0.90)
            {
                // Ausnahme: Base64 Strings könnten Payload sein, aber direkt ausführbar sind sie nicht.
                // Wir ignorieren "Text" hier, um False Positives zu vermeiden.
                return false;
            }

            // 4. Pattern Scan (Signaturbasiert)
            foreach (var pattern in _patterns)
            {
                if (IndexOfSequence(buffer, pattern.Bytes) != -1)
                {
                    if (pattern.IsStrongIndicator)
                    {
                        detectionReason = $"CRITICAL THREAT: {pattern.Name}";
                        return true;
                    }
                    else
                    {
                        detectionReason = $"Suspicious Artifact: {pattern.Name}";
                        // Schwache Pattern reichen allein oft nicht, wir schauen weiter auf Stats
                    }
                }
            }

            // 5. Heuristik: Maschinencode-Verteilung
            // Echter Code hat eine spezifische Verteilung von Opcodes (00, FF, E8, C3, 55, etc.)
            if (CheckForMachineCode(stats))
            {
                // Wenn wir schon einen schwachen Pattern-Treffer hatten, ist das die Bestätigung
                if (detectionReason == "Clean")
                    detectionReason = "Heuristics: High Machine Code Probability";
                return true;
            }

            // 6. Heuristik: High Entropy (Packed/Encrypted)
            // PE-sieve nutzt > 6.0 für "Possibly Encrypted", > 7.0 für "Strong Encryption"
            // Wir filtern hier aber Fälle raus, wo ein Byte extrem dominiert (z.B. Bitmap-Hintergrund)
            if (stats.Entropy > 6.8)
            {
                // Prüfen ob es nicht einfach ein Bild oder komprimierte Daten mit einem dominanten Byte ist
                double maxFreqRatio = (double)stats.Histogram[stats.MostFrequentByte] / stats.Size;
                if (maxFreqRatio < 0.10) // Wenn kein Byte mehr als 10% ausmacht -> Echte hohe Entropie
                {
                    detectionReason = $"High Entropy ({stats.Entropy:F2}) - Potential Packed/Encrypted Payload";
                    return true;
                }
            }

            // Wenn wir einen schwachen Pattern-Treffer hatten, aber die Stats dagegen sprechen, geben wir es trotzdem als Warnung aus
            if (detectionReason != "Clean") return true;

            return false;
        }

        private static BufferStats CalculateStats(byte[] buffer)
        {
            var map = new Dictionary<byte, int>();
            int printableCount = 0;
            int maxCount = 0;
            byte maxByte = 0;

            foreach (byte b in buffer)
            {
                if (!map.ContainsKey(b)) map.Add(b, 0);
                map[b]++;

                if (map[b] > maxCount)
                {
                    maxCount = map[b];
                    maxByte = b;
                }

                // Prüfen auf druckbare Zeichen (ASCII 32-126 und Standard Whitespace)
                if ((b >= 32 && b <= 126) || b == 0x09 || b == 0x0A || b == 0x0D)
                {
                    printableCount++;
                }
            }

            double entropy = 0.0;
            int len = buffer.Length;
            foreach (var item in map)
            {
                var frequency = (double)item.Value / len;
                entropy -= frequency * (Math.Log(frequency) / Math.Log(2));
            }

            return new BufferStats
            {
                Entropy = entropy,
                Histogram = map,
                Size = len,
                PrintableRatio = (double)printableCount / len,
                MostFrequentByte = maxByte
            };
        }

        // Implementiert Logik ähnlich wie pe-sieve's CodeMatcher
        private static bool CheckForMachineCode(BufferStats stats)
        {
            // Code hat selten extrem niedrige oder extrem hohe Entropie
            if (stats.Entropy < 2.5 || stats.Entropy > 6.8) return false;

            int points = 0;

            // Prüfe auf typische x86/x64 Befehls-Bytes und deren Häufigkeit
            if (GetByteRatio(stats, 0x00) > 0.05) points++; // NOPs / Padding / Operands
            if (GetByteRatio(stats, 0x0F) > 0.005) points++; // Multi-byte Opcode Prefix
            if (GetByteRatio(stats, 0x48) > 0.01) points++; // REX.W Prefix (x64)
            if (GetByteRatio(stats, 0x8B) > 0.01) points++; // MOV
            if (GetByteRatio(stats, 0xFF) > 0.01) points++; // CALL/JMP indirect
            if (GetByteRatio(stats, 0xE8) > 0.005) points++; // CALL relative
            if (GetByteRatio(stats, 0xC3) > 0.001) points++; // RET
            if (GetByteRatio(stats, 0x55) > 0.001) points++; // PUSH RBP (Prologue)

            // Wir brauchen mindestens 3 Indikatoren für "Likely Code"
            return points >= 3;
        }

        private static double GetByteRatio(BufferStats stats, byte b)
        {
            if (stats.Histogram.TryGetValue(b, out int count))
            {
                return (double)count / stats.Size;
            }
            return 0.0;
        }

        private static byte[] StringToByteArray(string hex)
        {
            hex = hex.Replace(" ", "");
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        private static bool IsAllZeros(byte[] buffer)
        {
            int len = buffer.Length;
            for (int i = 0; i < len; i++) if (buffer[i] != 0) return false;
            return true;
        }

        private static int IndexOfSequence(byte[] buffer, byte[] pattern)
        {
            int len = pattern.Length;
            int limit = buffer.Length - len;
            for (int i = 0; i <= limit; i++)
            {
                int k = 0;
                for (; k < len; k++) if (pattern[k] != buffer[i + k]) break;
                if (k == len) return i;
            }
            return -1;
        }
    }
}