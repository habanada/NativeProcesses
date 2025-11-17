/*
   NativeProcesses Framework  |
   © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NativeProcesses.Core.Inspection
{
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

        private static List<ShellcodePattern> _patterns;

        // Statischer Konstruktor lädt die Signaturen einmalig
        static ShellcodeDetector()
        {
            _patterns = new List<ShellcodePattern>();

            // 1. Versuche, externe DB zu laden
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

            // 2. Fallback: Wenn Datei leer/fehlt, nutze Hardcoded Defaults (Safety Net)
            if (_patterns.Count == 0)
            {
                AddDefaultPatterns();
            }
        }

        private static void AddDefaultPatterns()
        {
            // Die wichtigsten Fallbacks, falls signatures.dat fehlt
            _patterns.Add(new ShellcodePattern("x64 PEB Access (MOV RAX, GS:[60h])", new byte[] { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00 }));
            _patterns.Add(new ShellcodePattern("GetPC (CALL+0/POP)", new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58 }));
            _patterns.Add(new ShellcodePattern("String: beacon.x64.dll", Encoding.ASCII.GetBytes("beacon.x64.dll")));
            // ... weitere Defaults hier einfügen wenn gewünscht
        }

        public static bool IsLikelyShellcode(byte[] buffer, out string detectionReason)
        {
            detectionReason = "Clean";
            if (buffer == null || buffer.Length == 0) return false;
            if (IsAllZeros(buffer)) return false;

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
                    }
                }
            }

            if (detectionReason != "Clean") return true;

            double entropy = CalculateShannonEntropy(buffer);
            if (entropy > 6.8)
            {
                detectionReason = $"High Entropy ({entropy:F2}) - Potential Packed/Encrypted Code";
                return true;
            }
            return false;
        }

        // Helper: "64 A1 30" -> byte[]
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