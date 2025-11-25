/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Microsoft.Diagnostics.Runtime;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace NativeProcesses.Core.Inspection.Heuristics
{
    public class CryptoScanner
    {
        private static readonly HashSet<string> ExoticAlgorithmNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Twofish", "Blowfish", "Serpent", "Camellia", "Cast5", "Cast6", "Idea", "Gost", "Skipjack",
            "ChaCha", "Salsa", "XChaCha", "XSalsa", "RC4", "Arc4", "Vmpc", "HC128", "HC256", "Grain", "Rabbit",
            "Sosemanuk", "Blake2", "Whirlpool", "Ripemd", "Argon2", "Scrypt", "Bcrypt", "Keccak", "Threefish",
            "Skein", "Poly1305", "Curve25519", "Ed25519", "X25519"
        };

        private HashSet<string> _seenKeyHashes = new HashSet<string>();

        public IEnumerable<HeuristicResult> Scan(ClrHeap heap)
        {
            var results = new List<HeuristicResult>();
            _seenKeyHashes.Clear();

            int standardCryptoCount = 0;
            int bouncyCastleCount = 0;
            int exoticCount = 0;
            int cryptoStreamCount = 0;
            int weakKeyCount = 0;
            int reusedKeyCount = 0;
            int kdfCount = 0; // Key Derivation Function Count

            foreach (var obj in heap.EnumerateObjects())
            {
                if (obj.Type == null || string.IsNullOrEmpty(obj.Type.Name)) continue;

                string typeName = obj.Type.Name;

                // 1. BouncyCastle
                if (typeName.Contains("BouncyCastle") || typeName.Contains("Org.BouncyCastle"))
                {
                    bouncyCastleCount++;
                    if (typeName.Contains("Engine") || typeName.Contains("Parameter") || typeName.Contains("Signer"))
                    {
                        if (bouncyCastleCount <= 5)
                            AddResult(results, "Third-Party Crypto (BouncyCastle)", typeName, obj.Address, ThreatScore.High);
                    }
                    continue;
                }

                // 2. Exotic Algos
                bool isExotic = false;
                foreach (var algo in ExoticAlgorithmNames)
                {
                    if (typeName.IndexOf(algo, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        if (typeName.StartsWith("System.")) continue;
                        exoticCount++;
                        AddResult(results, $"Exotic Crypto Detected ({algo})", typeName, obj.Address, ThreatScore.High);
                        isExotic = true;
                        break;
                    }
                }
                if (isExotic) continue;

                // 3. System.Security.Cryptography
                if (typeName.StartsWith("System.Security.Cryptography"))
                {
                    // A. Streams
                    if (typeName.Contains("CryptoStream"))
                    {
                        cryptoStreamCount++;
                        CheckCryptoStream(obj, results);
                    }
                    // B. Symmetrisch (mit Key-Check)
                    else if (typeName.Contains("Aes") || typeName.Contains("Rijndael") || typeName.Contains("DES") || typeName.Contains("RC2"))
                    {
                        standardCryptoCount++;
                        CheckSymmetricKey(obj, results, ref weakKeyCount, ref reusedKeyCount);
                    }
                    // C. Asymmetrisch
                    else if (typeName.Contains("RSA") || typeName.Contains("DSA") || typeName.Contains("ECDsa"))
                    {
                        standardCryptoCount++;
                    }
                    // D. Key Derivation (KDF) - DAS WICHTIGE UPDATE
                    else if (typeName.Contains("Rfc2898DeriveBytes") || typeName.Contains("PasswordDeriveBytes") || typeName.Contains("DeriveBytes"))
                    {
                        kdfCount++;
                        // Einmalig melden, wenn gefunden
                        if (kdfCount == 1)
                            AddResult(results, "Dynamic Key Derivation", typeName, obj.Address, ThreatScore.Medium, "PBKDF2 / PasswordDeriveBytes detected");
                    }
                    // E. Interfaces
                    else if (typeName.Contains("ICryptoTransform"))
                    {
                        standardCryptoCount++;
                    }
                }
                else
                {
                    // Generic suspicious names
                    if (typeName.EndsWith("BlockCipher") || typeName.EndsWith("StreamCipher") || typeName.EndsWith("SBox"))
                    {
                        exoticCount++;
                        AddResult(results, "Generic Crypto Implementation", typeName, obj.Address, ThreatScore.Medium);
                    }
                }
            }

            // --- Aggregierte Analyse ---

            if (bouncyCastleCount > 0)
                results.Add(new HeuristicResult("BouncyCastle Library Detected", ScanCategory.Cryptography, ThreatScore.High, $"Found {bouncyCastleCount} BouncyCastle objects.", "Heap", $"Count: {bouncyCastleCount}"));

            if (exoticCount > 0)
                results.Add(new HeuristicResult("Non-Standard Encryption", ScanCategory.Cryptography, ThreatScore.Critical, $"Process uses exotic algorithms.", "Heap", $"Exotic Count: {exoticCount}"));

            if (cryptoStreamCount > 0)
            {
                ThreatScore score = cryptoStreamCount > 5 ? ThreatScore.High : ThreatScore.Medium;
                results.Add(new HeuristicResult("Active Crypto Streams", ScanCategory.Cryptography, score, $"Process has {cryptoStreamCount} active CryptoStreams.", "Heap", $"Streams: {cryptoStreamCount}"));
            }

            if (weakKeyCount > 0)
                results.Add(new HeuristicResult("Weak/Hardcoded Crypto Keys", ScanCategory.Cryptography, ThreatScore.High, $"Found {weakKeyCount} keys with low entropy.", "Heap", $"Weak Keys: {weakKeyCount}"));

            if (reusedKeyCount > 0)
                results.Add(new HeuristicResult("Crypto Key Reuse", ScanCategory.Cryptography, ThreatScore.High, $"Found {reusedKeyCount} identical keys.", "Heap", $"Reused: {reusedKeyCount}"));

            if (kdfCount > 2)
                results.Add(new HeuristicResult("Heavy Key Derivation", ScanCategory.Cryptography, ThreatScore.Medium, $"Multiple KDF objects ({kdfCount}) found. Possible password cracking or complex unpacking.", "Heap", $"KDF Count: {kdfCount}"));

            return results;
        }

        private void CheckSymmetricKey(ClrObject obj, List<HeuristicResult> results, ref int weakCount, ref int reuseCount)
        {
            try
            {
                // Manche Implementierungen nutzen "KeyValue", andere "m_keyValue"
                ClrObject keyField = obj.ReadObjectField("KeyValue");
                if (keyField.IsNull) keyField = obj.ReadObjectField("m_keyValue");

                // Falls das Feld nicht existiert oder null ist -> Abbruch
                if (keyField.IsNull) return;

                if (keyField.IsArray && keyField.Type.ElementType == ClrElementType.UInt8)
                {
                    var arr = keyField.AsArray();
                    int len = arr.Length;
                    if (len > 0 && len < 1024)
                    {
                        byte[] keyBytes = new byte[len];
                        for (int i = 0; i < len; i++) keyBytes[i] = arr.GetValue<byte>(i);

                        double entropy = CalculateEntropy(keyBytes);
                        string hash = ComputeHash(keyBytes);

                        // 1. Weak Key Check
                        if (entropy < 3.0)
                        {
                            weakCount++;
                            AddResult(results, "Weak Crypto Key Detected", obj.Type.Name, obj.Address, ThreatScore.High, $"Entropy: {entropy:F2} (Low)");
                        }

                        // 2. Reuse Check
                        if (_seenKeyHashes.Contains(hash))
                        {
                            reuseCount++;
                        }
                        else
                        {
                            _seenKeyHashes.Add(hash);
                        }
                    }
                }
            }
            catch { }
        }

        private void CheckCryptoStream(ClrObject obj, List<HeuristicResult> results)
        {
            try
            {
                // Wir prüfen den zugrundeliegenden Stream
                ClrObject streamField = obj.ReadObjectField("_stream");
                if (streamField.IsNull) return;

                if (streamField.Type != null && streamField.Type.Name == "System.IO.MemoryStream")
                {
                    ClrObject bufferField = streamField.ReadObjectField("_buffer");
                    if (!bufferField.IsNull && bufferField.IsArray)
                    {
                        int len = bufferField.AsArray().Length;
                        if (len > 1024)
                        {
                            AddResult(results, "In-Memory Crypto Stream", "CryptoStream -> MemoryStream", obj.Address, ThreatScore.Medium, $"Buffer Size: {len}");
                        }
                    }
                }
            }
            catch { }
        }

        private void AddResult(List<HeuristicResult> list, string rule, string type, ulong addr, ThreatScore score, string artifact = "")
        {
            string art = string.IsNullOrEmpty(artifact) ? type : artifact;
            list.Add(new HeuristicResult(
                rule,
                ScanCategory.Cryptography,
                score,
                $"Crypto Artifact: {type}",
                addr.ToString("X"),
                art
            ));
        }

        private double CalculateEntropy(byte[] data)
        {
            int[] frequency = new int[256];
            foreach (byte b in data) frequency[b]++;

            double entropy = 0.0;
            double len = (double)data.Length;

            for (int i = 0; i < 256; i++)
            {
                if (frequency[i] > 0)
                {
                    double p = (double)frequency[i] / len;
                    entropy -= p * Math.Log(p, 2);
                }
            }
            return entropy;
        }

        private string ComputeHash(byte[] data)
        {
            using (var sha = SHA256.Create())
            {
                return BitConverter.ToString(sha.ComputeHash(data));
            }
        }
    }
}