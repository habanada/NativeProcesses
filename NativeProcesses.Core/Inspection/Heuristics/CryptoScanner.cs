/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Microsoft.Diagnostics.Runtime;
using System;
using System.Collections.Generic;

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

        public IEnumerable<HeuristicResult> Scan(ClrHeap heap)
        {
            var results = new List<HeuristicResult>();

            int standardCryptoCount = 0;
            int bouncyCastleCount = 0;
            int exoticCount = 0;
            int cryptoStreamCount = 0;

            foreach (var obj in heap.EnumerateObjects())
            {
                if (obj.Type == null || string.IsNullOrEmpty(obj.Type.Name)) continue;

                string typeName = obj.Type.Name;

                // 1. BouncyCastle Detection (Der heilige Gral der .NET Malware)
                if (typeName.Contains("BouncyCastle") || typeName.Contains("Org.BouncyCastle"))
                {
                    bouncyCastleCount++;

                    // Wir wollen wissen, WAS von BouncyCastle genutzt wird (Engine, Parameter, Signer)
                    if (typeName.Contains("Engine") || typeName.Contains("Parameter") || typeName.Contains("Signer"))
                    {
                        if (bouncyCastleCount <= 5)
                        {
                            AddResult(results, "Third-Party Crypto (BouncyCastle)", typeName, obj.Address, ThreatScore.High);
                        }
                    }
                    continue;
                }

                // 2. Exotic & Custom Crypto Detection (Name-Based)
                // Wir suchen nach Teilstrings wie "TwofishEngine", "ChaCha20Poly1305", "MyBlowfish"
                bool isExotic = false;
                foreach (var algo in ExoticAlgorithmNames)
                {
                    if (typeName.IndexOf(algo, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        // Filter: System-eigene Implementierungen (selten bei Exoten, aber möglich)
                        if (typeName.StartsWith("System.")) continue;

                        exoticCount++;
                        AddResult(results, $"Exotic Crypto Detected ({algo})", typeName, obj.Address, ThreatScore.High);
                        isExotic = true;
                        break;
                    }
                }
                if (isExotic) continue;

                // 3. Standard .NET Crypto (Microsoft Namespace)
                if (typeName.StartsWith("System.Security.Cryptography"))
                {
                    if (typeName.Contains("CryptoStream"))
                    {
                        cryptoStreamCount++;
                    }
                    else if (typeName.Contains("Aes") || typeName.Contains("Rijndael"))
                    {
                        standardCryptoCount++;
                    }
                    else if (typeName.Contains("RSA") || typeName.Contains("DSA") || typeName.Contains("ECDsa"))
                    {
                        standardCryptoCount++;
                    }
                    // TransformBlock / TransformFinalBlock Interfaces
                    else if (typeName.Contains("ICryptoTransform"))
                    {
                        standardCryptoCount++;
                    }
                }
                // 4. Generische Verdächtige (Custom Implementationen)
                else
                {
                    // Wenn eine Klasse "BlockCipher" oder "StreamCipher" heißt, aber nicht System ist -> Verdächtig
                    if (typeName.EndsWith("BlockCipher") || typeName.EndsWith("StreamCipher") || typeName.EndsWith("SBox"))
                    {
                        exoticCount++;
                        AddResult(results, "Generic Crypto Implementation", typeName, obj.Address, ThreatScore.Medium);
                    }
                }
            }

            // --- Aggregierte Analyse ---

            if (bouncyCastleCount > 0)
            {
                // BouncyCastle in einer normalen Business-App ist okay, aber in einer unbekannten EXE sehr verdächtig.
                // Wir werten es als High, da es die Standard-Waffe von RATs ist.
                results.Add(new HeuristicResult(
                    "BouncyCastle Library Detected",
                    ScanCategory.Cryptography,
                    ThreatScore.High,
                    $"Found {bouncyCastleCount} BouncyCastle objects. This library is heavily used by RATs/Stealers to bypass AV signatures.",
                    "Heap",
                    $"Count: {bouncyCastleCount}"
                ));
            }

            if (exoticCount > 0)
            {
                results.Add(new HeuristicResult(
                    "Non-Standard Encryption",
                    ScanCategory.Cryptography,
                    ThreatScore.Critical,
                    $"Process uses exotic algorithms (ChaCha/Twofish/etc). Malware often uses these to evade 'AES-only' hooks.",
                    "Heap",
                    $"Exotic Count: {exoticCount}"
                ));
            }

            if (cryptoStreamCount > 0)
            {
                ThreatScore score = cryptoStreamCount > 5 ? ThreatScore.High : ThreatScore.Medium;
                results.Add(new HeuristicResult(
                    "Active Crypto Streams",
                    ScanCategory.Cryptography,
                    score,
                    $"Process has {cryptoStreamCount} active CryptoStreams (Data Processing). Potential Ransomware loop.",
                    "Heap",
                    $"Streams: {cryptoStreamCount}"
                ));
            }

            return results;
        }

        private void AddResult(List<HeuristicResult> list, string rule, string type, ulong addr, ThreatScore score)
        {
            list.Add(new HeuristicResult(
                rule,
                ScanCategory.Cryptography,
                score,
                $"Identified crypto artifact: {type}",
                addr.ToString("X"),
                type
            ));
        }
    }
}