/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Microsoft.Diagnostics.Runtime;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace NativeProcesses.Core.Inspection.Heuristics
{
    public class StringScanner
    {
        private static readonly HashSet<string> IocKeywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "powershell", "cmdexe", "wscript", "cscript", "runpe", "shellcode", "reflective",
            "virtualalloc", "writeprocessmemory", "createremotethread", "ntmapviewofsection",
            "loadlibrary", "getprocaddress", "amsiscanbuffer", "etweventwrite",
            "http://", "https://", "127.0.0.1", "onion"
        };

        private static readonly HashSet<string> BrowserArtifacts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Login Data", "Web Data", "Cookies", "Local State", "Extension Cookies", "User Data", "cookies.sqlite", "places.sqlite"
        };

        private static readonly HashSet<string> KnownBenignStrings = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "System", "Microsoft", "Windows", "Culture", "Version", "PublicKeyToken",
            "neutral", "mscorlib", "v4.0.30319", "String", "Int32", "Boolean", "Char",
            "CompareTo", "Equals", "GetHashCode", "ToString", "GetType", ".ctor", "Invoke",
            "Finalize", "Dispose", "MemberwiseClone"
        };

        private static readonly Regex CleanerRegex = new Regex("[^a-zA-Z0-9]", RegexOptions.Compiled);
        private static readonly Regex Base64Regex = new Regex(@"^[a-zA-Z0-9\+/]{50,}={0,2}$", RegexOptions.Compiled);
        private static readonly Regex Utf7Regex = new Regex(@"^\+[A-Za-z0-9/]+-$", RegexOptions.Compiled);

        private static readonly Regex DiscordTokenRegex = new Regex(@"[A-Za-z0-9\\w-]{24}\.[A-Za-z0-9\\w-]{6}\.[A-Za-z0-9\\w-]{27}", RegexOptions.Compiled);
        private static readonly Regex TelegramBotRegex = new Regex(@"\d{8,10}:[A-Za-z0-9_-]{35}", RegexOptions.Compiled);
        private static readonly Regex AwsKeyRegex = new Regex(@"(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}", RegexOptions.Compiled);

        private static readonly Regex CryptoWalletRegex = new Regex(
            @"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b|" +
            @"\b0x[a-fA-F0-9]{40}\b|" +
            @"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b",
            RegexOptions.Compiled);

        public IEnumerable<HeuristicResult> Scan(ClrHeap heap)
        {
            var results = new List<HeuristicResult>();

            int suspiciousCount = 0;
            int base64Count = 0;
            int gzipCount = 0;

            var detectedCategories = new HashSet<string>();

            foreach (var obj in heap.EnumerateObjects())
            {
                if (obj.Type == null) continue;

                string content = null;

                if (obj.Type.IsString)
                {
                    content = obj.AsString(2048);
                }
                else if (obj.IsArray)
                {
                    int len = obj.AsArray().Length;
                    if (len > 10 && len < 4096)
                    {
                        if (obj.Type.ElementType == ClrElementType.Char)
                            content = ReadCharArray(obj);
                        else if (obj.Type.ElementType == ClrElementType.UInt8)
                            content = ReadByteArrayAsAscii(obj);
                    }
                }

                if (string.IsNullOrEmpty(content)) continue;

                if (IsBenign(content)) continue;

                if (content.Length > 40)
                {
                    if (DiscordTokenRegex.IsMatch(content))
                    {
                        results.Add(CreateResult("Stealer: Discord Token", ScanCategory.StealerArtifact, ThreatScore.High, obj.Address, content, "Discord Token"));
                        detectedCategories.Add("Stealer");
                    }
                    else if (TelegramBotRegex.IsMatch(content))
                    {
                        results.Add(CreateResult("Stealer: Telegram API Key", ScanCategory.StealerArtifact, ThreatScore.High, obj.Address, content, "Telegram Bot"));
                        detectedCategories.Add("C2");
                    }
                    else if (AwsKeyRegex.IsMatch(content))
                    {
                        results.Add(CreateResult("Stealer: AWS Access Key", ScanCategory.StealerArtifact, ThreatScore.High, obj.Address, content, "AWS Key"));
                        detectedCategories.Add("Stealer");
                    }
                    else if (CryptoWalletRegex.IsMatch(content))
                    {
                        results.Add(CreateResult("Stealer: Crypto Wallet Address", ScanCategory.StealerArtifact, ThreatScore.Medium, obj.Address, content, "Wallet Address"));
                        detectedCategories.Add("Wallet");
                    }

                    foreach (var artifact in BrowserArtifacts)
                    {
                        if (content.IndexOf(artifact, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            results.Add(CreateResult("Stealer: Browser Artifact", ScanCategory.StealerArtifact, ThreatScore.Medium, obj.Address, content, artifact));
                            detectedCategories.Add("Browser");
                            break;
                        }
                    }
                }

                if (content.Length > 50)
                {
                    if (IsBase64(content))
                    {
                        base64Count++;

                        if (content.StartsWith("H4sI"))
                        {
                            gzipCount++;
                            results.Add(CreateResult("Compressed Payload (Gzip+Base64)", ScanCategory.Obfuscation, ThreatScore.High, obj.Address, content, "Gzip Magic Header"));
                            detectedCategories.Add("Loader");
                        }
                        else if (base64Count <= 5)
                        {
                            results.Add(CreateResult("Suspicious Base64 Payload", ScanCategory.Obfuscation, ThreatScore.Medium, obj.Address, content, "Base64"));
                        }
                    }
                    else if (Utf7Regex.IsMatch(content))
                    {
                        results.Add(CreateResult("UTF-7 Obfuscated String", ScanCategory.Obfuscation, ThreatScore.Medium, obj.Address, content, "UTF-7 Pattern"));
                    }
                    else
                    {
                        double entropy = CalculateEntropy(content);
                        if (entropy > 6.5 && obj.Type.IsString)
                        {
                            results.Add(CreateResult("High Entropy String", ScanCategory.Obfuscation, ThreatScore.High, obj.Address, $"Entropy: {entropy:F2}", "Crypto/Packed"));
                        }
                    }
                }

                string cleanContent = CleanerRegex.Replace(content, "");
                if (cleanContent.Length < 4) continue;

                foreach (var keyword in IocKeywords)
                {
                    if (cleanContent.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        suspiciousCount++;
                        if (suspiciousCount <= 10)
                        {
                            results.Add(CreateResult("Obfuscated IOC Detected", ScanCategory.CodeInjection, ThreatScore.High, obj.Address, content, keyword));
                            detectedCategories.Add("IOC");
                        }
                        break;
                    }

                    if (Math.Abs(cleanContent.Length - keyword.Length) <= 2 && cleanContent.Length > 5)
                    {
                        int dist = ComputeLevenshteinDistance(cleanContent.ToLower(), keyword.ToLower());
                        if (dist <= 2)
                        {
                            suspiciousCount++;
                            if (suspiciousCount <= 10)
                            {
                                results.Add(CreateResult("Fuzzy IOC Match", ScanCategory.CodeInjection, ThreatScore.Medium, obj.Address, content, $"Match: {keyword}"));
                                detectedCategories.Add("IOC");
                            }
                            break;
                        }
                    }
                }

                if (content.IndexOf("IEX", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    content.IndexOf("Invoke-Expression", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    results.Add(CreateResult("PowerShell Stager", ScanCategory.CodeInjection, ThreatScore.Critical, obj.Address, content, "IEX Pattern"));
                    detectedCategories.Add("Loader");
                }
            }

            if (base64Count > 20)
                results.Add(new HeuristicResult("Base64 Flood", ScanCategory.Obfuscation, ThreatScore.Medium, $"Process contains massive amount ({base64Count}) of Base64 strings.", "Heap", "Count: " + base64Count));

            if (detectedCategories.Count >= 2)
            {
                string cats = string.Join(", ", detectedCategories);
                results.Add(new HeuristicResult(
                    "Multi-Vector Threat (Keyword Fusion)",
                    ScanCategory.StealerArtifact,
                    ThreatScore.Critical,
                    $"Process exhibits multiple disparate threat indicators ({cats}). Highly characteristic of complex Stealers/RATs.",
                    "Global",
                    "Fusion Match"));
            }

            return results;
        }

        private bool IsBenign(string s)
        {
            if (KnownBenignStrings.Contains(s)) return true;
            if (s.StartsWith("System.") || s.StartsWith("Microsoft.")) return true;
            return false;
        }

        private HeuristicResult CreateResult(string rule, ScanCategory cat, ThreatScore score, ulong addr, string details, string artifact)
        {
            string safeDetails = details.Length > 100 ? details.Substring(0, 97) + "..." : details;
            return new HeuristicResult(rule, cat, score, safeDetails, addr.ToString("X"), artifact);
        }

        private int ComputeLevenshteinDistance(string s, string t)
        {
            if (string.IsNullOrEmpty(s)) return string.IsNullOrEmpty(t) ? 0 : t.Length;
            if (string.IsNullOrEmpty(t)) return s.Length;

            int n = s.Length;
            int m = t.Length;
            int[,] d = new int[n + 1, m + 1];

            for (int i = 0; i <= n; d[i, 0] = i++) { }
            for (int j = 0; j <= m; d[0, j] = j++) { }

            for (int i = 1; i <= n; i++)
            {
                for (int j = 1; j <= m; j++)
                {
                    int cost = (t[j - 1] == s[i - 1]) ? 0 : 1;
                    d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
                }
            }
            return d[n, m];
        }

        private string ReadCharArray(ClrObject obj)
        {
            try
            {
                var arr = obj.AsArray();
                int len = arr.Length;
                int readLen = Math.Min(len, 512);
                char[] buffer = new char[readLen];
                for (int i = 0; i < readLen; i++) buffer[i] = arr.GetValue<char>(i);
                return new string(buffer);
            }
            catch { return null; }
        }

        private string ReadByteArrayAsAscii(ClrObject obj)
        {
            try
            {
                var arr = obj.AsArray();
                int len = arr.Length;
                int readLen = Math.Min(len, 512);
                byte[] buffer = new byte[readLen];
                for (int i = 0; i < readLen; i++) buffer[i] = arr.GetValue<byte>(i);

                int printable = 0;
                foreach (byte b in buffer) if ((b >= 32 && b <= 126) || b == 10 || b == 13 || b == 9) printable++;
                if ((double)printable / readLen < 0.7) return null;

                return Encoding.ASCII.GetString(buffer);
            }
            catch { return null; }
        }

        private double CalculateEntropy(string s)
        {
            var map = new Dictionary<char, int>();
            foreach (char c in s)
            {
                if (!map.ContainsKey(c)) map.Add(c, 1); else map[c]++;
            }
            double result = 0.0;
            int len = s.Length;
            foreach (var item in map)
            {
                var freq = (double)item.Value / len;
                result -= freq * (Math.Log(freq) / Math.Log(2));
            }
            return result;
        }

        private bool IsBase64(string s)
        {
            if (!Base64Regex.IsMatch(s)) return false;
            if (s.Length % 4 != 0) return false;
            return true;
        }
    }
}