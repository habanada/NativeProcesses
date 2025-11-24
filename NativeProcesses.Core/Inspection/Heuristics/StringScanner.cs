/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Microsoft.Diagnostics.Runtime;
using System;
using System.Collections.Generic;

namespace NativeProcesses.Core.Inspection.Heuristics
{
    public class StringScanner
    {
        private static readonly string[] SuspiciousPatterns = new string[]
        {
            "powershell", "cmd.exe", "/c start",
            "System.Reflection", "Invoke",
            "DownloadString", "DownloadFile",
            "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
            "ReflectiveLoader", "AmsiScanBuffer",
            "TVqQAAMAAAAEAAAA",
            "FromBase64String"
        };

        public IEnumerable<HeuristicResult> Scan(ClrHeap heap)
        {
            var results = new List<HeuristicResult>();
            if (heap.StringType == null) return results;

            int findingsCount = 0;

            foreach (var obj in heap.EnumerateObjects())
            {
                if (obj.Type != heap.StringType) continue;

                string content = obj.AsString(1024);
                if (string.IsNullOrEmpty(content)) continue;

                if (content.Length > 500 && !content.Contains(" "))
                {
                    if (IsBase64(content))
                    {
                        results.Add(new HeuristicResult(
                            "Large Base64 String",
                            ScanCategory.Obfuscation,
                            ThreatScore.Medium,
                            $"Found large Base64 blob ({content.Length} chars). Possible payload.",
                            obj.Address.ToString("X"),
                            content.Substring(0, 30) + "..."
                        ));
                        findingsCount++;
                    }
                }

                foreach (string pattern in SuspiciousPatterns)
                {
                    if (content.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        results.Add(new HeuristicResult(
                            "Suspicious String IOC",
                            ScanCategory.General,
                            ThreatScore.Medium,
                            $"Found suspicious keyword: '{pattern}'",
                            obj.Address.ToString("X"),
                            content
                        ));
                        findingsCount++;
                    }
                }

                if (findingsCount > 50) break;
            }
            return results;
        }

        private bool IsBase64(string s)
        {
            if (s.Length % 4 != 0) return false;
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='))
                    return false;
            }
            return true;
        }
    }
}