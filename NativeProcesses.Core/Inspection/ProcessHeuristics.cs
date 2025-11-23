using System;
using System.Collections.Generic;

namespace NativeProcesses.Core.Inspection
{
    public static class ProcessHeuristics
    {
        // Prozesse, die legitimen JIT-Code (Private+Execute) erzeugen
        private static readonly HashSet<string> JitProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe", "vivaldi.exe",
            "javaw.exe", "java.exe", "eclipse.exe",
            "discord.exe", "code.exe", "teams.exe", "slack.exe", "spotify.exe",
            "devenv.exe", "powershell.exe", "pwsh.exe"
        };

        public static bool IsKnownJitProcess(string processName)
        {
            if (string.IsNullOrEmpty(processName)) return false;
            return JitProcessNames.Contains(processName);
        }

        /// <summary>
        /// Entscheidet, ob eine Speicherregion wahrscheinlich harmloser JIT-Code ist.
        /// </summary>
        public static bool IsLikelyJitMemory(string processName, string protection, byte[] content)
        {
            // 1. Kontext: Ist es ein bekannter JIT-Prozess?
            if (!IsKnownJitProcess(processName)) return false;

            // 2. Schutz: JIT muss ausführbar sein
            if (!protection.ToUpper().Contains("EXECUTE")) return false;

            // 3. Inhalt: JIT-Code hat NIEMALS einen PE-Header (MZ) am Anfang
            if (content.Length > 2 && content[0] == 0x4D && content[1] == 0x5A) return false;

            // (Optional könnte man hier auf typische Shellcode-Muster prüfen, 
            // aber JIT-Code ist meist sehr "chaotisch", genau wie Shellcode)

            return true; // Vermutlich Safe
        }
    }
}