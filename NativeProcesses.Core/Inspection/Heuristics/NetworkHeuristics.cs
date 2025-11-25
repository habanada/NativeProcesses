/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace NativeProcesses.Core.Inspection.Heuristics
{
    public static class NetworkHeuristics
    {
        // 1. Verdächtige Top-Level-Domains (TLDs)
        // Malware nutzt oft billige/anonyme Domains.
        private static readonly HashSet<string> SuspiciousTlds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".ru", ".cn", ".xyz", ".top", ".pw", ".cc", ".su", ".club", ".onion",
            ".kim", ".ir", ".tk", ".ml", ".ga", ".cf", ".gq", ".info", ".pro"
        };

        // 2. Verdächtige Ports (Standard-Ports für bekannte RATs/C2s)
        private static readonly HashSet<int> SuspiciousPorts = new HashSet<int>
        {
            4444, // Metasploit / Cobalt Strike Default
            1337, // "Leet" Port (oft in Skript-Kiddie Malware)
            6667, // IRC (Botnets)
            8080, 8443, // Alt-HTTP/HTTPS (oft Proxies)
            31337, // Back Orifice
            1604, // DarkComet
            1177, // NjRAT
            5552, // NanoCore
            81, 82, 8888 // Simple Web Shells
        };

        // 3. Verdächtige URI-Pfade (C2 Profile Signaturen)
        // Cobalt Strike, Empire, Metasploit nutzen oft spezifische URL-Strukturen.
        private static readonly string[] SuspiciousUriPatterns = new string[]
        {
            "/admin/get.php",
            "/news.php",
            "/pictures/",
            "/api/v1/client", // Generic API lookalikes
            "/gate.php",
            "/login/process.php",
            "/upload.php",
            ".php?id=", // Simple PHP C2s
            "token=",
            "auth="
        };

        // Regex für IP-Adressen (IPv4)
        private static readonly Regex IpRegex = new Regex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled);

        // Whitelist für vertrauenswürdige Domains (um False Positives zu vermeiden)
        private static readonly HashSet<string> WhitelistedDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "microsoft.com", "windowsupdate.com", "google.com", "googleapis.com",
            "live.com", "azure.com", "digicert.com", "symantec.com", "thawte.com",
            "verisign.com", "msocsp.com", "cloudflare.com", "akamaiedge.net"
        };

        public static bool IsSuspiciousUrl(string url, out string reason)
        {
            reason = null;
            if (string.IsNullOrEmpty(url)) return false;

            Uri uri;
            try
            {
                // Versuchen, die URL zu parsen. Wenn kein Schema da ist, "http://" davor setzen.
                if (!url.Contains("://")) url = "http://" + url;
                uri = new Uri(url);
            }
            catch
            {
                // Wenn URL nicht parsbar ist, aber wie IP aussieht, prüfen wir das roh
                var match = IpRegex.Match(url);
                if (match.Success && !IsLocalIp(match.Value))
                {
                    reason = "Raw IP Address detected";
                    return true;
                }
                return false;
            }

            string host = uri.Host;

            // A. Whitelist Check
            if (WhitelistedDomains.Any(w => host.EndsWith(w, StringComparison.OrdinalIgnoreCase))) return false;

            // B. Direct IP Check (C2 Server nutzen oft direkt IPs statt DNS, um Takedowns zu erschweren)
            if (uri.HostNameType == UriHostNameType.IPv4)
            {
                if (IsLocalIp(host)) return false; // Localhost ist ok
                reason = "Direct Public IP Connection";
                return true;
            }

            // C. TLD Check
            string tld = host.Substring(host.LastIndexOf('.'));
            if (SuspiciousTlds.Contains(tld))
            {
                reason = $"Suspicious TLD ({tld})";
                return true;
            }

            // D. Port Check
            if (!uri.IsDefaultPort && SuspiciousPorts.Contains(uri.Port))
            {
                reason = $"Suspicious C2 Port ({uri.Port})";
                return true;
            }

            // E. Path Patterns Check
            foreach (var pattern in SuspiciousUriPatterns)
            {
                if (uri.PathAndQuery.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    reason = $"Known C2 URI Pattern ('{pattern}')";
                    return true;
                }
            }

            return false;
        }

        private static bool IsLocalIp(string ip)
        {
            return ip.StartsWith("127.") || ip.StartsWith("192.168.") || ip.StartsWith("10.") || ip == "0.0.0.0";
        }
    }
}