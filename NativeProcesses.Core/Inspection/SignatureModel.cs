/*
   NativeProcesses Framework  |
   © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;

namespace NativeProcesses.Core.Inspection
{
    public class SignatureModel
    {
        public string Name { get; set; }
        public string PatternHex { get; set; } // Format: "64 A1 30 00" oder "64A13000"
        public string PatternString { get; set; } // Optional: Für String-Suche (z.B. "beacon.dll")
        public bool IsStringAscii { get; set; } // True=ASCII, False=Unicode (nur relevant wenn PatternString gesetzt)
        public bool IsStrongIndicator { get; set; }
    }
}