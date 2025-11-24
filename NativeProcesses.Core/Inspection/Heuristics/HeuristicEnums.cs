/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/

namespace NativeProcesses.Core.Inspection.Heuristics
{
    public enum ThreatScore
    {
        None = 0,
        Low = 10,
        Medium = 40,
        High = 70,
        Critical = 100
    }

    public enum ScanCategory
    {
        General,
        Network,
        Cryptography,
        CodeInjection,
        Obfuscation,
        StealerArtifact
    }
}