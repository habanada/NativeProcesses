/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
namespace NativeProcesses.Core.Inspection.Heuristics
{
    public class HeuristicResult
    {
        public string RuleName { get; set; }
        public ScanCategory Category { get; set; }
        public ThreatScore Score { get; set; }
        public string Description { get; set; }
        public string AddressInfo { get; set; }
        public string Artifact { get; set; }

        public HeuristicResult(string rule, ScanCategory cat, ThreatScore score, string desc, string addr = "", string artifact = "")
        {
            RuleName = rule;
            Category = cat;
            Score = score;
            Description = desc;
            AddressInfo = addr;
            Artifact = artifact;
        }
    }
}