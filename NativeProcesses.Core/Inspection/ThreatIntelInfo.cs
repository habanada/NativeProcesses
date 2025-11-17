/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;

namespace NativeProcesses.Core.Inspection
{
    public class ThreatIntelInfo
    {
        public int ProcessId { get; set; }
        public string EventName { get; set; }
        public string ProviderName { get; set; }
        public DateTime TimeStamp { get; set; }
        public string Detail { get; set; }
    }
}