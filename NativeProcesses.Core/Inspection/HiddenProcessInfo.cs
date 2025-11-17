/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;

namespace NativeProcesses.Core.Inspection
{
    public class HiddenProcessInfo
    {
        public int Pid { get; set; }
        public string Name { get; set; }
        public string ExePath { get; set; }
        public string DetectionMethod { get; set; }
    }
}