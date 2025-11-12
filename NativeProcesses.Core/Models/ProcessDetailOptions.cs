/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
namespace NativeProcesses.Core
{
    public class ProcessDetailOptions
    {
        public bool LoadExePathAndCommandLine { get; set; } = true;
        public bool LoadIoCounters { get; set; } = true;
        public bool LoadSecurityInfo { get; set; } = true;
        public bool LoadMitigationInfo { get; set; } = true;
        public bool LoadSignatureInfo { get; set; } = true;
        public bool LoadFileVersionInfo { get; set; } = true;
        public bool LoadModules { get; set; } = false;
        public bool LoadHandles { get; set; } = false;
        public bool LoadExtendedStatusFlags { get; set; } = true;
    }    
}