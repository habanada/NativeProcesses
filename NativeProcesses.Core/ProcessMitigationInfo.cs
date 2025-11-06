/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
namespace NativeProcesses.Core
{
    public class ProcessMitigationInfo
    {
        public bool DepEnabled { get; set; } = false;
        public bool DepAtlThunkEmulationDisabled { get; set; } = false;
        public bool AslrEnabled { get; set; } = false;
        public bool AslrForceRelocateImages { get; set; } = false;
        public bool CfgEnabled { get; set; } = false;
        public bool DynamicCodeProhibited { get; set; } = false;
        public bool Win32kSystemCallsDisabled { get; set; } = false;
        public ProcessMitigationInfo()
        {
        }

        public ProcessMitigationInfo Clone()
        {
            return (ProcessMitigationInfo)this.MemberwiseClone();
        }
    }
}