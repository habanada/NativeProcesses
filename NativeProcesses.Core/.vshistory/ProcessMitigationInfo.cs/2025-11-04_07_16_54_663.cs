namespace NativeProcesses
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

        public ProcessMitigationInfo Clone()
        {
            return (ProcessMitigationInfo)this.MemberwiseClone();
        }
    }
}