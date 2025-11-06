namespace NativeProcesses
{
    public class ProcessDetailOptions
    {
        public bool LoadExePathAndCommandLine { get; set; } = true;
        public bool LoadIoCounters { get; set; } = true;
        public bool LoadSecurityInfo { get; set; } = true;
        public bool LoadMitigationInfo { get; set; } = true;
        public bool LoadSignatureInfo { get; set; } = true;
        public bool LoadFileVersionInfo { get; set; } = true;
    }
}