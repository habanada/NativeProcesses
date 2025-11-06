namespace NativeProcesses
{
    public class ProcessSecurityInfo
    {
        public string UserName { get; set; } = "N/A";
        public string IntegrityLevel { get; set; } = "N/A";
        public bool IsElevated { get; set; } = false;
        public bool IsWow64 { get; set; } = false;
        public string ImageType => IsWow64 ? "32-bit" : "64-bit";

        public ProcessSecurityInfo Clone()
        {
            return (ProcessSecurityInfo)this.MemberwiseClone();
        }
    }
}