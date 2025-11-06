namespace NativeProcesses.Core
{
    public class ProcessSignatureInfo
    {
        public bool IsSigned { get; set; } = false;
        public string SignerName { get; set; } = "N/A";
        public string ErrorMessage { get; set; } = "N/A";
        public ProcessSignatureInfo()
        {
        }
        public ProcessSignatureInfo Clone()
        {
            return (ProcessSignatureInfo)this.MemberwiseClone();
        }
    }
}