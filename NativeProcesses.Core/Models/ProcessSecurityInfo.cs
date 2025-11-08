/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
namespace NativeProcesses.Core
{
    public class ProcessSecurityInfo
    {
        public ProcessSecurityInfo()
        {
        }

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