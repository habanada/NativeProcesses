/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
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