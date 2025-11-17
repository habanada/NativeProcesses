/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
namespace NativeProcesses.Core.Models
{
    public class DotNetFinalizerInfo
    {
        public ulong ObjectAddress { get; set; }
        public string TypeName { get; set; }
    }
}