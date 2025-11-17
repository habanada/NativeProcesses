/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
namespace NativeProcesses.Core.Models
{
    public class DotNetGcRootPathInfo
    {
        public string Kind { get; set; }
        public ulong Address { get; set; }
        public string TypeName { get; set; }
        public string RootKind { get; set; }
    }
}