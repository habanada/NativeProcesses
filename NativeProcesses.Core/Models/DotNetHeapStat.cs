/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
namespace NativeProcesses.Core.Models
{
    public class DotNetHeapStat
    {
        public string TypeName { get; set; }
        public int Count { get; set; }
        public long TotalSize { get; set; }
    }
}