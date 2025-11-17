/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
namespace NativeProcesses.Core.Models
{
    public class DotNetStringDuplicateInfo
    {
        public string Value { get; set; }
        public int Count { get; set; }
        public long TotalSize { get; set; }
        public long WastedSize
        {
            get
            {
                if (Count <= 1)
                    return 0;

                long averageSize = TotalSize / Count;
                return (Count - 1) * averageSize;
            }
        }
    }
}