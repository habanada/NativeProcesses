namespace NativeProcesses.Core.Models
{
    public class DotNetHeapStat
    {
        public string TypeName { get; set; }
        public int Count { get; set; }
        public long TotalSize { get; set; }
    }
}