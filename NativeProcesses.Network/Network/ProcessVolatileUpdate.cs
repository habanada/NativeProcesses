/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
namespace NativeProcesses.Network
{
    public class ProcessVolatileUpdate
    {
        public int Pid { get; set; }
        public double Cpu { get; set; }
        public long WorkingSet { get; set; }
        public int ThreadCount { get; set; }
        public int BasePriority { get; set; }
        public long TotalReadBytes { get; set; }
        public long TotalWriteBytes { get; set; }
        public long TotalReadOps { get; set; }
        public long TotalWriteOps { get; set; }
        public long TotalPageFaults { get; set; }
        public long PagedPool { get; set; }
        public long NonPagedPool { get; set; }
        public long PrivatePageCount { get; set; }
        public long PagefileUsage { get; set; }
    }
}