namespace NativeProcesses.Network
{
    public class ProcessVolatileUpdate
    {
        public int Pid { get; set; }
        public double Cpu { get; set; }
        public long WorkingSet { get; set; }
        public int ThreadCount { get; set; }

        // --- NEU HINZUGEFÜGT ---
        public int BasePriority { get; set; }
        public long TotalReadBytes { get; set; }
        public long TotalWriteBytes { get; set; }
    }
}