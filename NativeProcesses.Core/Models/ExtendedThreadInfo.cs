namespace NativeProcesses.Core.Models
{
    public enum IoPriorityHint
    {
        VeryLow = 0,
        Low = 1,
        Normal = 2,
        High = 3,
        Critical = 4,
        Unknown = -1
    }

    public enum MemoryPriorityHint
    {
        VeryLow = 1,
        Low = 2,
        Medium = 3,
        Normal = 4,
        High = 5,
        Unknown = -1
    }

    public class ExtendedThreadInfo
    {
        public int ThreadId { get; set; }
        public IoPriorityHint IoPriority { get; set; }
        public MemoryPriorityHint MemoryPriority { get; set; }
    }
}