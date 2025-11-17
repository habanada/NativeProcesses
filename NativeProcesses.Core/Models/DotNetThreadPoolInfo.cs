/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
namespace NativeProcesses.Core.Models
{
    public class DotNetThreadPoolInfo
    {
        public int CpuUtilization { get; set; }
        public int MinWorkerThreads { get; set; }
        public int MaxWorkerThreads { get; set; }
        public int ActiveWorkerThreads { get; set; }
        public int IdleWorkerThreads { get; set; }
        public int MinCompletionPortThreads { get; set; }
        public int MaxCompletionPortThreads { get; set; }
        public int ActiveCompletionPortThreads { get; set; }
        public int IdleCompletionPortThreads { get; set; }
    }
}