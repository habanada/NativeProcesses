/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
namespace NativeProcesses.Core.Engine
{
    public enum ProcessMetric
    {
        CpuUsage,
        WorkingSet,
        PrivatePageCount,
        PagefileUsage,
        TotalReadBytes,
        TotalWriteBytes,
        TotalNetworkSend,
        TotalNetworkRecv
    }
}