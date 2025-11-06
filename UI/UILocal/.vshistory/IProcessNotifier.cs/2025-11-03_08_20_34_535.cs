using System;
namespace NativeProcesses
{
    public interface IProcessNotifier
    {
        void OnProcessStarted(int pid, string name);
        void OnProcessStopped(int pid);
        void OnProcessStatisticsUpdate(int pid, long workingSet, uint threads, int priority);
        void OnProcessIoUpdate(int pid, long readBytes, long writeBytes);
        void OnProcessCpuUpdate(int pid, double cpuPercent);
    }
}
