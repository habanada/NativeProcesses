/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Collections.Generic;

namespace NativeProcesses.Core.Engine
{
    public interface IProcessNotifier
    {
        void OnProcessStarted(int pid, string name);
        void OnProcessStopped(int pid);
        void OnProcessStatisticsUpdate(int pid, long workingSet, long pagedPool, long nonPagedPool, long privatePageCount, long pagefileUsage, uint threads, int priority, List<ThreadInfo> threadInfos);
        void OnProcessIoUpdate(int pid, long readBytesDelta, long writeBytesDelta, long readOpsDelta, long writeOpsDelta, uint pageFaultDelta);
        void OnProcessCpuUpdate(int pid, double cpuPercent);
        void OnProcessNetworkUpdate(int pid, long sendBytesDelta, long recvBytesDelta);
    }
}