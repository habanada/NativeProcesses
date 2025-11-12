/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using NativeProcesses.Core.Engine;
using NativeProcesses.Core.Native;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace NativeProcesses.Core.Providers
{
    public class PollingProcessProvider : IProcessEventProvider
    {
        private IProcessNotifier _notifier;
        private IEngineLogger _logger;
        private NativeProcessLister _lister;
        private Task _loop;
        private CancellationTokenSource _cts;
        private TimeSpan _interval;
        private readonly ConcurrentDictionary<int, long> _cpuCache = new ConcurrentDictionary<int, long>();

        private readonly ConcurrentDictionary<int, long> _ioReadCache = new ConcurrentDictionary<int, long>();
        private readonly ConcurrentDictionary<int, long> _ioWriteCache = new ConcurrentDictionary<int, long>();
        private readonly ConcurrentDictionary<int, long> _ioReadOpsCache = new ConcurrentDictionary<int, long>();
        private readonly ConcurrentDictionary<int, long> _ioWriteOpsCache = new ConcurrentDictionary<int, long>();
        private readonly ConcurrentDictionary<int, long> _pageFaultCache = new ConcurrentDictionary<int, long>();
        private long _lastTimeTicks;

        private readonly int _processorCount = Environment.ProcessorCount;

        public TimeSpan Interval
        {
            get { return _interval; }
            set { _interval = value; }
        }

        public PollingProcessProvider(TimeSpan interval)
        {
            _interval = interval;
        }

        public void Start(IProcessNotifier notifier, IEngineLogger logger)
        {
            _notifier = notifier;
            _logger = logger;
            _lister = new NativeProcessLister(_logger);
            _cts = new CancellationTokenSource();
            _lastTimeTicks = Stopwatch.GetTimestamp();
            _loop = Task.Run(() => FastLoop(_cts.Token));
        }

        private async Task FastLoop(CancellationToken token)
        {
            var knownPids = new HashSet<int>();
            while (!token.IsCancellationRequested)
            {
                try
                {
                    var nativeList = _lister.GetProcesses();
                    var currentPids = new HashSet<int>(nativeList.Select(p => p.Pid));
                    long nowTicks = Stopwatch.GetTimestamp();
                    long elapsedTicks = nowTicks - _lastTimeTicks;
                    _lastTimeTicks = nowTicks;
                    var pidsToRemove = knownPids.Where(pid => !currentPids.Contains(pid)).ToList();
                    foreach (var pid in pidsToRemove)
                    {
                        _notifier.OnProcessStopped(pid);
                        knownPids.Remove(pid);
                        _cpuCache.TryRemove(pid, out _);
                        _ioReadCache.TryRemove(pid, out _);
                        _ioWriteCache.TryRemove(pid, out _);
                        _ioReadOpsCache.TryRemove(pid, out _);
                        _ioWriteOpsCache.TryRemove(pid, out _);
                        _pageFaultCache.TryRemove(pid, out _);
                    }

                    foreach (var nativeInfo in nativeList)
                    {
                        if (!knownPids.Contains(nativeInfo.Pid))
                        {
                            _notifier.OnProcessStarted(nativeInfo.Pid, nativeInfo.Name);
                            knownPids.Add(nativeInfo.Pid);
                        }

                        var threadList = nativeInfo.Threads
                            .Select(rawThread => new ThreadInfo(rawThread))
                            .ToList();

                        _notifier.OnProcessStatisticsUpdate(
                            nativeInfo.Pid,
                            nativeInfo.WorkingSetSize,
                            nativeInfo.PagedPoolUsage,
                            nativeInfo.NonPagedPoolUsage,
                            nativeInfo.PrivatePageCount,
                            nativeInfo.PagefileUsage,
                            nativeInfo.NumberOfThreads,
                            nativeInfo.BasePriority,
                            threadList
                        );

                        CalculateCpuUsage(nativeInfo, elapsedTicks);
                        CalculateIoAndPageFaults(nativeInfo);
                    }
                }
                catch (Exception ex)
                {
                    _logger?.Log(LogLevel.Error, "Polling loop failed.", ex);
                    await Task.Delay(5000, token);
                }
                await Task.Delay(_interval, token);
            }
        }
        private void CalculateCpuUsage(NativeProcessInfo info, long elapsedTicks)
        {
            if (elapsedTicks == 0)
            {
                return;
            }

            long newTotalTicks = info.KernelTime + info.UserTime;

            bool hasLastTicks = _cpuCache.TryGetValue(info.Pid, out long lastTotalTicks);

            if (hasLastTicks)
            {
                long ticksDelta = newTotalTicks - lastTotalTicks;
                if (ticksDelta < 0) ticksDelta = 0;
                double cpuPercent = (ticksDelta / (double)elapsedTicks) * 100.0 / _processorCount;
                _notifier.OnProcessCpuUpdate(info.Pid, cpuPercent);
            }

            _cpuCache[info.Pid] = newTotalTicks;
        }
        private void CalculateIoAndPageFaults(NativeProcessInfo info)
        {
            long newReadBytes = info.ReadTransferCount;
            long newWriteBytes = info.WriteTransferCount;
            long newReadOps = info.ReadOperationCount;
            long newWriteOps = info.WriteOperationCount;
            long newPageFaults = info.PageFaultCount;

            bool hasLastIo = _ioReadCache.TryGetValue(info.Pid, out long lastReadBytes);
            _ioWriteCache.TryGetValue(info.Pid, out long lastWriteBytes);
            _ioReadOpsCache.TryGetValue(info.Pid, out long lastReadOps);
            _ioWriteOpsCache.TryGetValue(info.Pid, out long lastWriteOps);
            _pageFaultCache.TryGetValue(info.Pid, out long lastPageFaults);

            if (hasLastIo)
            {
                long readDelta = newReadBytes - lastReadBytes;
                long writeDelta = newWriteBytes - lastWriteBytes;
                long readOpsDelta = newReadOps - lastReadOps;
                long writeOpsDelta = newWriteOps - lastWriteOps;
                long pageFaultDelta = newPageFaults - lastPageFaults;

                if (readDelta < 0) readDelta = 0;
                if (writeDelta < 0) writeDelta = 0;
                if (readOpsDelta < 0) readOpsDelta = 0;
                if (writeOpsDelta < 0) writeOpsDelta = 0;
                if (pageFaultDelta < 0) pageFaultDelta = 0;

                if (readDelta > 0 || writeDelta > 0 || readOpsDelta > 0 || writeOpsDelta > 0 || pageFaultDelta > 0)
                {
                    _notifier.OnProcessIoUpdate(info.Pid, readDelta, writeDelta, readOpsDelta, writeOpsDelta, (uint)pageFaultDelta);
                }
            }

            _ioReadCache[info.Pid] = newReadBytes;
            _ioWriteCache[info.Pid] = newWriteBytes;
            _ioReadOpsCache[info.Pid] = newReadOps;
            _ioWriteOpsCache[info.Pid] = newWriteOps;
            _pageFaultCache[info.Pid] = newPageFaults;
        }
        //private void CalculateIoUsage(NativeProcessInfo info)
        //{
        //    long newReadBytes = info.ReadTransferCount;
        //    long newWriteBytes = info.WriteTransferCount;
        //    long newReadOps = info.ReadOperationCount;
        //    long newWriteOps = info.WriteOperationCount;

        //    bool hasLastIo = _ioReadCache.TryGetValue(info.Pid, out long lastReadBytes);
        //    _ioWriteCache.TryGetValue(info.Pid, out long lastWriteBytes);
        //    _ioReadOpsCache.TryGetValue(info.Pid, out long lastReadOps);
        //    _ioWriteOpsCache.TryGetValue(info.Pid, out long lastWriteOps);

        //    if (hasLastIo)
        //    {
        //        long readDelta = newReadBytes - lastReadBytes;
        //        long writeDelta = newWriteBytes - lastWriteBytes;
        //        long readOpsDelta = newReadOps - lastReadOps;
        //        long writeOpsDelta = newWriteOps - lastWriteOps;

        //        if (readDelta < 0) readDelta = 0;
        //        if (writeDelta < 0) writeDelta = 0;
        //        if (readOpsDelta < 0) readOpsDelta = 0;
        //        if (writeOpsDelta < 0) writeOpsDelta = 0;

        //        if (readDelta > 0 || writeDelta > 0 || readOpsDelta > 0 || writeOpsDelta > 0)
        //        {
        //            _notifier.OnProcessIoUpdate(info.Pid, readDelta, writeDelta, readOpsDelta, writeOpsDelta, 0);
        //        }
        //    }

        //    _ioReadCache[info.Pid] = newReadBytes;
        //    _ioWriteCache[info.Pid] = newWriteBytes;
        //    _ioReadOpsCache[info.Pid] = newReadOps;
        //    _ioWriteOpsCache[info.Pid] = newWriteOps;
        //}
        public void Stop() { _cts?.Cancel(); }
        public void Dispose() { Stop(); }

    }
}