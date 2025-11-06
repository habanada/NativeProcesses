using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
namespace NativeProcesses
{
    public class PollingProcessProvider : IProcessEventProvider
    {
        private IProcessNotifier _notifier;
        private IEngineLogger _logger;
        private readonly NativeProcessLister _lister = new NativeProcessLister();
        private Task _loop;
        private CancellationTokenSource _cts;
        private readonly TimeSpan _interval;
        private readonly ConcurrentDictionary<int, long> _cpuCache = new ConcurrentDictionary<int, long>();
        private long _lastTimeTicks;
        private readonly int _processorCount = Environment.ProcessorCount;
        public PollingProcessProvider(TimeSpan interval)
        {
            _interval = interval;
        }
        public void Start(IProcessNotifier notifier, IEngineLogger logger)
        {
            _notifier = notifier;
            _logger = logger;
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
                    }
                    foreach (var nativeInfo in nativeList)
                    {
                        if (!knownPids.Contains(nativeInfo.Pid))
                        {
                            _notifier.OnProcessStarted(nativeInfo.Pid, nativeInfo.Name);
                            knownPids.Add(nativeInfo.Pid);
                        }
                        _notifier.OnProcessStatisticsUpdate(
                            nativeInfo.Pid,
                            nativeInfo.WorkingSetSize,
                            nativeInfo.NumberOfThreads,
                            nativeInfo.BasePriority
                        );
                        CalculateCpuUsage(nativeInfo, elapsedTicks);
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
            long newTotalTicks = info.KernelTime + info.UserTime;
            if (elapsedTicks == 0)
            {
                _cpuCache[info.Pid] = newTotalTicks;
                return;
            }
            _cpuCache.TryGetValue(info.Pid, out long lastTotalTicks);
            long ticksDelta = newTotalTicks - lastTotalTicks;
            if (ticksDelta < 0) ticksDelta = 0;
            double cpuPercent = (ticksDelta / (double)elapsedTicks) * 100.0 / _processorCount;
            _notifier.OnProcessCpuUpdate(info.Pid, cpuPercent);
            _cpuCache[info.Pid] = newTotalTicks;
        }
        public void Stop() { _cts?.Cancel(); }
        public void Dispose() { Stop(); }
    }
}
