/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Collections.Generic;

namespace NativeProcesses.Core.Engine
{
    public class ProcessMonitorEngine : IDisposable
    {
        private readonly ProcessService _service;
        private readonly IEngineLogger _logger;

        private readonly Dictionary<int, HashSet<ProcessMetric>> _watchlist;
        private readonly Dictionary<int, ProcessStateCache> _lastStateCache;
        private readonly object _watchlistLock = new object();
        private readonly object _cacheLock = new object();

        public event EventHandler<ProcessMetricChangeEventArgs> MetricChanged;

        private class ProcessStateCache
        {
            public double LastCpuUsage;
            public long LastWorkingSet;
            public long LastPrivatePageCount;
            public long LastPagefileUsage;
            public long LastTotalReadBytes;
            public long LastTotalWriteBytes;
            public long LastTotalNetworkSend;
            public long LastTotalNetworkRecv;
        }

        public ProcessMonitorEngine(ProcessService service, IEngineLogger logger)
        {
            _service = service ?? throw new ArgumentNullException(nameof(service));
            _logger = logger;
            _watchlist = new Dictionary<int, HashSet<ProcessMetric>>();
            _lastStateCache = new Dictionary<int, ProcessStateCache>();
        }

        public void Start()
        {
            try
            {
                _service.ProcessUpdated += OnProcessUpdated;
                _service.ProcessRemoved += OnProcessRemoved;
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, "ProcessMonitorEngine failed to start (hook events).", ex);
            }
        }

        public void Stop()
        {
            try
            {
                _service.ProcessUpdated -= OnProcessUpdated;
                _service.ProcessRemoved -= OnProcessRemoved;
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, "ProcessMonitorEngine failed to stop (unhook events).", ex);
            }
        }

        public void Subscribe(int pid, ProcessMetric metric)
        {
            try
            {
                lock (_watchlistLock)
                {
                    if (!_watchlist.TryGetValue(pid, out var metrics))
                    {
                        metrics = new HashSet<ProcessMetric>();
                        _watchlist[pid] = metrics;
                    }
                    metrics.Add(metric);
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, $"ProcessMonitorEngine.Subscribe failed for PID {pid}.", ex);
            }
        }

        public void Unsubscribe(int pid, ProcessMetric metric)
        {
            try
            {
                lock (_watchlistLock)
                {
                    if (_watchlist.TryGetValue(pid, out var metrics))
                    {
                        metrics.Remove(metric);
                        if (metrics.Count == 0)
                        {
                            _watchlist.Remove(pid);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, $"ProcessMonitorEngine.Unsubscribe failed for PID {pid}.", ex);
            }
        }

        private void OnProcessRemoved(int pid)
        {
            try
            {
                lock (_watchlistLock)
                {
                    _watchlist.Remove(pid);
                }
                lock (_cacheLock)
                {
                    _lastStateCache.Remove(pid);
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, $"ProcessMonitorEngine.OnProcessRemoved failed for PID {pid}.", ex);
            }
        }

        private void OnProcessUpdated(FullProcessInfo info)
        {
            if (MetricChanged == null)
                return;

            HashSet<ProcessMetric> metricsToWatch;
            lock (_watchlistLock)
            {
                if (!_watchlist.TryGetValue(info.Pid, out metricsToWatch) || metricsToWatch.Count == 0)
                {
                    return;
                }
            }

            ProcessStateCache cache;
            lock (_cacheLock)
            {
                if (!_lastStateCache.TryGetValue(info.Pid, out cache))
                {
                    cache = new ProcessStateCache();
                    _lastStateCache[info.Pid] = cache;
                }
            }

            try
            {
                foreach (var metric in metricsToWatch)
                {
                    switch (metric)
                    {
                        case ProcessMetric.CpuUsage:
                            CheckAndNotify(info.Pid, metric, cache.LastCpuUsage, info.CpuUsagePercent, (val) => cache.LastCpuUsage = (double)val);
                            break;
                        case ProcessMetric.WorkingSet:
                            CheckAndNotify(info.Pid, metric, cache.LastWorkingSet, info.WorkingSetSize, (val) => cache.LastWorkingSet = (long)val);
                            break;
                        case ProcessMetric.PrivatePageCount:
                            CheckAndNotify(info.Pid, metric, cache.LastPrivatePageCount, info.PrivatePageCount, (val) => cache.LastPrivatePageCount = (long)val);
                            break;
                        case ProcessMetric.PagefileUsage:
                            CheckAndNotify(info.Pid, metric, cache.LastPagefileUsage, info.PagefileUsage, (val) => cache.LastPagefileUsage = (long)val);
                            break;
                        case ProcessMetric.TotalReadBytes:
                            CheckAndNotify(info.Pid, metric, cache.LastTotalReadBytes, info.TotalReadBytes, (val) => cache.LastTotalReadBytes = (long)val);
                            break;
                        case ProcessMetric.TotalWriteBytes:
                            CheckAndNotify(info.Pid, metric, cache.LastTotalWriteBytes, info.TotalWriteBytes, (val) => cache.LastTotalWriteBytes = (long)val);
                            break;
                        case ProcessMetric.TotalNetworkSend:
                            CheckAndNotify(info.Pid, metric, cache.LastTotalNetworkSend, info.TotalNetworkSend, (val) => cache.LastTotalNetworkSend = (long)val);
                            break;
                        case ProcessMetric.TotalNetworkRecv:
                            CheckAndNotify(info.Pid, metric, cache.LastTotalNetworkRecv, info.TotalNetworkRecv, (val) => cache.LastTotalNetworkRecv = (long)val);
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, $"ProcessMonitorEngine.OnProcessUpdated failed during metric check for PID {info.Pid}.", ex);
            }
        }

        private void CheckAndNotify<T>(int pid, ProcessMetric metric, T oldValue, T newValue, Action<T> updateCache) where T : IComparable
        {
            if (newValue.CompareTo(oldValue) != 0)
            {
                try
                {
                    MetricChanged?.Invoke(this, new ProcessMetricChangeEventArgs(pid, metric, oldValue, newValue));
                }
                catch (Exception ex)
                {
                    _logger?.Log(LogLevel.Warning, $"ProcessMonitorEngine.MetricChanged event handler failed for {metric} on PID {pid}.", ex);
                }
                updateCache(newValue);
            }
        }

        public void Dispose()
        {
            Stop();
        }
    }
}