//using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
//using NativeProcesses.Core.Engine;
//using System;
//using System.Collections.Concurrent;
//using System.Threading;

//namespace NativeProcesses.Tracing
//{
//    public class EtwAggregator : IDisposable
//    {
//        private readonly EtwKernelSession _session;
//        private readonly IEngineLogger _logger;
//        private readonly ConcurrentDictionary<int, IoUsageData> _usageData;
//        private Timer _flushTimer;
//        private readonly int _intervalMs;
//        private readonly double _intervalSec;

//        public event Action<ProcessTraceData> ProcessStarted;
//        public event Action<ProcessTraceData> ProcessStopped;
//        public event Action<AggregatedIoUsage> IoUsageUpdated;

//        private class IoUsageData
//        {
//            public long DiskReadBytes;
//            public long DiskWriteBytes;
//            public long DiskReadOps;
//            public long DiskWriteOps;
//            public long NetworkSendBytes;
//            public long NetworkRecvBytes;
//        }

//        public EtwAggregator(EtwKernelSession session, IEngineLogger logger, int intervalMs = 1000)
//        {
//            if (intervalMs <= 0)
//                throw new ArgumentOutOfRangeException(nameof(intervalMs), "Interval must be greater than zero.");

//            _session = session;
//            _logger = logger;
//            _intervalMs = intervalMs;
//            _intervalSec = intervalMs / 1000.0;
//            _usageData = new ConcurrentDictionary<int, IoUsageData>();
//        }

//        public void Start()
//        {
//            try
//            {
//                if (_flushTimer != null)
//                    return;

//                _session.ProcessStarted += OnProcessStarted;
//                _session.ProcessStopped += OnProcessStopped;
//                _session.DiskRead += OnDiskRead;
//                _session.DiskWrite += OnDiskWrite;
//                _session.NetworkSend += OnNetworkSend;
//                _session.NetworkReceive += OnNetworkReceive;

//                _flushTimer = new Timer(AggregateAndFlush, null, _intervalMs, _intervalMs);
//                _session.Start();
//            }
//            catch (Exception ex)
//            {
//                _logger?.Log(LogLevel.Error, "EtwAggregator failed to start.", ex);
//            }
//        }

//        public void Stop()
//        {
//            try
//            {
//                if (_flushTimer == null)
//                    return;

//                _flushTimer.Dispose();
//                _flushTimer = null;

//                _session.Stop();

//                _session.ProcessStarted -= OnProcessStarted;
//                _session.ProcessStopped -= OnProcessStopped;
//                _session.DiskRead -= OnDiskRead;
//                _session.DiskWrite -= OnDiskWrite;
//                _session.NetworkSend -= OnNetworkSend;
//                _session.NetworkReceive -= OnNetworkReceive;
//            }
//            catch (Exception ex)
//            {
//                _logger?.Log(LogLevel.Error, "EtwAggregator failed to stop cleanly.", ex);
//            }
//        }

//        private void OnProcessStarted(ProcessTraceData data)
//        {
//            try
//            {
//                _usageData.TryAdd(data.ProcessID, new IoUsageData());
//                ProcessStarted?.Invoke(data);
//            }
//            catch (Exception ex)
//            {
//                _logger?.Log(LogLevel.Warning, "EtwAggregator.OnProcessStarted failed.", ex);
//            }
//        }

//        private void OnProcessStopped(ProcessTraceData data)
//        {
//            try
//            {
//                _usageData.TryRemove(data.ProcessID, out _);
//                ProcessStopped?.Invoke(data);
//            }
//            catch (Exception ex)
//            {
//                _logger?.Log(LogLevel.Warning, "EtwAggregator.OnProcessStopped failed.", ex);
//            }
//        }

//        private void OnDiskRead(DiskIOTraceData data)
//        {
//            var counters = _usageData.GetOrAdd(data.ProcessID, (pid) => new IoUsageData());
//            Interlocked.Add(ref counters.DiskReadBytes, data.TransferSize);
//            Interlocked.Add(ref counters.DiskReadOps, 1);
//        }

//        private void OnDiskWrite(DiskIOTraceData data)
//        {
//            var counters = _usageData.GetOrAdd(data.ProcessID, (pid) => new IoUsageData());
//            Interlocked.Add(ref counters.DiskWriteBytes, data.TransferSize);
//            Interlocked.Add(ref counters.DiskWriteOps, 1);
//        }

//        private void OnNetworkSend(TcpIpSendTraceData data)
//        {
//            var counters = _usageData.GetOrAdd(data.ProcessID, (pid) => new IoUsageData());
//            Interlocked.Add(ref counters.NetworkSendBytes, data.size);
//        }

//        private void OnNetworkReceive(TcpIpTraceData data)
//        {
//            var counters = _usageData.GetOrAdd(data.ProcessID, (pid) => new IoUsageData());
//            Interlocked.Add(ref counters.NetworkRecvBytes, data.size);
//        }

//        private void AggregateAndFlush(object state)
//        {
//            try
//            {
//                foreach (var pid in _usageData.Keys)
//                {
//                    if (_usageData.TryGetValue(pid, out var counters))
//                    {
//                        long read = Interlocked.Exchange(ref counters.DiskReadBytes, 0);
//                        long write = Interlocked.Exchange(ref counters.DiskWriteBytes, 0);
//                        long readOps = Interlocked.Exchange(ref counters.DiskReadOps, 0);
//                        long writeOps = Interlocked.Exchange(ref counters.DiskWriteOps, 0);
//                        long netSend = Interlocked.Exchange(ref counters.NetworkSendBytes, 0);
//                        long netRecv = Interlocked.Exchange(ref counters.NetworkRecvBytes, 0);

//                        if (read > 0 || write > 0 || readOps > 0 || writeOps > 0 || netSend > 0 || netRecv > 0)
//                        {
//                            var update = new AggregatedIoUsage
//                            {
//                                Pid = pid,
//                                DiskReadPerSec = (long)(read / _intervalSec),
//                                DiskWritePerSec = (long)(write / _intervalSec),
//                                DiskReadOpsPerSec = (long)(readOps / _intervalSec),
//                                DiskWriteOpsPerSec = (long)(writeOps / _intervalSec),
//                                NetworkSendPerSec = (long)(netSend / _intervalSec),
//                                NetworkRecvPerSec = (long)(netRecv / _intervalSec)
//                            };
//                            IoUsageUpdated?.Invoke(update);
//                        }
//                    }
//                }
//            }
//            catch (Exception ex)
//            {
//                _logger?.Log(LogLevel.Error, "EtwAggregator.AggregateAndFlush timer callback failed.", ex);
//            }
//        }

//        public void Dispose()
//        {
//            Stop();
//            _flushTimer?.Dispose();
//            _session?.Dispose();
//        }
//    }
//}