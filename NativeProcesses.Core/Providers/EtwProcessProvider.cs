/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing;
using NativeProcesses.Core.Engine;
using System.Threading;
using System.Collections.Concurrent;
using NativeProcesses.Core.Native;
using System.Linq;

namespace NativeProcesses.Core.Providers
{
    public class EtwProcessProvider : IProcessEventProvider
    {
        private IProcessNotifier _notifier;
        private IEngineLogger _logger;
        private TraceEventSession _session;
        private Task _listenTask;
        private Timer _flushTimer;
        private int _intervalMs = 1000;
        private readonly ConcurrentDictionary<int, IoUsageData> _usageData = new ConcurrentDictionary<int, IoUsageData>();

        private class IoUsageData
        {
            public long DiskReadBytes;
            public long DiskWriteBytes;
            public long DiskReadOps;
            public long DiskWriteOps;
            public long NetworkSendBytes;
            public long NetworkRecvBytes;
            public long PageFaults;
        }

        public void Start(IProcessNotifier notifier, IEngineLogger logger)
        {
            _notifier = notifier;
            _logger = logger;
            string sessionName = "MyProcessManagerSession_" + Process.GetCurrentProcess().Id;
            _listenTask = Task.Run(() =>
            {
                try
                {
                    try
                    {
                        _logger?.Log(LogLevel.Debug, "EtwProcessProvider: Starting initial process snapshot...");
                        var lister = new NativeProcessLister(_logger);
                        var initialProcesses = lister.GetProcesses();

                        foreach (var nativeInfo in initialProcesses)
                        {
                            try
                            {
                                // 1. Prozess als "gestartet" melden, um ihn zu erstellen
                                _notifier.OnProcessStarted(nativeInfo.Pid, nativeInfo.Name);

                                // 2. Den Prozess unserem Aggregations-Cache hinzufügen
                                _usageData.TryAdd(nativeInfo.Pid, new IoUsageData());

                                var threadList = nativeInfo.Threads
                                    .Select(rawThread => new ThreadInfo(rawThread))
                                    .ToList();

                                // 4. Die initialen Statistik-Daten senden
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
                            }
                            catch (Exception ex)
                            {
                                _logger?.Log(LogLevel.Warning, $"EtwProcessProvider: Failed to add process {nativeInfo.Pid} during initial snapshot.", ex);
                            }
                        }
                        _logger?.Log(LogLevel.Debug, $"EtwProcessProvider: Initial snapshot complete. {initialProcesses.Count} processes loaded.");
                    }
                    catch (Exception ex)
                    {
                        _logger?.Log(LogLevel.Error, "EtwProcessProvider: Initial process snapshot failed.", ex);
                    }
                    // +++ ENDE SNAPSHOT-LOGIK +++


                    // Starte die ETW-Session für ZUKÜNFTIGE Updates
                    using (_session = new TraceEventSession(sessionName))
                    {
                        var keywords = KernelTraceEventParser.Keywords.Process |
                                       KernelTraceEventParser.Keywords.DiskIO |
                                       KernelTraceEventParser.Keywords.NetworkTCPIP |
                                       KernelTraceEventParser.Keywords.MemoryHardFaults;

                        _session.EnableKernelProvider(keywords);

                        _session.Source.Kernel.ProcessStart += OnProcessStart;
                        _session.Source.Kernel.ProcessStop += OnProcessStop;
                        _session.Source.Kernel.DiskIORead += OnDiskIo;
                        _session.Source.Kernel.DiskIOWrite += OnDiskIo;
                        _session.Source.Kernel.TcpIpSend += OnNetworkSend;
                        _session.Source.Kernel.TcpIpRecv += OnNetworkReceive;
                        _session.Source.Kernel.MemoryHardFault += OnMemoryHardFault;

                        _flushTimer = new Timer(AggregateAndFlush, null, _intervalMs, _intervalMs);

                        _session.Source.Process();
                    }
                }
                catch (Exception ex)
                {
                    _logger?.Log(LogLevel.Error, "ETW session failed.", ex);
                }
                finally
                {
                    _flushTimer?.Dispose();
                    _flushTimer = null;
                }
            });
        }
        private void OnProcessStart(ProcessTraceData data)
        {
            try
            {
                _notifier.OnProcessStarted(data.ProcessID, data.ImageFileName);
                _usageData.TryAdd(data.ProcessID, new IoUsageData());
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, $"EtwProcessProvider.OnProcessStart failed for PID {data.ProcessID}", ex);
            }
        }
        private void OnProcessStop(ProcessTraceData data)
        {
            try
            {
                _notifier.OnProcessStopped(data.ProcessID);
                _usageData.TryRemove(data.ProcessID, out _);
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, $"EtwProcessProvider.OnProcessStop failed for PID {data.ProcessID}", ex);
            }
        }
        private void OnDiskIo(DiskIOTraceData data)
        {
            try
            {
                var counters = _usageData.GetOrAdd(data.ProcessID, (pid) => new IoUsageData());
                bool isRead = data.Opcode == (TraceEventOpcode)10;

                if (isRead)
                {
                    Interlocked.Add(ref counters.DiskReadBytes, data.TransferSize);
                    Interlocked.Add(ref counters.DiskReadOps, 1);
                }
                else
                {
                    Interlocked.Add(ref counters.DiskWriteBytes, data.TransferSize);
                    Interlocked.Add(ref counters.DiskWriteOps, 1);
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, $"EtwProcessProvider.OnDiskIo failed for PID {data.ProcessID}", ex);
            }
        }
        private void OnNetworkSend(TcpIpSendTraceData data)
        {
            try
            {
                var counters = _usageData.GetOrAdd(data.ProcessID, (pid) => new IoUsageData());
                Interlocked.Add(ref counters.NetworkSendBytes, data.size);
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, $"EtwProcessProvider.OnNetworkSend failed for PID {data.ProcessID}", ex);
            }
        }

        private void OnNetworkReceive(TcpIpTraceData data)
        {
            try
            {
                var counters = _usageData.GetOrAdd(data.ProcessID, (pid) => new IoUsageData());
                Interlocked.Add(ref counters.NetworkRecvBytes, data.size);
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, $"EtwProcessProvider.OnNetworkReceive failed for PID {data.ProcessID}", ex);
            }
        }
        private void OnMemoryHardFault(MemoryHardFaultTraceData data)
        {
            try
            {
                var counters = _usageData.GetOrAdd(data.ProcessID, (pid) => new IoUsageData());
                Interlocked.Increment(ref counters.PageFaults);
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, $"EtwProcessProvider.OnMemoryHardFault failed for PID {data.ProcessID}", ex);
            }
        }
        private void AggregateAndFlush(object state)
        {
            if (_notifier == null)
                return;

            try
            {
                foreach (var pid in _usageData.Keys)
                {
                    if (_usageData.TryGetValue(pid, out var counters))
                    {
                        long read = Interlocked.Exchange(ref counters.DiskReadBytes, 0);
                        long write = Interlocked.Exchange(ref counters.DiskWriteBytes, 0);
                        long readOps = Interlocked.Exchange(ref counters.DiskReadOps, 0);
                        long writeOps = Interlocked.Exchange(ref counters.DiskWriteOps, 0);
                        long netSend = Interlocked.Exchange(ref counters.NetworkSendBytes, 0);
                        long netRecv = Interlocked.Exchange(ref counters.NetworkRecvBytes, 0);
                        long pageFaults = Interlocked.Exchange(ref counters.PageFaults, 0);

                        if (read > 0 || write > 0 || readOps > 0 || writeOps > 0 || pageFaults > 0)
                        {
                            _notifier.OnProcessIoUpdate(pid, read, write, readOps, writeOps, (uint)pageFaults);
                        }

                        if (netSend > 0 || netRecv > 0)
                        {
                            _notifier.OnProcessNetworkUpdate(pid, netSend, netRecv);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, "EtwProcessProvider.AggregateAndFlush timer callback failed.", ex);
            }
        }
        public void Stop()
        {
            try
            {
                _flushTimer?.Change(Timeout.Infinite, Timeout.Infinite);
                _flushTimer?.Dispose();
                _flushTimer = null;
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, "Failed to stop ETW flush timer.", ex);
            }

            _session?.Stop(true);

            if (_session?.Source?.Kernel != null)
            {
                try
                {
                    _session.Source.Kernel.ProcessStart -= OnProcessStart;
                    _session.Source.Kernel.ProcessStop -= OnProcessStop;
                    _session.Source.Kernel.DiskIORead -= OnDiskIo;
                    _session.Source.Kernel.DiskIOWrite -= OnDiskIo;
                    _session.Source.Kernel.TcpIpSend -= OnNetworkSend;
                    _session.Source.Kernel.TcpIpRecv -= OnNetworkReceive;
                    _session.Source.Kernel.MemoryHardFault -= OnMemoryHardFault;
                }
                catch (Exception ex)
                {
                    _logger?.Log(LogLevel.Debug, "Failed to unregister ETW kernel handlers.", ex);
                }
            }
        }
        public void Dispose()
        {
            Stop();
            _session?.Dispose();
        }
    }
}
