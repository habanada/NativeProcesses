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
using NativeProcesses.Core.Inspection;
using Microsoft.Diagnostics.Tracing;
using NativeProcesses.Core.Inspection;
using static NativeProcesses.Core.Native.ManagedProcess;
using System.Runtime.InteropServices;

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
        public event Action<ThreatIntelInfo> ThreatDetected;
        public event Action<NativeHeapAllocationInfo> HeapEventDetected;
        private readonly ConcurrentDictionary<int, DateTime> _lastAlertTime = new ConcurrentDictionary<int, DateTime>();
        private readonly TimeSpan _alertCooldown = TimeSpan.FromSeconds(5); // Nur alle 5 Sekunden alarmieren

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        private void OnPerfInfoSample(SampledProfileTraceData data)
        {
            // 1. FAST FAIL: Wenn wir den Prozess nicht überwachen, sofort raus.
            // Das ist nur ein Dictionary-Lookup (Nanosekunden-Bereich).
            if (!_monitoredHandles.TryGetValue(data.ProcessID, out IntPtr hProcess))
            {
                return;
            }
            // --- NEU: DEDUPLIZIERUNG (COOLDOWN) ---
            if (_lastAlertTime.TryGetValue(data.ProcessID, out DateTime lastTime))
            {
                if (DateTime.Now - lastTime < _alertCooldown)
                {
                    return; // Noch im Cooldown, ignorieren
                }
            }
            // Wenn wir hier sind, ist es ein Prozess, der uns interessiert (Watchlist).
            try
            {
                // Wir nutzen das GECATCHTE Handle. Kein OpenProcess!
                MEMORY_BASIC_INFORMATION mbi;
                IntPtr codeAddr = (IntPtr)data.InstructionPointer;

                // 2. VAD Check: Was ist an der Stelle, wo der Code gerade läuft?
                if (VirtualQueryEx(hProcess, codeAddr, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != 0)
                {
                    // DAS IST DER CHECK:
                    // CPU sagt: "Ich führe hier Code aus." (Instruction Pointer)
                    // VAD sagt: "Hier ist nichts (MEM_FREE) oder reserviert (MEM_RESERVE)."
                    // Das ist physikalisch unmöglich, es sei denn, jemand hat den VAD-Eintrag gelöscht (DKOM Rootkit).

                    if (mbi.State == (uint)MemoryState.MEM_FREE ||
                        mbi.State == (uint)MemoryState.MEM_RESERVE)
                    {
                        // DEDUPLIZIERUNG: Wir wollen nicht 1000 Events pro Sekunde feuern.
                        // Prüfen, ob wir für diese PID vor kurzem schon alarmiert haben (optional, aber empfohlen)
                        _lastAlertTime[data.ProcessID] = DateTime.Now;

                        var threatInfo = new ThreatIntelInfo
                        {
                            ProcessId = data.ProcessID,
                            EventName = "DKOM / VAD Unlinking Detected",
                            ProviderName = "NativeProcesses EDR Logic",
                            TimeStamp = DateTime.Now,
                            Detail = $"CPU execution at 0x{codeAddr:X}, but VAD reports Memory State {mbi.State} (Free/Reserve). Hidden Kernel Rootkit activity!"
                        };

                        // Event feuern -> Das löst dann im MainForm den "Deep Scan" aus
                        ThreatDetected?.Invoke(threatInfo);

                        // Optional: Monitoring für diesen Prozess kurz pausieren, um Log-Spam zu vermeiden
                        StopMonitoringPid(data.ProcessID);
                    }
                }
            }
            catch { }
        }

        private readonly ConcurrentDictionary<int, IntPtr> _monitoredHandles = new ConcurrentDictionary<int, IntPtr>();

        // Wird von der UI/Service aufgerufen, wenn ein Prozess in den "Fokus" rückt
        public void StartMonitoringPid(int pid)
        {
            if (_monitoredHandles.ContainsKey(pid)) return;

            try
            {
                // Wir brauchen nur QueryLimitedInformation für VirtualQueryEx
                // Das ist sehr unauffällig und benötigt keine Admin-Rechte für den eigenen User
                var handle = OpenProcess(NativeProcesses.Core.Native.ProcessAccessFlags.QueryLimitedInformation, false, pid);
                if (handle != IntPtr.Zero)
                {
                    _monitoredHandles.TryAdd(pid, handle);
                }
            }
            catch { }
        }

        // Wird aufgerufen, wenn der Prozess den Fokus verliert oder beendet wird
        public void StopMonitoringPid(int pid)
        {
            if (_monitoredHandles.TryRemove(pid, out IntPtr handle))
            {
                CloseHandle(handle);
            }
        }

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
                                       KernelTraceEventParser.Keywords.MemoryHardFaults |
                                       KernelTraceEventParser.Keywords.VirtualAlloc |
                                       KernelTraceEventParser.Keywords.Profile; ;

                        _session.EnableKernelProvider(keywords);
                        _session.EnableProvider("Microsoft-Windows-Threat-Intelligence");
                        _session.Source.Dynamic.All += OnDynamicThreatEvent;

                        _session.Source.Kernel.ProcessStart += OnProcessStart;
                        _session.Source.Kernel.ProcessStop += OnProcessStop;
                        _session.Source.Kernel.DiskIORead += OnDiskIo;
                        _session.Source.Kernel.DiskIOWrite += OnDiskIo;
                        _session.Source.Kernel.TcpIpSend += OnNetworkSend;
                        _session.Source.Kernel.TcpIpRecv += OnNetworkReceive;
                        _session.Source.Kernel.MemoryHardFault += OnMemoryHardFault;
                        _session.Source.Kernel.PerfInfoSample += OnPerfInfoSample;

                        _session.Source.Kernel.VirtualMemAlloc += OnVirtualAlloc;
                        _session.Source.Kernel.VirtualMemFree += OnVirtualFree; // Verweist jetzt auf die korrigierte Methode
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
        private void OnDynamicThreatEvent(TraceEvent data)
        {
            if (ThreatDetected == null)
                return;

            try
            {
                if (data.ProviderName.Equals("Microsoft-Windows-Threat-Intelligence", StringComparison.OrdinalIgnoreCase))
                {
                    string detail = string.Empty;
                    try
                    {
                        if (data.PayloadNames.Length > 0)
                        {
                            detail = $"{data.PayloadNames[0]}: {data.PayloadValue(0)}";
                        }
                    }
                    catch { }

                    var info = new ThreatIntelInfo
                    {
                        ProcessId = data.ProcessID,
                        EventName = data.EventName,
                        ProviderName = data.ProviderName,
                        TimeStamp = data.TimeStamp,
                        Detail = detail
                    };
                    ThreatDetected?.Invoke(info);
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, $"EtwProcessProvider.OnDynamicThreatEvent failed for {data.EventName}", ex);
            }
        }
        private void OnVirtualAlloc(VirtualAllocTraceData data)
        {
            if (HeapEventDetected == null)
                return;

            try
            {
                var info = new NativeHeapAllocationInfo
                {
                    ProcessId = data.ProcessID,
                    ThreadId = data.ThreadID,
                    TimeStamp = data.TimeStamp,
                    EventName = "VirtualAlloc",
                    BaseAddress = (IntPtr)data.BaseAddr,
                    Size = data.Length,
                    Type = "N/A",
                    Protection = data.Flags.ToString()
                };
                HeapEventDetected?.Invoke(info);
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, $"EtwProcessProvider.OnVirtualAlloc failed for PID {data.ProcessID}", ex);
            }
        }
        private void OnVirtualFree(VirtualAllocTraceData data)
        {
            if (HeapEventDetected == null)
                return;

            try
            {
                var info = new NativeHeapAllocationInfo
                {
                    ProcessId = data.ProcessID,
                    ThreadId = data.ThreadID,
                    TimeStamp = data.TimeStamp,
                    EventName = "VirtualFree",
                    BaseAddress = (IntPtr)data.BaseAddr,
                    Size = data.Length,
                    Type = "N/A (Free)",
                    Protection = data.Flags.ToString()
                };
                HeapEventDetected?.Invoke(info);
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, $"EtwProcessProvider.OnVirtualFree failed for PID {data.ProcessID}", ex);
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
                    _session.Source.Dynamic.All -= OnDynamicThreatEvent;
                    _session.Source.Kernel.VirtualMemAlloc -= OnVirtualAlloc;
                    _session.Source.Kernel.VirtualMemFree -= OnVirtualFree;
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
