/*
 ██████   █████            █████     ███                       ███████████                                                                       
░░██████ ░░███            ░░███     ░░░                       ░░███░░░░░███                                                                      
 ░███░███ ░███   ██████   ███████   ████  █████ █████  ██████  ░███    ░███ ████████   ██████   ██████   ██████   █████   █████   ██████   █████ 
 ░███░░███░███  ░░░░░███ ░░░███░   ░░███ ░░███ ░░███  ███░░███ ░██████████ ░░███░░███ ███░░███ ███░░███ ███░░███ ███░░   ███░░   ███░░███ ███░░  
 ░███ ░░██████   ███████   ░███     ░███  ░███  ░███ ░███████  ░███░░░░░░   ░███ ░░░ ░███ ░███░███ ░░░ ░███████ ░░█████ ░░█████ ░███████ ░░█████ 
 ░███  ░░█████  ███░░███   ░███ ███ ░███  ░░███ ███  ░███░░░   ░███         ░███     ░███ ░███░███  ███░███░░░   ░░░░███ ░░░░███░███░░░   ░░░░███
 █████  ░░█████░░████████  ░░█████  █████  ░░█████   ░░██████  █████        █████    ░░██████ ░░██████ ░░██████  ██████  ██████ ░░██████  ██████ 
░░░░░    ░░░░░  ░░░░░░░░    ░░░░░  ░░░░░    ░░░░░     ░░░░░░  ░░░░░        ░░░░░      ░░░░░░   ░░░░░░   ░░░░░░  ░░░░░░  ░░░░░░   ░░░░░░  ░░░░░░  
                                                                                                                            
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
 */
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Threading;
using NativeProcesses.Core.Providers;
using NativeProcesses.Core.Native;

namespace NativeProcesses.Core.Engine
{
    public class ProcessService : IProcessNotifier, IDisposable
    {
        private readonly IProcessEventProvider _provider;
        private readonly ConcurrentDictionary<int, FullProcessInfo> _processCache;
        private readonly IEngineLogger _logger;
        private readonly BlockingCollection<FullProcessInfo> _detailLoadQueue = new BlockingCollection<FullProcessInfo>();
        private readonly List<Thread> _detailLoadWorkers = new List<Thread>();
        public event Action<FullProcessInfo> ProcessAdded;
        public event Action<int> ProcessRemoved;
        public event Action<FullProcessInfo> ProcessUpdated;

        public bool UseCpuSmoothing { get; set; } = true;
        public double CpuSmoothingFactor { get; set; } = 0.3;
        public ProcessDetailOptions DetailOptions { get; set; }
        public ProcessService(IProcessEventProvider provider, IEngineLogger logger = null, ProcessDetailOptions options = null)
        {
            _provider = provider;
            _logger = logger;
            _processCache = new ConcurrentDictionary<int, FullProcessInfo>();
            this.DetailOptions = options ?? new ProcessDetailOptions();
        }
        public ProcessService(IProcessEventProvider provider, IEngineLogger logger = null)
        {
            _provider = provider;
            _logger = logger;
            _processCache = new ConcurrentDictionary<int, FullProcessInfo>();
            this.DetailOptions = new ProcessDetailOptions();
        }

        public void Start()
        {
            _logger?.Log(LogLevel.Info, "ProcessService starting...");

            int workerCount = Math.Max(1, Environment.ProcessorCount / 2);
            for (int i = 0; i < workerCount; i++)
            {
                var worker = new Thread(DetailLoadConsumerLoop)
                {
                    IsBackground = true,
                    Name = $"DetailLoader-{i}"
                };
                worker.Start();
                _detailLoadWorkers.Add(worker);
            }

            _provider.Start(this, _logger);
        }

        public void Stop()
        {
            _logger?.Log(LogLevel.Info, "ProcessService stopping...");
            _detailLoadQueue.CompleteAdding();
            _provider.Stop();
        }

        public List<FullProcessInfo> GetCurrentProcesses()
        {
            return _processCache.Values.Select(info => info.CreateSnapshot()).ToList();
        }

        void IProcessNotifier.OnProcessStarted(int pid, string name)
        {
            var newInfo = new FullProcessInfo(pid, name, 0, 0, 0);
            if (_processCache.TryAdd(pid, newInfo))
            {
                ProcessAdded?.Invoke(newInfo.CreateSnapshot());

                if (!_detailLoadQueue.IsAddingCompleted)
                {
                    _detailLoadQueue.Add(newInfo);
                }
            }
            else
            {
                if (_processCache.TryGetValue(pid, out FullProcessInfo existing))
                {
                    existing.Name = name;
                    ProcessUpdated?.Invoke(existing.CreateSnapshot());
                }
            }
        }

        void IProcessNotifier.OnProcessStopped(int pid)
        {
            if (_processCache.TryRemove(pid, out FullProcessInfo removedInfo))
            {
                ProcessRemoved?.Invoke(pid);
            }
        }

        void IProcessNotifier.OnProcessStatisticsUpdate(int pid, long workingSet, long pagedPool, long nonPagedPool, long privatePageCount, long pagefileUsage, uint threads, int priority, List<ThreadInfo> threadInfos)
        {
            if (_processCache.TryGetValue(pid, out FullProcessInfo info))
            {
                info.UpdateFastData(info.Name, workingSet, pagedPool, nonPagedPool, privatePageCount, pagefileUsage, threads, priority, threadInfos);
                ProcessUpdated?.Invoke(info.CreateSnapshot());
            }
        }

        void IProcessNotifier.OnProcessIoUpdate(int pid, long readBytesDelta, long writeBytesDelta, long readOpsDelta, long writeOpsDelta, uint pageFaultDelta)
        {
            if (_processCache.TryGetValue(pid, out FullProcessInfo info))
            {
                info.TotalReadBytes += readBytesDelta;
                info.TotalWriteBytes += writeBytesDelta;
                info.TotalReadOps += readOpsDelta;
                info.TotalWriteOps += writeOpsDelta;
                info.TotalPageFaults += pageFaultDelta;
                ProcessUpdated?.Invoke(info.CreateSnapshot());
            }
        }

        void IProcessNotifier.OnProcessCpuUpdate(int pid, double cpuPercent)
        {
            if (_processCache.TryGetValue(pid, out FullProcessInfo info))
            {
                if (this.UseCpuSmoothing)
                {
                    double alpha = this.CpuSmoothingFactor;
                    if (info.CpuUsagePercent == 0)
                    {
                        info.CpuUsagePercent = cpuPercent;
                    }
                    else
                    {
                        info.CpuUsagePercent = info.CpuUsagePercent * (1 - alpha) + cpuPercent * alpha;
                    }
                }
                else
                {
                    info.CpuUsagePercent = cpuPercent;
                }
                ProcessUpdated?.Invoke(info.CreateSnapshot());
            }
        }
        private void DetailLoadConsumerLoop()
        {
            try
            {
                foreach (var info in _detailLoadQueue.GetConsumingEnumerable())
                {
                    try
                    {
                        if (info != null)
                        {
                            LoadSlowDetails(info);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger?.Log(LogLevel.Debug, $"Detail loader worker failed for PID {info?.Pid}", ex);
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }
        }
        private void LoadSlowDetails(FullProcessInfo info)
        {
            if (info.IsLoadingDetails || info.IsDetailsLoaded)
            {
                return;
            }
            info.IsLoadingDetails = true;
            try
            {
                var access = ProcessAccessFlags.QueryInformation |
                             ProcessAccessFlags.VmRead |
                             ProcessAccessFlags.QueryLimitedInformation;
                using (var proc = new ManagedProcess(info.Pid, access))
                {
                    if (this.DetailOptions.LoadExePathAndCommandLine)
                    {
                        try { info.ExePath = proc.GetExePath(); }
                        catch (Win32Exception ex)
                        {
                            info.ExePath = "Access Denied";
                        }
                        catch (Exception ex)
                        {
                            info.ExePath = "Access Denied";
                            _logger?.Log(LogLevel.Debug, $"Failed to get ExePath for PID {info.Pid}.", ex);
                        }
                        try { info.CommandLine = proc.GetCommandLine(); }
                        catch (Win32Exception ex)
                        {
                            info.CommandLine = "Access Denied";
                        }
                        catch (Exception ex)
                        {
                            info.CommandLine = "Access Denied";
                            _logger?.Log(LogLevel.Debug, $"Failed to get CommandLine for PID {info.Pid}.", ex);
                        }
                    }

                    if (this.DetailOptions.LoadIoCounters)
                    {
                        try { info.IoCounters = proc.GetIoCounters(); }
                        catch (Win32Exception ex)
                        { } //denoise
                        catch (Exception ex)
                        {
                            _logger?.Log(LogLevel.Debug, $"Failed to get IoCounters for PID {info.Pid}.", ex);
                        }
                    }

                    if (this.DetailOptions.LoadSecurityInfo)
                    {
                        try { info.SecurityInfo = proc.GetSecurityInfo(); }
                        catch (Win32Exception ex)
                        { } //denoise
                        catch (Exception ex)
                        {
                            _logger?.Log(LogLevel.Debug, $"Failed to get SecurityInfo for PID {info.Pid}.", ex);
                        }
                    }

                    if (this.DetailOptions.LoadMitigationInfo)
                    {
                        try { info.MitigationInfo = proc.GetMitigationInfo(); }
                        catch (Win32Exception ex)
                        { } //denoise
                        catch (Exception ex)
                        {
                            _logger?.Log(LogLevel.Debug, $"Failed to get MitigationInfo for PID {info.Pid}.", ex);
                        }
                    }
                    if (this.DetailOptions.LoadExtendedStatusFlags)
                    {
                        try
                        {
                            proc.GetExtendedStatusFlags(out bool isDebuggerAttached, out bool isInJob, out bool isEcoMode);
                            info.IsDebuggerAttached = isDebuggerAttached;
                            info.IsInJob = isInJob;
                            info.IsEcoMode = isEcoMode;
                        }
                        catch (Win32Exception)
                        { } //denoise
                        catch (Exception ex)
                        {
                            _logger?.Log(LogLevel.Debug, $"Failed to get ExtendedStatusFlags for PID {info.Pid}.", ex);
                        }
                    }
                    if (this.DetailOptions.LoadDpiAndUIContext)
                    {
                        try
                        {
                            proc.GetDpiAndUIContextInfo(out string dpi, out bool immersive);
                            info.DpiAwareness = dpi;
                            info.IsImmersive = immersive;
                        }
                        catch (Win32Exception)
                        { } //denoise
                        catch (Exception ex)
                        {
                            _logger?.Log(LogLevel.Debug, $"Failed to get DpiAndUIContext for PID {info.Pid}.", ex);
                        }
                    }
                    if (this.DetailOptions.LoadPackageInfo)
                    {
                        try
                        {
                            info.PackageFullName = proc.GetPackageFullName();
                        }
                        catch (Win32Exception ex)
                        {
                            if (ex.NativeErrorCode == ManagedProcess.APPMODEL_ERROR_NO_PACKAGE)
                            {
                                info.PackageFullName = "N/A";
                            }
                            else
                            {
                                info.PackageFullName = "Error";
                            }
                        }
                        catch (Exception ex)
                        {
                            info.PackageFullName = "Error";
                            _logger?.Log(LogLevel.Debug, $"Failed to get PackageFullName for PID {info.Pid}.", ex);
                        }
                        if (info.PackageFullName == null)
                        {
                            info.PackageFullName = "N/A";
                        }
                    }
                }
            }
            catch (Win32Exception ex)
            {
                info.ExePath = ex.Message;
                info.CommandLine = ex.Message;
                info.SecurityInfo.UserName = ex.Message;
                //denoise
                //    _logger?.Log(LogLevel.Debug, $"Failed to open PID {info.Pid} for details.", ex);
            }

            if (info.ExePath.StartsWith("Access Denied") || info.ExePath.StartsWith("["))
            {
                info.FileCompany = "N/A";
                info.FileDescription = "N/A";
                info.FileVersion = "N/A";
                info.SignatureInfo.ErrorMessage = info.ExePath;
            }
            else
            {
                if (this.DetailOptions.LoadSignatureInfo)
                {
                    try
                    {
                        info.SignatureInfo = SignatureVerifier.Verify(info.ExePath);
                    }
                    catch (Exception ex)
                    {
                        info.SignatureInfo.ErrorMessage = ex.Message;
                        _logger?.Log(LogLevel.Debug, $"Failed to verify signature for {info.ExePath}.", ex);
                    }
                }

                if (this.DetailOptions.LoadFileVersionInfo)
                {
                    try
                    {
                        var versionInfo = FileVersionInfo.GetVersionInfo(info.ExePath);
                        info.FileCompany = string.IsNullOrEmpty(versionInfo.CompanyName) ? "N/A" : versionInfo.CompanyName;
                        info.FileDescription = string.IsNullOrEmpty(versionInfo.FileDescription) ? "N/A" : versionInfo.FileDescription;
                        info.FileVersion = string.IsNullOrEmpty(versionInfo.FileVersion) ?
                            "N/A" : versionInfo.FileVersion;
                    }
                    catch (Exception ex)
                    {
                        info.FileCompany = "N/A";
                        info.FileDescription = ex.Message;
                        info.FileVersion = "N/A";
                        //denoise
                        //    _logger?.Log(LogLevel.Debug, $"Failed to get FileVersionInfo for {info.ExePath}.", ex);
                    }
                }
            }

            info.IsLoadingDetails = false;
            info.IsDetailsLoaded = true;
            ProcessUpdated?.Invoke(info.CreateSnapshot());
        }

        public void Dispose()
        {
            Stop();
            _provider?.Dispose();
        }
    }
}