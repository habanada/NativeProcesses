using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using System.Diagnostics;

namespace NativeProcesses
{
    public class ProcessService : IProcessNotifier, IDisposable
    {
        private readonly IProcessEventProvider _provider;
        private readonly ConcurrentDictionary<int, FullProcessInfo> _processCache;
        private readonly IEngineLogger _logger;
        private readonly ProcessDetailOptions _detailOptions;

        public event Action<FullProcessInfo> ProcessAdded;
        public event Action<int> ProcessRemoved;
        public event Action<FullProcessInfo> ProcessUpdated;

        public bool UseCpuSmoothing { get; set; } = true;
        public double CpuSmoothingFactor { get; set; } = 0.3;

        public ProcessService(IProcessEventProvider provider, ProcessDetailOptions options, IEngineLogger logger = null)
        {
            _provider = provider;
            _logger = logger;
            _processCache = new ConcurrentDictionary<int, FullProcessInfo>();
            _detailOptions = options ?? new ProcessDetailOptions();
        }

        public void Start()
        {
            _logger?.Log(LogLevel.Info, "ProcessService starting...");
            _provider.Start(this, _logger);
        }

        public void Stop()
        {
            _logger?.Log(LogLevel.Info, "ProcessService stopping...");
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
                Task.Run(() => LoadSlowDetails(newInfo));
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

        void IProcessNotifier.OnProcessStatisticsUpdate(int pid, long workingSet, uint threads, int priority, List<ThreadInfo> threadInfos)
        {
            if (_processCache.TryGetValue(pid, out FullProcessInfo info))
            {
                info.UpdateFastData(info.Name, workingSet, threads, priority, threadInfos);
                ProcessUpdated?.Invoke(info.CreateSnapshot());
            }
        }

        void IProcessNotifier.OnProcessIoUpdate(int pid, long readBytes, long writeBytes)
        {
            if (_processCache.TryGetValue(pid, out FullProcessInfo info))
            {
                info.TotalReadBytes += readBytes;
                info.TotalWriteBytes += writeBytes;
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
                    if (_detailOptions.LoadExePathAndCommandLine)
                    {
                        try { info.ExePath = proc.GetExePath(); }
                        catch (Exception ex)
                        {
                            info.ExePath = "Access Denied";
                            _logger?.Log(LogLevel.Debug, $"Failed to get ExePath for PID {info.Pid}.", ex);
                        }

                        try { info.CommandLine = proc.GetCommandLine(); }
                        catch (Exception ex)
                        {
                            info.CommandLine = "Access Denied";
                            _logger?.Log(LogLevel.Debug, $"Failed to get CommandLine for PID {info.Pid}.", ex);
                        }
                    }

                    if (_detailOptions.LoadIoCounters)
                    {
                        try { info.IoCounters = proc.GetIoCounters(); }
                        catch (Exception ex)
                        {
                            _logger?.Log(LogLevel.Debug, $"Failed to get IoCounters for PID {info.Pid}.", ex);
                        }
                    }

                    if (_detailOptions.LoadSecurityInfo)
                    {
                        try { info.SecurityInfo = proc.GetSecurityInfo(); }
                        catch (Exception ex)
                        {
                            _logger?.Log(LogLevel.Debug, $"Failed to get SecurityInfo for PID {info.Pid}.", ex);
                        }
                    }

                    if (_detailOptions.LoadMitigationInfo)
                    {
                        try { info.MitigationInfo = proc.GetMitigationInfo(); }
                        catch (Exception ex)
                        {
                            _logger?.Log(LogLevel.Debug, $"Failed to get MitigationInfo for PID {info.Pid}.", ex);
                        }
                    }
                }
            }
            catch (Win32Exception ex)
            {
                info.ExePath = ex.Message;
                info.CommandLine = ex.Message;
                info.SecurityInfo.UserName = ex.Message;
                _logger?.Log(LogLevel.Debug, $"Failed to open PID {info.Pid} for details.", ex);
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
                if (_detailOptions.LoadSignatureInfo)
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

                if (_detailOptions.LoadFileVersionInfo)
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
                        _logger?.Log(LogLevel.Debug, $"Failed to get FileVersionInfo for {info.ExePath}.", ex);
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