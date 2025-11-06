using System;
using System.Management;
namespace NativeProcesses
{
    public class WmiProcessProvider : IProcessEventProvider
    {
        private IProcessNotifier _notifier;
        private IEngineLogger _logger;
        private ManagementEventWatcher _startWatcher;
        private ManagementEventWatcher _stopWatcher;
        public void Start(IProcessNotifier notifier, IEngineLogger logger)
        {
            _notifier = notifier;
            _logger = logger;
            try
            {
                var startQuery = new WqlEventQuery("__InstanceCreationEvent",
                    new TimeSpan(0, 0, 1),
                    "TargetInstance isa 'Win32_Process'");
                _startWatcher = new ManagementEventWatcher(startQuery);
                _startWatcher.EventArrived += OnProcessStarted;
                _startWatcher.Start();
                var stopQuery = new WqlEventQuery("__InstanceDeletionEvent",
                    new TimeSpan(0, 0, 1),
                    "TargetInstance isa 'Win32_Process'");
                _stopWatcher = new ManagementEventWatcher(stopQuery);
                _stopWatcher.EventArrived += OnProcessStopped;
                _stopWatcher.Start();
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, "Failed to start WMI provider.", ex);
            }
        }
        private void OnProcessStarted(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var instance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                int pid = Convert.ToInt32(instance["ProcessId"]);
                string name = instance["Name"].ToString();
                _notifier.OnProcessStarted(pid, name);
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Warning, "WMI OnProcessStarted event failed.", ex);
            }
        }
        private void OnProcessStopped(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var instance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                int pid = Convert.ToInt32(instance["ProcessId"]);
                _notifier.OnProcessStopped(pid);
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Warning, "WMI OnProcessStopped event failed.", ex);
            }
        }
        public void Stop()
        {
            _startWatcher?.Stop();
            _stopWatcher?.Stop();
        }
        public void Dispose()
        {
            Stop();
            _startWatcher?.Dispose();
            _stopWatcher?.Dispose();
        }
    }
}
