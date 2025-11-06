?using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing;
namespace NativeProcesses
{
    public class EtwProcessProvider : IProcessEventProvider
    {
        private IProcessNotifier _notifier;
        private IEngineLogger _logger;
        private TraceEventSession _session;
        private Task _listenTask;
        public void Start(IProcessNotifier notifier, IEngineLogger logger)
        {
            _notifier = notifier;
            _logger = logger;
            string sessionName = "MyProcessManagerSession_" + Process.GetCurrentProcess().Id;
            _listenTask = Task.Run(() =>
            {
                try
                {
                    using (_session = new TraceEventSession(sessionName))
                    {
                        _session.EnableKernelProvider(
                            KernelTraceEventParser.Keywords.Process |
                            KernelTraceEventParser.Keywords.DiskIO
                        );
                        _session.Source.Kernel.ProcessStart += OnProcessStart;
                        _session.Source.Kernel.ProcessStop += OnProcessStop;
                        _session.Source.Kernel.DiskIORead += OnDiskIo;
                        _session.Source.Kernel.DiskIOWrite += OnDiskIo;
                        _session.Source.Process();
                    }
                }
                catch (Exception ex)
                {
                    _logger?.Log(LogLevel.Error, "ETW session failed.", ex);
                }
            });
        }
        private void OnProcessStart(ProcessTraceData data)
        {
            _notifier.OnProcessStarted(data.ProcessID, data.ImageFileName);
        }
        private void OnProcessStop(ProcessTraceData data)
        {
            _notifier.OnProcessStopped(data.ProcessID);
        }
        private void OnDiskIo(DiskIOTraceData data)
        {
            bool isRead = data.Opcode == (TraceEventOpcode)10;
            long read = isRead ? data.TransferSize : 0;
            long write = !isRead ? data.TransferSize : 0;
            _notifier.OnProcessIoUpdate(data.ProcessID, read, write);
        }
        public void Stop()
        {
            _session?.Stop(true);
        }
        public void Dispose()
        {
            Stop();
            _session?.Dispose();
        }
    }
}
