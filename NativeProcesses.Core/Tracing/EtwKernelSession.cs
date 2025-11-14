//using Microsoft.Diagnostics.Tracing;
//using Microsoft.Diagnostics.Tracing.Parsers;
//using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
//using Microsoft.Diagnostics.Tracing.Session;
//using NativeProcesses.Core.Engine;
//using System;
//using System.Threading;
//using System.Threading.Tasks;

//namespace NativeProcesses.Tracing
//{
//    public class EtwKernelSession : IDisposable
//    {
//        private const string DefaultSessionName = "NativeProcessesKernelSession";

//        private readonly string _sessionName;
//        private TraceEventSession _session;
//        private Task _processingTask;
//        private CancellationTokenSource _cts;
//        private readonly IEngineLogger _logger;

//        public event Action<ProcessTraceData> ProcessStarted;
//        public event Action<ProcessTraceData> ProcessStopped;
//        public event Action<DiskIOTraceData> DiskRead;
//        public event Action<DiskIOTraceData> DiskWrite;

//        public event Action<TcpIpSendTraceData> NetworkSend;
//        public event Action<TcpIpTraceData> NetworkReceive;

//        public event Action<TraceEvent> EventLost;

//        public bool IsRunning { get; private set; }

//        public EtwKernelSession(IEngineLogger logger, string sessionName = DefaultSessionName)
//        {
//            _sessionName = sessionName;
//            _logger = logger;
//        }

//        public void Start()
//        {
//            try
//            {
//                if (IsRunning || _processingTask != null)
//                { 
//                    return;
//                }

//                _cts = new CancellationTokenSource();
//                IsRunning = true;

//                _processingTask = Task.Run(() => ProcessingLoop(_cts.Token), _cts.Token);
//            }
//            catch (Exception ex)
//            {
//                IsRunning = false;
//                LogError("Failed to start ETW session", ex);
//            }
//        }

//        public void Stop()
//        {
//            try
//            {
//                if (!IsRunning || _cts == null)
//                {
//                    return;
//                }

//                _cts.Cancel();
//                _session?.Stop(true);

//                _processingTask?.Wait(5000);
//            }
//            catch (Exception ex)
//            {
//                LogError("Error during ETW session stop", ex);
//            }
//            finally
//            {
//                Cleanup();
//            }
//        }

//        private void ProcessingLoop(CancellationToken token)
//        {
//            try
//            {
//                using (_session = new TraceEventSession(_sessionName))
//                {
//                    _session.StopOnDispose = true;

//                    _session.Source.UnhandledEvents += (data) =>
//                    {
//                        if (data.ID == (TraceEventID)65534)
//                        {
//                            EventLost?.Invoke(data);
//                        }
//                    };

//                    var keywords = KernelTraceEventParser.Keywords.Process |
//                                   KernelTraceEventParser.Keywords.DiskIO |
//                                   KernelTraceEventParser.Keywords.NetworkTCPIP;

//                    _session.EnableKernelProvider(keywords);

//                    SetupParsers(_session.Source.Kernel);

//                    _session.Source.Process();
//                }
//            }
//            catch (OperationCanceledException)
//            {
//            }
//            catch (Exception ex)
//            {
//                LogError("ETW ProcessingLoop failed", ex);
//            }
//            finally
//            {
//                IsRunning = false;
//            }
//        }

//        private void SetupParsers(KernelTraceEventParser parser)
//        {
//            parser.ProcessStart += (data) => ProcessStarted?.Invoke(data);
//            parser.ProcessStop += (data) => ProcessStopped?.Invoke(data);

//            parser.DiskIORead += (data) => DiskRead?.Invoke(data);
//            parser.DiskIOWrite += (data) => DiskWrite?.Invoke(data);

//            parser.TcpIpSend += (data) => NetworkSend?.Invoke(data);
//            parser.TcpIpRecv += (data) => NetworkReceive?.Invoke(data);
//        }

//        private void Cleanup()
//        {
//            _session?.Dispose();
//            _cts?.Dispose();
//            _session = null;
//            _cts = null;
//            _processingTask = null;
//            IsRunning = false;
//        }

//        private void LogError(string message, Exception ex)
//        {
//            Console.WriteLine();
//            _logger?.Log(LogLevel.Error, $"[EtwKernelSession] ERROR: {message} - {ex.Message}", ex);
//        }

//        public void Dispose()
//        {
//            Stop();
//        }
//    }
//}