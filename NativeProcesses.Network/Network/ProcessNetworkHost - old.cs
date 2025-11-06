//using Newtonsoft.Json;
//using System.Linq;
//using System.Net.Security;
//using System.Threading.Tasks;
//using System;
//using NativeProcesses.Core;

//namespace NativeProcesses.Network
//{
//    public class ProcessNetworkHost
//    {
//        private readonly ProcessService _service;
//        private readonly SecureTcpServer _server;
//        private readonly IProcessEventProvider _provider;

//        public ProcessNetworkHost(ProcessService service, SecureTcpServer server, IProcessEventProvider provider)
//        {
//            _service = service;
//            _server = server;
//            _provider = provider;

//            _service.ProcessAdded += OnProcessAdded;
//            _service.ProcessUpdated += OnProcessUpdated;
//            _service.ProcessRemoved += OnProcessRemoved;

//            _server.MessageReceived += OnMessageReceived;
//        }

//        private void OnProcessAdded(FullProcessInfo info)
//        {
//            Task.Run(() => _server.BroadcastAsync("process_added", info));
//        }

//        private void OnProcessUpdated(FullProcessInfo info)
//        {
//            Task.Run(() => _server.BroadcastAsync("process_updated", info));
//        }

//        private void OnProcessRemoved(int pid)
//        {
//            Task.Run(() => _server.BroadcastAsync("process_removed", pid));
//        }

//        private void OnMessageReceived(SslStream ssl, string type, string data)
//        {
//            try
//            {
//                switch (type)
//                {
//                    case "kill":
//                        int pidToKill = JsonConvert.DeserializeObject<int>(data);
//                        ProcessManager.Kill(pidToKill);
//                        break;

//                    case "suspend":
//                        int pidToSuspend = JsonConvert.DeserializeObject<int>(data);
//                        ProcessManager.Suspend(pidToSuspend);
//                        break;

//                    case "resume":
//                        int pidToResume = JsonConvert.DeserializeObject<int>(data);
//                        ProcessManager.Resume(pidToResume);
//                        break;

//                    case "get_all_processes":
//                        var allProcs = _service.GetCurrentProcesses();
//                        Task.Run(() => _server.SendMessageAsync(ssl, "process_list", allProcs));
//                        break;

//                    case "get_process_info":
//                        int pidInfo = JsonConvert.DeserializeObject<int>(data);
//                        var proc = _service.GetCurrentProcesses().FirstOrDefault(p => p.Pid == pidInfo);
//                        Task.Run(() => _server.SendMessageAsync(ssl, "process_info", proc));
//                        break;

//                    case "set_detail_level":
//                        ProcessDetailOptions options = JsonConvert.DeserializeObject<ProcessDetailOptions>(data);
//                        if (options != null)
//                        {
//                            _service.DetailOptions = options;
//                        }
//                        break;

//                    case "set_poll_interval":
//                        int ms = JsonConvert.DeserializeObject<int>(data);
//                        if (ms > 500 && _provider is PollingProcessProvider poller)
//                        {
//                            poller.Interval = TimeSpan.FromMilliseconds(ms);
//                        }
//                        break;

//                    case "shutdown_server":
//                        Task.Run(() =>
//                        {
//                            ShutdownServer();
//                        });
//                        break;
//                }
//            }
//            catch
//            {
//            }
//        }

//        public void ShutdownServer()
//        {
//            if (_service!=null)
//                _service.Stop();
//            if (_server != null) 
//                _server.Stop();
//        }
//    }
//}