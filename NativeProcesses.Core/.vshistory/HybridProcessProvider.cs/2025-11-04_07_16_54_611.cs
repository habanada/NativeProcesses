using System;
namespace NativeProcesses
{
    public class HybridProcessProvider : IProcessEventProvider
    {
        private readonly IProcessEventProvider[] _providers;
        public HybridProcessProvider(params IProcessEventProvider[] providers) { _providers = providers; }
        public void Start(IProcessNotifier notifier, IEngineLogger logger)
        {
            foreach (var p in _providers) p.Start(notifier, logger);
        }
        public void Stop() { foreach (var p in _providers) p.Stop(); }
        public void Dispose() { foreach (var p in _providers) p.Dispose(); }
    }
}
