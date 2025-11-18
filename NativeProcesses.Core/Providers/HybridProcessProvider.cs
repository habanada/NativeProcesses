/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using NativeProcesses.Core.Engine;
using System;
using System.Collections.Generic;

namespace NativeProcesses.Core.Providers
{
    public class HybridProcessProvider : IProcessEventProvider
    {
        private readonly IProcessEventProvider[] _providers;
        public HybridProcessProvider(params IProcessEventProvider[] providers) { _providers = providers; }

        public IEnumerable<IProcessEventProvider> Providers => _providers;

        public void Start(IProcessNotifier notifier, IEngineLogger logger)
        {
            foreach (var p in _providers) p.Start(notifier, logger);
        }
        public void Stop() { foreach (var p in _providers) p.Stop(); }
        public void Dispose() { foreach (var p in _providers) p.Dispose(); }
    }
}
