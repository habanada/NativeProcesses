using System;
namespace NativeProcesses.Core
{
    public interface IProcessEventProvider : IDisposable
    {
        void Start(IProcessNotifier notifier, IEngineLogger logger);
        void Stop();
    }
}
