?using System;
namespace NativeProcesses
{
    public interface IProcessEventProvider : IDisposable
    {
        void Start(IProcessNotifier notifier, IEngineLogger logger);
        void Stop();
    }
}
