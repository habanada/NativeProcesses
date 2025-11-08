/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using NativeProcesses.Core.Engine;
using System;
namespace NativeProcesses.Core.Providers
{
    public interface IProcessEventProvider : IDisposable
    {
        void Start(IProcessNotifier notifier, IEngineLogger logger);
        void Stop();
    }
}
