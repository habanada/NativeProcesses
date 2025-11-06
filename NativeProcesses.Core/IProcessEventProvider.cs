/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
namespace NativeProcesses.Core
{
    public interface IProcessEventProvider : IDisposable
    {
        void Start(IProcessNotifier notifier, IEngineLogger logger);
        void Stop();
    }
}
