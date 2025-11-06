using System;
namespace NativeProcesses.Core
{
    public interface IEngineLogger
    {
        void Log(LogLevel level, string message, Exception ex = null);
    }
}
