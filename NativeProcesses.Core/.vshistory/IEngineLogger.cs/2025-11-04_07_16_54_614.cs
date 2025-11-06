using System;
namespace NativeProcesses
{
    public interface IEngineLogger
    {
        void Log(LogLevel level, string message, Exception ex = null);
    }
}
