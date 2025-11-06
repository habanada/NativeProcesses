/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
namespace NativeProcesses.Core
{
    public interface IEngineLogger
    {
        void Log(LogLevel level, string message, Exception ex = null);
    }
}
