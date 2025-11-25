/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;

namespace NativeProcesses.Core.Engine
{
    public enum BehaviorEventType
    {
        Unknown,
        ProcessStart,
        ImageLoad,
        VirtualAlloc,
        VirtualProtect,
        MapPreView, // NtMapViewOfSection
        JitCompile, // .NET Method JIT
        InteropCall, // P/Invoke
        ThreadStart
    }

    public struct BehaviorEvent
    {
        public DateTime Time;
        public BehaviorEventType Type;
        public long Address;
        public long Size;
        public string Details; // z.B. Protection Flags oder Methoden-Name
        public string MethodName; // Für JIT
    }
}