/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
namespace NativeProcesses.Core.Models
{
    public class DotNetStackFrame
    {
        public string MethodName { get; set; }
        public ulong InstructionPointer { get; set; }
        public ulong StackPointer { get; set; }

        public override string ToString()
        {
            return MethodName;
        }
    }
}