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