namespace NativeProcesses.Core.Models
{
    public class DotNetGcRootPathInfo
    {
        public string Kind { get; set; }
        public ulong Address { get; set; }
        public string TypeName { get; set; }
        public string RootKind { get; set; }
    }
}