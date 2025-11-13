namespace NativeProcesses.Core.Models
{
    public class NetworkConnectionInfo
    {
        public string Protocol { get; set; }
        public string LocalAddress { get; set; }
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; }
        public int RemotePort { get; set; }
        public string State { get; set; }
        public int OwnerPid { get; set; }
    }
}