using System.Collections.Generic;

namespace NativeProcesses.Core.Models
{
    public class DotNetAppDomainInfo
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public ulong Address { get; set; }
        public string ConfigFile { get; set; }
        public string ApplicationBase { get; set; }

        public List<string> LoadedAssemblies { get; set; }

        public DotNetAppDomainInfo()
        {
            LoadedAssemblies = new List<string>();
        }
    }
}