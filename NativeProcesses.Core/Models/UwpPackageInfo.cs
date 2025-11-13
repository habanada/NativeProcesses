using System;

namespace NativeProcesses.Core.Models
{
    public class UwpPackageInfo
    {
        public string PackageFullName { get; set; }
        public string DisplayName { get; set; }
        public string Publisher { get; set; }
        public string Version { get; set; }
        public DateTimeOffset InstallDate { get; set; }
        public string LogoPath { get; set; }
    }
}