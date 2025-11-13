using NativeProcesses.Core.Models;
using System;
using Windows.Management.Deployment;

namespace processlist
{
    internal  class UwpManager
    {
        public static UwpPackageInfo GetPackageInfo(string packageFullName)
        {
            try
            {
                PackageManager pm = new PackageManager();
                Windows.ApplicationModel.Package package = pm.FindPackageForUser(string.Empty, packageFullName);

                if (package == null)
                    throw new Exception("Package not found.");

                var info = new UwpPackageInfo
                {
                    PackageFullName = package.Id.FullName,
                    DisplayName = package.DisplayName,
                    Publisher = package.Id.Publisher,
                    Version = string.Format("{0}.{1}.{2}.{3}",
                        package.Id.Version.Major,
                        package.Id.Version.Minor,
                        package.Id.Version.Build,
                        package.Id.Version.Revision),
                    InstallDate = package.InstalledDate,
                    LogoPath = package.Logo?.AbsolutePath ?? "N/A"
                };

                return info;
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to query WinRT PackageManager. (Process may be terminating or access denied). Error: {ex.Message}");
            }
        }
    }
}