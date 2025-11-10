using NativeProcesses.Core.Models;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NativeProcesses.Core.Native
{
    public static class PsApiModuleEnumerator
    {
        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumProcessModules(
            IntPtr hProcess,
            [Out] IntPtr[] lphModule,
            int cb,
            [MarshalAs(UnmanagedType.I4)] out int lpcbNeeded);

        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetModuleFileNameEx(
            IntPtr hProcess,
            IntPtr hModule,
            [Out] StringBuilder lpBaseName,
            [MarshalAs(UnmanagedType.I4)] int nSize);

        public static List<ProcessModuleInfo> GetModules(ManagedProcess process)
        {
            if (process == null || process.Handle == IntPtr.Zero)
            {
                throw new ArgumentNullException(nameof(process), "ManagedProcess or its Handle cannot be null.");
            }

            var modules = new List<ProcessModuleInfo>();
            IntPtr[] moduleHandles = new IntPtr[1024];
            int sizeNeeded;

            if (!EnumProcessModules(process.Handle, moduleHandles, moduleHandles.Length * IntPtr.Size, out sizeNeeded))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "EnumProcessModules failed.");
            }

            int moduleCount = sizeNeeded / IntPtr.Size;
            StringBuilder sb = new StringBuilder(1024);

            for (int i = 0; i < moduleCount; i++)
            {
                if (moduleHandles[i] == IntPtr.Zero)
                {
                    continue;
                }

                if (GetModuleFileNameEx(process.Handle, moduleHandles[i], sb, sb.Capacity) > 0)
                {
                    string path = sb.ToString();
                    modules.Add(new ProcessModuleInfo
                    {
                        BaseDllName = System.IO.Path.GetFileName(path),
                        FullDllName = path,
                        DllBase = moduleHandles[i],
                        SizeOfImage = 0,
                        EntryPoint = IntPtr.Zero
                    });
                }

                sb.Clear();
            }

            return modules;
        }
    }
}
