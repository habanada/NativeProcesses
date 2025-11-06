/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Microsoft.Win32;

namespace ProcessDemo
{
    public static class DarkTitleBarHelper
    {
        private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
        private const int DWMWA_CAPTION_COLOR = 35;
        private const int DWMWA_TEXT_COLOR = 36;

        [DllImport("dwmapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

        public static void Apply(Form form)
        {
            try
            {
                if (!IsWindows10OrGreater(17763))
                {
                    return;
                }

                int useDark = 1;
                var handle = form.Handle;
                DwmSetWindowAttribute(handle, DWMWA_USE_IMMERSIVE_DARK_MODE, ref useDark, sizeof(int));

                int darkCaptionColor = 0x00302D2D;
                int lightTextColor = 0x00FFFFFF;

                DwmSetWindowAttribute(handle, DWMWA_CAPTION_COLOR, ref darkCaptionColor, sizeof(int));
                DwmSetWindowAttribute(handle, DWMWA_TEXT_COLOR, ref lightTextColor, sizeof(int));
            }
            catch
            {
            }
        }

        private static bool IsWindows10OrGreater(int build = 0)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (key == null) return false;

                    object majorObj = key.GetValue("CurrentMajorVersionNumber");
                    if (majorObj == null) return false;

                    int major = (int)majorObj;

                    object buildObj = key.GetValue("CurrentBuildNumber");
                    if (buildObj == null) return false;

                    int buildNumber = int.Parse(buildObj.ToString());

                    return (major == 10 && buildNumber >= build) || major > 10;
                }
            }
            catch
            {
                return false;
            }
        }
    }
}