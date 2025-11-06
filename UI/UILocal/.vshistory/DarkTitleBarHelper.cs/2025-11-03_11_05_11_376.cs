using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

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
            Version osVersion = Environment.OSVersion.Version;
            return (osVersion.Major == 10 && osVersion.Build >= build) || osVersion.Major > 10;
        }
    }
}