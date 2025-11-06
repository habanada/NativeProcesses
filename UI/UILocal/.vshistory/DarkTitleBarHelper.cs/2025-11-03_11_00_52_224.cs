using System;
using System.Windows.Forms;

namespace ProcessDemo.ProcessDemo
{
        public static class DarkTitleBarHelper
        {
            // DWM API values
            private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;  // ab Windows 10 1809
            private const int DWMWA_CAPTION_COLOR = 35;
            private const int DWMWA_TEXT_COLOR = 36;

            [DllImport("dwmapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

            /// <summary>
            /// Aktiviert den Darkmode für die Titelleiste, falls vom OS unterstützt.
            /// </summary>
            public static void Apply(Form form)
            {
                try
                {
                    if (!IsWindows10OrGreater(17763))
                        return; // nur Win10 1809+

                    int useDark = 1;
                    var handle = form.Handle;
                    DwmSetWindowAttribute(handle, DWMWA_USE_IMMERSIVE_DARK_MODE, ref useDark, sizeof(int));

                    // Optional: Farben explizit setzen (Win11+)
                    uint darkCaptionColor = 0x002D2D30;  // RGB(45,45,48)
                    uint lightTextColor = 0x00FFFFFF;    // Weiß

                    DwmSetWindowAttribute(handle, DWMWA_CAPTION_COLOR, ref Unsafe.As<uint, int>(ref darkCaptionColor), sizeof(int));
                    DwmSetWindowAttribute(handle, DWMWA_TEXT_COLOR, ref Unsafe.As<uint, int>(ref lightTextColor), sizeof(int));
                }
                catch
                {
                    // stiller Fallback, kein Fehler werfen
                }
            }

            private static bool IsWindows10OrGreater(int build = 0)
            {
                Version osVersion = Environment.OSVersion.Version;
                return (osVersion.Major == 10 && osVersion.Build >= build) || osVersion.Major > 10;
            }
        }
}