using NativeProcesses.Core.Models;
using System;
using System.Collections.Generic;
using System.Text;

namespace NativeProcesses.Core.Native
{
    public static class WindowManager
    {
        public static List<WindowInfo> GetWindowsForProcess(int pid)
        {
            List<WindowInfo> windows = new List<WindowInfo>();

            User32.EnumWindowsProc proc = (hWnd, lParam) =>
            {
                User32.GetWindowThreadProcessId(hWnd, out uint windowPid);
                if (windowPid == pid)
                {
                    int length = User32.GetWindowTextLength(hWnd);
                    StringBuilder sb = new StringBuilder(length + 1);
                    User32.GetWindowText(hWnd, sb, sb.Capacity);

                    windows.Add(new WindowInfo
                    {
                        Handle = hWnd,
                        Title = sb.ToString(),
                        IsVisible = User32.IsWindowVisible(hWnd),
                        IsMinimized = User32.IsIconic(hWnd)
                    });
                }
                return true;
            };

            User32.EnumWindows(proc, IntPtr.Zero);
            return windows;
        }
    }
}