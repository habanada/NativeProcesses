using System;

namespace NativeProcesses.Core.Models
{
    public class WindowInfo
    {
        public IntPtr Handle { get; set; }
        public string Title { get; set; }
        public bool IsVisible { get; set; }
        public bool IsMinimized { get; set; }
        public string Status
        {
            get
            {
                if (IsMinimized) return "Minimized";
                if (IsVisible) return "Visible";
                return "Hidden";
            }
        }
    }
}