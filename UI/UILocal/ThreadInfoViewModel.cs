/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using NativeProcesses.Core;
using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace ProcessDemo
{
    public class ThreadInfoViewModel : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;
        private void Notify([CallerMemberName] string prop = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(prop));
        }

        public int ThreadId { get; private set; }
        private IntPtr _startAddress;
        public IntPtr StartAddress
        {
            get { return _startAddress; }
            set { _startAddress = value; Notify(); }
        }
        private int _priority;
        public int BasePriority
        {
            get { return _priority; }
            set { _priority = value; Notify(); }
        }

        private long _kernelTime;
        public long KernelTime
        {
            get { return _kernelTime; }
            set { _kernelTime = value; Notify(); }
        }

        private long _userTime;
        public long UserTime
        {
            get { return _userTime; }
            set { _userTime = value; Notify(); }
        }


        public ThreadInfoViewModel(ThreadInfo source)
        {
            this.ThreadId = source.ThreadId;
            this.ApplyUpdate(source);
        }

        public void ApplyUpdate(ThreadInfo source)
        {
            this.BasePriority = source.BasePriority;
            this.KernelTime = source.KernelTime;
            this.UserTime = source.UserTime;
            this.StartAddress = source.StartAddress;
        }
    }
}