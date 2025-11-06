using System.ComponentModel;
using System.Runtime.CompilerServices;
using NativeProcesses.Core;

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
        }
    }
}