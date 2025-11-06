using System.ComponentModel;
using System.Runtime.CompilerServices;
using NativeProcesses;
using System.Collections.Generic;
using System.Linq;

namespace ProcessDemo
{
    public class ProcessInfoViewModel : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;
        private void Notify([CallerMemberName] string prop = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(prop));
        }

        public int Pid { get; private set; }

        private string _name;
        public string Name
        {
            get { return _name; }
            set { _name = value; Notify(); }
        }

        private long _workingSet;
        public long WorkingSetSize
        {
            get { return _workingSet; }
            set { _workingSet = value; Notify(); }
        }

        private uint _threads;
        public uint NumberOfThreads
        {
            get { return _threads; }
            set { _threads = value; Notify(); }
        }

        private int _priority;
        public int BasePriority
        {
            get { return _priority; }
            set { _priority = value; Notify(); }
        }

        private string _exePath;
        public string ExePath
        {
            get { return _exePath; }
            set { _exePath = value; Notify(); }
        }

        private string _commandLine;
        public string CommandLine
        {
            get { return _commandLine; }
            set { _commandLine = value; Notify(); }
        }

        private long _totalReadBytes;
        public long TotalReadBytes
        {
            get { return _totalReadBytes; }
            set { _totalReadBytes = value; Notify(); }
        }

        private long _totalWriteBytes;
        public long TotalWriteBytes
        {
            get { return _totalWriteBytes; }
            set { _totalWriteBytes = value; Notify(); }
        }

        private double _cpuUsagePercent;
        public double CpuUsagePercent
        {
            get { return _cpuUsagePercent; }
            set { _cpuUsagePercent = value; Notify(); }
        }

        public BindingList<ThreadInfoViewModel> Threads { get; private set; }

        private string _userName;
        public string UserName
        {
            get { return _userName; }
            set { _userName = value; Notify(); }
        }

        private string _integrity;
        public string IntegrityLevel
        {
            get { return _integrity; }
            set { _integrity = value; Notify(); }
        }

        private string _imageType;
        public string ImageType
        {
            get { return _imageType; }
            set { _imageType = value; Notify(); }
        }

        private bool _isElevated;
        public bool IsElevated
        {
            get { return _isElevated; }
            set { _isElevated = value; Notify(); }
        }

        private string _fileCompany;
        public string FileCompany
        {
            get { return _fileCompany; }
            set { _fileCompany = value; Notify(); }
        }

        private string _fileDescription;
        public string FileDescription
        {
            get { return _fileDescription; }
            set { _fileDescription = value; Notify(); }
        }

        private string _fileVersion;
        public string FileVersion
        {
            get { return _fileVersion; }
            set { _fileVersion = value; Notify(); }
        }

        private ulong _ioReads;
        public ulong IoReads
        {
            get { return _ioReads; }
            set { _ioReads = value; Notify(); }
        }

        private ulong _ioWrites;
        public ulong IoWrites
        {
            get { return _ioWrites; }
            set { _ioWrites = value; Notify(); }
        }


        public ProcessInfoViewModel(FullProcessInfo source)
        {
            this.Pid = source.Pid;
            this.Threads = new BindingList<ThreadInfoViewModel>();
            this.ApplyUpdate(source);
        }

        public void ApplyUpdate(FullProcessInfo source)
        {
            this.Name = source.Name;
            this.WorkingSetSize = source.WorkingSetSize;
            this.NumberOfThreads = source.NumberOfThreads;
            this.BasePriority = source.BasePriority;
            this.ExePath = source.ExePath;
            this.CommandLine = source.CommandLine;
            this.TotalReadBytes = source.TotalReadBytes;
            this.TotalWriteBytes = source.TotalWriteBytes;
            this.CpuUsagePercent = source.CpuUsagePercent;

            this.UserName = source.SecurityInfo.UserName;
            this.IntegrityLevel = source.SecurityInfo.IntegrityLevel;
            this.ImageType = source.SecurityInfo.ImageType;
            this.IsElevated = source.SecurityInfo.IsElevated;

            this.FileCompany = source.FileCompany;
            this.FileDescription = source.FileDescription;
            this.FileVersion = source.FileVersion;

            this.IoReads = source.IoCounters.ReadOperationCount;
            this.IoWrites = source.IoCounters.WriteOperationCount;

            var sourceThreadIds = new HashSet<int>(source.Threads.Select(t => t.ThreadId));

            var threadsToRemove = this.Threads.Where(t => !sourceThreadIds.Contains(t.ThreadId)).ToList();
            foreach (var oldThread in threadsToRemove)
            {
                this.Threads.Remove(oldThread);
            }

            foreach (var sourceThread in source.Threads)
            {
                var existingThread = this.Threads.FirstOrDefault(t => t.ThreadId == sourceThread.ThreadId);
                if (existingThread != null)
                {
                    existingThread.ApplyUpdate(sourceThread);
                }
                else
                {
                    this.Threads.Add(new ThreadInfoViewModel(sourceThread));
                }
            }
        }
    }
}