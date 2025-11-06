using System.Collections.Generic;
using System.Linq;

namespace NativeProcesses
{
    public class FullProcessInfo
    {
        private const string LOADINGSTR = "[Loading...]";
        private readonly object _updateLock = new object();
        private readonly object _threadListLock = new object();

        public int Pid { get; private set; }

        private string _name;
        public string Name
        {
            get { lock (_updateLock) { return _name; } }
            set { lock (_updateLock) { _name = value; } }
        }

        private long _workingSet;
        public long WorkingSetSize
        {
            get { lock (_updateLock) { return _workingSet; } }
            set { lock (_updateLock) { _workingSet = value; } }
        }

        private uint _rawNumberOfThreads;
        public uint NumberOfThreads
        {
            get { lock (_updateLock) { return _rawNumberOfThreads; } }
            set { lock (_updateLock) { _rawNumberOfThreads = value; } }
        }

        private int _priority;
        public int BasePriority
        {
            get { lock (_updateLock) { return _priority; } }
            set { lock (_updateLock) { _priority = value; } }
        }

        private string _exePath;
        public string ExePath
        {
            get { lock (_updateLock) { return _exePath; } }
            set { lock (_updateLock) { _exePath = value; } }
        }

        private string _commandLine;
        public string CommandLine
        {
            get { lock (_updateLock) { return _commandLine; } }
            set { lock (_updateLock) { _commandLine = value; } }
        }

        private long _totalReadBytes;
        public long TotalReadBytes
        {
            get { lock (_updateLock) { return _totalReadBytes; } }
            set { lock (_updateLock) { _totalReadBytes = value; } }
        }

        private long _totalWriteBytes;
        public long TotalWriteBytes
        {
            get { lock (_updateLock) { return _totalWriteBytes; } }
            set { lock (_updateLock) { _totalWriteBytes = value; } }
        }

        private double _cpuUsagePercent;
        public double CpuUsagePercent
        {
            get { lock (_updateLock) { return _cpuUsagePercent; } }
            set { lock (_updateLock) { _cpuUsagePercent = value; } }
        }

        private List<ThreadInfo> _threadsList;
        public List<ThreadInfo> Threads
        {
            get
            {
                lock (_threadListLock)
                {
                    return _threadsList.Select(t => t.CreateSnapshot()).ToList();
                }
            }
            private set
            {
                lock (_threadListLock)
                {
                    _threadsList = value;
                }
            }
        }

        public volatile bool IsLoadingDetails;
        public volatile bool IsDetailsLoaded;

        public FullProcessInfo(int pid, string name, long workingSet, uint threads, int priority)
        {
            this.Pid = pid;
            this._name = name;
            this._workingSet = workingSet;
            this._rawNumberOfThreads = threads;
            this._priority = priority;
            this._exePath = LOADINGSTR;
            this._commandLine = LOADINGSTR;
            this._threadsList = new List<ThreadInfo>();
        }

        public void UpdateFastData(string name, long workingSet, uint threads, int priority, List<ThreadInfo> threadInfos)
        {
            lock (_updateLock)
            {
                this.Name = name;
                this.WorkingSetSize = workingSet;
                this.NumberOfThreads = threads;
                this.BasePriority = priority;
            }

            lock (_threadListLock)
            {
                this.Threads = threadInfos;
            }
        }

        public FullProcessInfo CreateSnapshot()
        {
            FullProcessInfo copy;
            lock (_updateLock)
            {
                copy = (FullProcessInfo)this.MemberwiseClone();
            }

            copy.Threads = this.Threads;
            return copy;
        }

        public void UpdateFastData(string name, long workingSet, uint threads, int priority)
        {
            lock (_updateLock)
            {
                this.Name = name;
                this.WorkingSetSize = workingSet;
                this.NumberOfThreads = threads;
                this.BasePriority = priority;
            }
        }
    }
}