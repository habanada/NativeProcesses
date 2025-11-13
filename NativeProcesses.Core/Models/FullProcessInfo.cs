/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/

using System.Collections.Generic;
using System.Linq;

namespace NativeProcesses.Core
{
    public class FullProcessInfo
    {
        private readonly object _updateLock = new object();
        private readonly object _threadListLock = new object();

        public int Pid { get;  set; }

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

        private long _totalReadOps;
        public long TotalReadOps
        {
            get { lock (_updateLock) { return _totalReadOps; } }
            set { lock (_updateLock) { _totalReadOps = value; } }
        }

        private long _totalWriteOps;
        public long TotalWriteOps
        {
            get { lock (_updateLock) { return _totalWriteOps; } }
            set { lock (_updateLock) { _totalWriteOps = value; } }
        }

        private long _totalPageFaults;
        public long TotalPageFaults
        {
            get { lock (_updateLock) { return _totalPageFaults; } }
            set { lock (_updateLock) { _totalPageFaults = value; } }
        }

        private long _pagedPoolUsage;
        public long PagedPoolUsage
        {
            get { lock (_updateLock) { return _pagedPoolUsage; } }
            set { lock (_updateLock) { _pagedPoolUsage = value; } }
        }

        private long _nonPagedPoolUsage;
        public long NonPagedPoolUsage
        {
            get { lock (_updateLock) { return _nonPagedPoolUsage; } }
            set { lock (_updateLock) { _nonPagedPoolUsage = value; } }
        }

        private long _privatePageCount;
        public long PrivatePageCount
        {
            get { lock (_updateLock) { return _privatePageCount; } }
            set { lock (_updateLock) { _privatePageCount = value; } }
        }

        private long _pagefileUsage;
        public long PagefileUsage
        {
            get { lock (_updateLock) { return _pagefileUsage; } }
            set { lock (_updateLock) { _pagefileUsage = value; } }
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
            set
            {
                lock (_threadListLock)
                {
                    _threadsList = value;
                }
            }
        }

        private ProcessIoCounters _ioCounters;
        public ProcessIoCounters IoCounters
        {
            get { lock (_updateLock) { return _ioCounters; } }
            set { lock (_updateLock) { _ioCounters = value; } }
        }

        private ProcessSecurityInfo _securityInfo;
        public ProcessSecurityInfo SecurityInfo
        {
            get { lock (_updateLock) { return _securityInfo; } }
            set { lock (_updateLock) { _securityInfo = value; } }
        }

        private ProcessMitigationInfo _mitigationInfo;
        public ProcessMitigationInfo MitigationInfo
        {
            get { lock (_updateLock) { return _mitigationInfo; } }
            set { lock (_updateLock) { _mitigationInfo = value; } }
        }

        private ProcessSignatureInfo _signatureInfo;
        public ProcessSignatureInfo SignatureInfo
        {
            get { lock (_updateLock) { return _signatureInfo; } }
            set { lock (_updateLock) { _signatureInfo = value; } }
        }

        private string _fileCompany;
        public string FileCompany
        {
            get { lock (_updateLock) { return _fileCompany; } }
            set { lock (_updateLock) { _fileCompany = value; } }
        }

        private string _fileDescription;
        public string FileDescription
        {
            get { lock (_updateLock) { return _fileDescription; } }
            set { lock (_updateLock) { _fileDescription = value; } }
        }

        private string _fileVersion;
        public string FileVersion
        {
            get { lock (_updateLock) { return _fileVersion; } }
            set { lock (_updateLock) { _fileVersion = value; } }
        }


        private bool _isDebuggerAttached;
        public bool IsDebuggerAttached
        {
            get { lock (_updateLock) { return _isDebuggerAttached; } }
            set { lock (_updateLock) { _isDebuggerAttached = value; } }
        }

        private bool _isInJob;
        public bool IsInJob
        {
            get { lock (_updateLock) { return _isInJob; } }
            set { lock (_updateLock) { _isInJob = value; } }
        }

        private bool _isEcoMode;
        public bool IsEcoMode
        {
            get { lock (_updateLock) { return _isEcoMode; } }
            set { lock (_updateLock) { _isEcoMode = value; } }
        }

        private string _dpiAwareness;
        public string DpiAwareness
        {
            get { lock (_updateLock) { return _dpiAwareness; } }
            set { lock (_updateLock) { _dpiAwareness = value; } }
        }

        private bool _isImmersive;
        public bool IsImmersive
        {
            get { lock (_updateLock) { return _isImmersive; } }
            set { lock (_updateLock) { _isImmersive = value; } }
        }

        public volatile bool IsLoadingDetails;
        public volatile bool IsDetailsLoaded;

        private string _packageFullName;
        public string PackageFullName
        {
            get { lock (_updateLock) { return _packageFullName; } }
            set { lock (_updateLock) { _packageFullName = value; } }
        }

        public bool IsPackagedApp
        {
            get
            {
                lock (_updateLock)
                {
                    bool hasPackageName = !string.IsNullOrEmpty(_packageFullName) &&
                                          !_packageFullName.StartsWith("[") &&
                                          _packageFullName != "N/A";

                    bool isAppContainer = this.SecurityInfo.IsAppContainer;

                    return hasPackageName || isAppContainer;
                }
            }
        }

        public FullProcessInfo()
        {
            this._threadsList = new List<ThreadInfo>();
            this._securityInfo = new ProcessSecurityInfo();
            this._mitigationInfo = new ProcessMitigationInfo();
            this._signatureInfo = new ProcessSignatureInfo();
        }
        public FullProcessInfo(int pid, string name, long workingSet, uint threads, int priority)
        {
            this.Pid = pid;
            this._name = name;
            this._workingSet = workingSet;
            this._rawNumberOfThreads = threads;
            this._priority = priority;
            this._exePath = "[Loading...]";
            this._commandLine = "[Loading...]";
            this._threadsList = new List<ThreadInfo>();
            this._securityInfo = new ProcessSecurityInfo();
            this._mitigationInfo = new ProcessMitigationInfo();
            this._signatureInfo = new ProcessSignatureInfo();
            this._fileCompany = "[Loading...]";
            this._fileDescription = "[Loading...]";
            this._fileVersion = "[Loading...]";
            this._isDebuggerAttached = false;
            this._isInJob = false;
            this._isEcoMode = false;
            this._dpiAwareness = "[Loading...]";
            this._isImmersive = false;
            this._packageFullName = "[Loading...]";
        }

        public void UpdateFastData(string name, long workingSet, long pagedPool, long nonPagedPool, long privatePageCount, long pagefileUsage, uint threads, int priority, List<ThreadInfo> threadInfos)
        {
            lock (_updateLock)
            {
                this.Name = name;
                this.WorkingSetSize = workingSet;
                this.PagedPoolUsage = pagedPool;
                this.NonPagedPoolUsage = nonPagedPool;
                this.PrivatePageCount = privatePageCount;
                this.PagefileUsage = pagefileUsage;
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
                copy.SecurityInfo = this.SecurityInfo.Clone();
                copy.MitigationInfo = this.MitigationInfo.Clone();
                copy.SignatureInfo = this.SignatureInfo.Clone();
            }

            copy.Threads = this.Threads;
            return copy;
        }

        public void UpdateFastData(string name, long workingSet, long pagedPool, long nonPagedPool, long privatePageCount, long pagefileUsage, uint threads, int priority)
        {
            lock (_updateLock)
            {
                this.Name = name;
                this.WorkingSetSize = workingSet;
                this.PagedPoolUsage = pagedPool;
                this.NonPagedPoolUsage = nonPagedPool;
                this.PrivatePageCount = privatePageCount;
                this.PagefileUsage = pagefileUsage;
                this.NumberOfThreads = threads;
                this.BasePriority = priority;
            }
        }
    }
}