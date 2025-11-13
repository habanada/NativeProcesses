/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System.ComponentModel;
using System.Runtime.CompilerServices;
using NativeProcesses.Core;
using System.Collections.Generic;
using System.Linq;
using NativeProcesses.Network;

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


        private long _totalReadOps;
        public long TotalReadOps
        {
            get { return _totalReadOps; }
            set { _totalReadOps = value; Notify(); }
        }

        private long _totalWriteOps;
        public long TotalWriteOps
        {
            get { return _totalWriteOps; }
            set { _totalWriteOps = value; Notify(); }
        }

        private long _totalPageFaults;
        public long TotalPageFaults
        {
            get { return _totalPageFaults; }
            set { _totalPageFaults = value; Notify(); }
        }

        private long _pagedPool;
        public long PagedPoolUsage
        {
            get { return _pagedPool; }
            set { _pagedPool = value; Notify(); }
        }

        private long _nonPagedPool;
        public long NonPagedPoolUsage
        {
            get { return _nonPagedPool; }
            set { _nonPagedPool = value; Notify(); }
        }

        private long _privatePageCount;
        public long PrivatePageCount
        {
            get { return _privatePageCount; }
            set { _privatePageCount = value; Notify(); }
        }

        private long _pagefileUsage;
        public long PagefileUsage
        {
            get { return _pagefileUsage; }
            set { _pagefileUsage = value; Notify(); }
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

        private bool _depEnabled;
        public bool DepEnabled
        {
            get { return _depEnabled; }
            set { _depEnabled = value; Notify(); }
        }

        private bool _aslrEnabled;
        public bool AslrEnabled
        {
            get { return _aslrEnabled; }
            set { _aslrEnabled = value; Notify(); }
        }

        private bool _cfgEnabled;
        public bool CfgEnabled
        {
            get { return _cfgEnabled; }
            set { _cfgEnabled = value; Notify(); }
        }

        private bool _dynamicCodeProhibited;
        public bool DynamicCodeProhibited
        {
            get { return _dynamicCodeProhibited; }
            set { _dynamicCodeProhibited = value; Notify(); }
        }

        private bool _win32kDisabled;
        public bool Win32kSystemCallsDisabled
        {
            get { return _win32kDisabled; }
            set { _win32kDisabled = value; Notify(); }
        }

        private bool _isSigned;
        public bool IsSigned
        {
            get { return _isSigned; }
            set { _isSigned = value; Notify(); }
        }

        private string _signerName;
        public string SignerName
        {
            get { return _signerName; }
            set { _signerName = value; Notify(); }
        }


        private bool _isDebuggerAttached;
        public bool IsDebuggerAttached
        {
            get { return _isDebuggerAttached; }
            set { _isDebuggerAttached = value; Notify(); }
        }

        private bool _isInJob;
        public bool IsInJob
        {
            get { return _isInJob; }
            set { _isInJob = value; Notify(); }
        }

        private bool _isEcoMode;
        public bool IsEcoMode
        {
            get { return _isEcoMode; }
            set { _isEcoMode = value; Notify(); }
        }
        private ulong _ioOther;
        public ulong IoOther
        {
            get { return _ioOther; }
            set { _ioOther = value; Notify(); }
        }
        private string _dpiAwareness;
        public string DpiAwareness
        {
            get { return _dpiAwareness; }
            set { _dpiAwareness = value; Notify(); }
        }

        private bool _isImmersive;
        public bool IsImmersive
        {
            get { return _isImmersive; }
            set { _isImmersive = value; Notify(); }
        }
        private string _packageFullName;
        public string PackageFullName
        {
            get { return _packageFullName; }
            set { _packageFullName = value; Notify(); }
        }

        public bool IsPackagedApp { get; private set; }
        private bool _isAppContainer;
        public bool IsAppContainer
        {
            get { return _isAppContainer; }
            set { _isAppContainer = value; Notify(); }
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
            this.ExePath = source.ExePath;
            this.CommandLine = source.CommandLine;
            this.IsDebuggerAttached = source.IsDebuggerAttached;
            this.IsInJob = source.IsInJob;
            this.IsEcoMode = source.IsEcoMode;


            ApplyVolatileValues(
                source.CpuUsagePercent,
                source.WorkingSetSize,
                source.NumberOfThreads,
                source.BasePriority,
                source.TotalReadBytes,
                source.TotalWriteBytes,
                source.TotalReadOps,
                source.TotalWriteOps,
                source.TotalPageFaults,
                source.PagedPoolUsage,
                source.NonPagedPoolUsage,
                source.PrivatePageCount,
                source.PagefileUsage
            );

            this.DpiAwareness = source.DpiAwareness;
            this.IsImmersive = source.IsImmersive;

            this.PackageFullName = source.PackageFullName;
            this.IsPackagedApp = source.IsPackagedApp;
            this.IsAppContainer = source.SecurityInfo.IsAppContainer;

            this.UserName = source.SecurityInfo.UserName;
            this.IntegrityLevel = source.SecurityInfo.IntegrityLevel;
            this.ImageType = source.SecurityInfo.ImageType;
            this.IsElevated = source.SecurityInfo.IsElevated;

            this.FileCompany = source.FileCompany;
            this.FileDescription = source.FileDescription;
            this.FileVersion = source.FileVersion;
            this.IoReads = source.IoCounters.ReadOperationCount;
            this.IoWrites = source.IoCounters.WriteOperationCount;
            this.IoOther = source.IoCounters.OtherOperationCount;

            this.DepEnabled = source.MitigationInfo.DepEnabled;
            this.AslrEnabled = source.MitigationInfo.AslrEnabled;
            this.CfgEnabled = source.MitigationInfo.CfgEnabled;
            this.DynamicCodeProhibited = source.MitigationInfo.DynamicCodeProhibited;
            this.Win32kSystemCallsDisabled = source.MitigationInfo.Win32kSystemCallsDisabled;

            this.IsSigned = source.SignatureInfo.IsSigned;
            if (this.IsSigned)
            {
                if (source.SignatureInfo.SignerName.StartsWith("N/A"))
                {
                    this.SignerName = "Signed (Catalog)";
                }
                else
                {
                    this.SignerName = source.SignatureInfo.SignerName;
                }
            }
            else
            {
                this.SignerName = source.SignatureInfo.ErrorMessage;
            }

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
        public void ApplyVolatileUpdate(ProcessVolatileUpdate update)
        {
            ApplyVolatileValues(
                update.Cpu,
                update.WorkingSet,
                (uint)update.ThreadCount,
                update.BasePriority,
                update.TotalReadBytes,
                update.TotalWriteBytes,
                update.TotalReadOps,
                update.TotalWriteOps,
                update.TotalPageFaults,
                update.PagedPool,
                update.NonPagedPool,
                update.PrivatePageCount,
                update.PagefileUsage
            );
        }

        private void ApplyVolatileValues(double cpu, long workingSet, uint threads, int priority, long reads, long writes, long readOps, long writeOps, long pageFaults, long pagedPool, long nonPagedPool, long privatePages, long pagefile)
        {
            this.CpuUsagePercent = cpu;
            this.WorkingSetSize = workingSet;
            this.NumberOfThreads = threads;
            this.BasePriority = priority;
            this.TotalReadBytes = reads;
            this.TotalWriteBytes = writes;
            this.TotalReadOps = readOps;
            this.TotalWriteOps = writeOps;
            this.TotalPageFaults = pageFaults;
            this.PagedPoolUsage = pagedPool;
            this.NonPagedPoolUsage = nonPagedPool;
            this.PrivatePageCount = privatePages;
            this.PagefileUsage = pagefile;
        }
    }
}