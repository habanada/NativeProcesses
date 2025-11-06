?using System.ComponentModel;
using System.Runtime.CompilerServices;
public class FullProcessInfo : INotifyPropertyChanged
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
    public volatile bool IsLoadingDetails;
    public volatile bool IsDetailsLoaded;
    public FullProcessInfo(int pid, string name, long workingSet, uint threads, int priority)
    {
        this.Pid = pid;
        this._name = name;
        this._workingSet = workingSet;
        this._threads = threads;
        this._priority = priority;
        this._exePath = "[L�dt...]";
        this._commandLine = "[L�dt...]";
    }
    public void UpdateFastData(string name, long workingSet, uint threads, int priority)
    {
        this.Name = name;
        this.WorkingSetSize = workingSet;
        this.NumberOfThreads = threads;
        this.BasePriority = priority;
    }
}
