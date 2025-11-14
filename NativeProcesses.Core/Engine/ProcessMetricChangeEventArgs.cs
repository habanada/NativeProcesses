using System;

namespace NativeProcesses.Core.Engine
{
    public class ProcessMetricChangeEventArgs : EventArgs
    {
        public int Pid { get; }
        public ProcessMetric Metric { get; }
        public object OldValue { get; }
        public object NewValue { get; }

        public ProcessMetricChangeEventArgs(int pid, ProcessMetric metric, object oldValue, object newValue)
        {
            Pid = pid;
            Metric = metric;
            OldValue = oldValue;
            NewValue = newValue;
        }
    }
}