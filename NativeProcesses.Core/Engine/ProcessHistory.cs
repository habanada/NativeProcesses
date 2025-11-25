/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace NativeProcesses.Core.Engine
{
    public class ProcessHistory
    {
        // Ring-Buffer pro PID (z.B. max 100 Events)
        private readonly ConcurrentDictionary<int, ConcurrentQueue<BehaviorEvent>> _history
            = new ConcurrentDictionary<int, ConcurrentQueue<BehaviorEvent>>();

        private const int MaxHistoryPerPid = 200;

        public void AddEvent(int pid, BehaviorEvent evt)
        {
            var queue = _history.GetOrAdd(pid, p => new ConcurrentQueue<BehaviorEvent>());

            queue.Enqueue(evt);

            // Cleanup wenn zu voll (einfacher Ring-Buffer)
            if (queue.Count > MaxHistoryPerPid)
            {
                queue.TryDequeue(out _);
            }
        }

        public void RemoveProcess(int pid)
        {
            _history.TryRemove(pid, out _);
        }

        public List<BehaviorEvent> GetEvents(int pid)
        {
            if (_history.TryGetValue(pid, out var queue))
            {
                return queue.ToList();
            }
            return new List<BehaviorEvent>();
        }
    }
}