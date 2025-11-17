/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System.Collections.Generic;

namespace NativeProcesses.Core.Models
{
    public class DotNetLockInfo
    {
        public ulong LockAddress { get; set; }
        public string ObjectType { get; set; }
        public int OwningThreadId { get; set; }
        public int WaitingThreadCount { get; set; }

        public bool IsDeadlockCandidate
        {
            get
            {
                return OwningThreadId != -1 && WaitingThreadCount > 0;
            }
        }

        public DotNetLockInfo()
        {
            this.WaitingThreadCount = 0;
            this.OwningThreadId = -1;
        }
    }
}