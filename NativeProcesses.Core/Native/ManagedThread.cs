/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace NativeProcesses.Core.Native
{
    public class ManagedThread : IDisposable
    {
        private const uint STATUS_SUCCESS = 0x00000000;

        [Flags]
        public enum ThreadAccessFlags : uint
        {
            Terminate = 0x0001,
            SuspendResume = 0x0002,
            GetContext = 0x0008,
            SetContext = 0x0010,
            SetInformation = 0x0020,
            QueryInformation = 0x0040,
            SetThreadToken = 0x0080,
            Impersonate = 0x0100,
            DirectImpersonation = 0x0200,
            All = 0x1F03FF
        }

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtSuspendThread(IntPtr threadHandle, out uint previousSuspendCount);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtResumeThread(IntPtr threadHandle, out uint previousSuspendCount);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(ThreadAccessFlags dwDesiredAccess, bool bInheritHandle, int dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationThread(
            IntPtr ThreadHandle,
            int ThreadInformationClass,
            IntPtr ThreadInformation,
            uint ThreadInformationLength,
            out uint ReturnLength);

        private const int ThreadIoPriority = 33;
        private const int ThreadPagePriority = 39;

        public IntPtr Handle { get; private set; }
        public int ThreadId { get; private set; }

        public ManagedThread(int threadId, ThreadAccessFlags access)
        {
            this.ThreadId = threadId;
            this.Handle = OpenThread(access, false, threadId);
            if (this.Handle == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to open thread.");
            }
        }

        public void Suspend()
        {
            uint status = NtSuspendThread(this.Handle, out _);
            if (status != STATUS_SUCCESS)
            {
                throw new Win32Exception($"NtSuspendThread failed with status: {status}");
            }
        }

        public void Resume()
        {
            uint status = NtResumeThread(this.Handle, out _);
            if (status != STATUS_SUCCESS)
            {
                throw new Win32Exception($"NtResumeThread failed with status: {status}");
            }
        }

        public void Dispose()
        {
            if (this.Handle != IntPtr.Zero)
            {
                CloseHandle(this.Handle);
                this.Handle = IntPtr.Zero;
            }
        }
        public void GetExtendedPriorities(out Models.IoPriorityHint ioPriority, out Models.MemoryPriorityHint memPriority)
        {
            ioPriority = Models.IoPriorityHint.Unknown;
            memPriority = Models.MemoryPriorityHint.Unknown;

            IntPtr buffer = IntPtr.Zero;
            try
            {
                uint returnLength;
                int size = sizeof(int);
                buffer = Marshal.AllocHGlobal(size);

                int statusIo = NtQueryInformationThread(this.Handle, ThreadIoPriority, buffer, (uint)size, out returnLength);
                if (statusIo == 0)
                {
                    ioPriority = (Models.IoPriorityHint)Marshal.ReadInt32(buffer);
                }

                int statusMem = NtQueryInformationThread(this.Handle, ThreadPagePriority, buffer, (uint)size, out returnLength);
                if (statusMem == 0)
                {
                    memPriority = (Models.MemoryPriorityHint)Marshal.ReadInt32(buffer);
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }
    }
}