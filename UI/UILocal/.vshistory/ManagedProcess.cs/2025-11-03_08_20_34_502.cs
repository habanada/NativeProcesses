using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
namespace NativeProcesses
{
    public class ManagedProcess : IDisposable
    {
        public int Pid { get; private set; }
        public IntPtr Handle { get; private set; }
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(
            ProcessAccessFlags processAccess,
            bool bInheritHandle,
            int processId);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetPriorityClass(IntPtr hProcess, uint dwPriorityClass);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetPriorityClass(IntPtr hProcess, out uint dwPriorityClass);
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtSuspendProcess(IntPtr processHandle);
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtResumeProcess(IntPtr processHandle);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out int lpNumberOfBytesRead);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int dwSize,
            out int lpNumberOfBytesWritten);
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            IntPtr processInformation,
            uint processInformationLength,
            out uint returnLength);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryFullProcessImageName(
            IntPtr hProcess,
            uint dwFlags,
            [Out] StringBuilder lpExeName,
            ref uint lpdwSize);
        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr Reserved3;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }
        public ManagedProcess(int pid, ProcessAccessFlags access)
        {
            this.Pid = pid;
            this.Handle = OpenProcess(access, false, pid);
            if (this.Handle == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        public void Kill()
        {
            if (!TerminateProcess(this.Handle, 1))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        public void Suspend()
        {
            NtSuspendProcess(this.Handle);
        }
        public void Resume()
        {
            NtResumeProcess(this.Handle);
        }
        public void SetPriority(ProcessManager.PriorityClass priority)
        {
            if (!SetPriorityClass(this.Handle, (uint)priority))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        public ProcessManager.PriorityClass GetPriority()
        {
            if (!GetPriorityClass(this.Handle, out uint priority))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return (ProcessManager.PriorityClass)priority;
        }
        public byte[] ReadMemory(IntPtr address, int size)
        {
            byte[] buffer = new byte[size];
            if (!ReadProcessMemory(this.Handle, address, buffer, size, out int bytesRead) || bytesRead != size)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not read process memory.");
            }
            return buffer;
        }
        public void WriteMemory(IntPtr address, byte[] data)
        {
            if (!WriteProcessMemory(this.Handle, address, data, data.Length, out int bytesWritten) || bytesWritten != data.Length)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not write process memory.");
            }
        }
        public string GetCommandLine()
        {
            IntPtr pbiPtr = IntPtr.Zero;
            IntPtr pebPtr = IntPtr.Zero;
            IntPtr rtlUserProcParamsPtr = IntPtr.Zero;
            try
            {
                uint size = (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
                pbiPtr = Marshal.AllocHGlobal((int)size);
                if (NtQueryInformationProcess(this.Handle, 0, pbiPtr, size, out _) != 0)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "NtQueryInformationProcess failed.");
                }
                PROCESS_BASIC_INFORMATION pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pbiPtr, typeof(PROCESS_BASIC_INFORMATION));
                pebPtr = pbi.PebBaseAddress;
                IntPtr rtlUserProcParamsPtrAddress = pebPtr + (IntPtr.Size == 8 ? 0x20 : 0x10);
                byte[] rtlUserProcParamsPtrBytes = ReadMemory(rtlUserProcParamsPtrAddress, IntPtr.Size);
                rtlUserProcParamsPtr = IntPtr.Size == 8 ? (IntPtr)BitConverter.ToInt64(rtlUserProcParamsPtrBytes, 0) : (IntPtr)BitConverter.ToInt32(rtlUserProcParamsPtrBytes, 0);
                IntPtr cmdLineAddress = rtlUserProcParamsPtr + (IntPtr.Size == 8 ? 0x70 : 0x40);
                byte[] cmdLineBytes = ReadMemory(cmdLineAddress, Marshal.SizeOf(typeof(UNICODE_STRING)));
                UNICODE_STRING cmdLineUnicodeString = (UNICODE_STRING)Marshal.PtrToStructure(Marshal.UnsafeAddrOfPinnedArrayElement(cmdLineBytes, 0), typeof(UNICODE_STRING));
                if (cmdLineUnicodeString.Length == 0)
                {
                    return "";
                }
                byte[] cmdLineStringBytes = ReadMemory(cmdLineUnicodeString.Buffer, cmdLineUnicodeString.Length);
                return Encoding.Unicode.GetString(cmdLineStringBytes);
            }
            finally
            {
                if (pbiPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pbiPtr);
                }
            }
        }
        public string GetExePath()
        {
            uint size = 1024;
            StringBuilder sb = new StringBuilder((int)size);
            if (!QueryFullProcessImageName(this.Handle, 0, sb, ref size))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryFullProcessImageName failed.");
            }
            return sb.ToString();
        }
        public void Dispose()
        {
            if (this.Handle != IntPtr.Zero)
            {
                CloseHandle(this.Handle);
                this.Handle = IntPtr.Zero;
            }
        }
    }
}
