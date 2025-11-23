using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace NativeProcesses.Core.Native
{
    public static class ManagedProcessExtensions
    {
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        public static IntPtr AllocateMemory(this ManagedProcess process, int size, IntPtr preferredAddress = default)
        {
            IntPtr addr = VirtualAllocEx(process.Handle, preferredAddress, (UIntPtr)size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (addr == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"VirtualAllocEx failed in PID {process.Pid}");
            }
            return addr;
        }

        public static void WriteMemory(this ManagedProcess process, IntPtr address, byte[] data)
        {
            if (!WriteProcessMemory(process.Handle, address, data, data.Length, out IntPtr written) || (int)written != data.Length)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"WriteProcessMemory failed at 0x{address.ToString("X")} in PID {process.Pid}");
            }
        }

        public static IntPtr StartRemoteThread(this ManagedProcess process, IntPtr startAddress, IntPtr parameter = default)
        {
            IntPtr hThread = CreateRemoteThread(process.Handle, IntPtr.Zero, 0, startAddress, parameter, 0, out _);
            if (hThread == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"CreateRemoteThread failed in PID {process.Pid}");
            }
            return hThread;
        }
    }
}