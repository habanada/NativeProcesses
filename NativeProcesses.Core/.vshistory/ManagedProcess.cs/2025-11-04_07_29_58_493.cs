using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace NativeProcesses.Core
{
    public class ManagedProcess : IDisposable
    {
        public int Pid { get; private set; }
        public IntPtr Handle { get; private set; }

        private const uint STATUS_SUCCESS = 0x00000000;

        #region P/Invoke Kernel32
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(
            ProcessAccessFlags processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetPriorityClass(IntPtr hProcess, uint dwPriorityClass);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetPriorityClass(IntPtr hProcess, out uint dwPriorityClass);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int dwSize,
            out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryFullProcessImageName(
            IntPtr hProcess,
            uint dwFlags,
            [Out] StringBuilder lpExeName,
            ref uint lpdwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWow64Process(IntPtr hProcess, out bool Wow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle,
            TokenAccessFlags DesiredAccess, out IntPtr TokenHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessMitigationPolicy(
            IntPtr hProcess,
            PROCESS_MITIGATION_POLICY policy,
            IntPtr lpBuffer,
            int dwLength);
        #endregion

        #region P/Invoke Ntdll
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtSuspendProcess(IntPtr processHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtResumeProcess(IntPtr processHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            IntPtr processInformation,
            uint processInformationLength,
            out uint returnLength);
        #endregion

        #region P/Invoke Advapi32
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupAccountSid(
            string lpSystemName,
            IntPtr lpSid,
            StringBuilder lpName,
            ref uint cchName,
            StringBuilder lpReferencedDomainName,
            ref uint cchReferencedDomainName,
            out SID_NAME_USE peUse);
        #endregion

        #region Structs & Enums
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

        [Flags]
        private enum TokenAccessFlags : uint
        {
            Query = 0x0008,
        }

        private enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            MaxTokenInfoClass
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_MANDATORY_LABEL
        {
            public SID_AND_ATTRIBUTES Label;
        }

        private enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }

        private enum PROCESS_MITIGATION_POLICY
        {
            ProcessDEPPolicy = 0,
            ProcessASLRPolicy = 1,
            ProcessDynamicCodePolicy = 2,
            ProcessControlFlowGuardPolicy = 7,
            ProcessSystemCallDisablePolicy = 9,
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_MITIGATION_DEP_POLICY
        {
            public uint Flags;
            public bool Permanent;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_MITIGATION_ASLR_POLICY
        {
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_MITIGATION_DYNAMIC_CODE_POLICY
        {
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY
        {
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY
        {
            public uint Flags;
        }
        #endregion

        public ManagedProcess(int pid, ProcessAccessFlags access)
        {
            this.Pid = pid;
            this.Handle = OpenProcess(access, false, pid);
            if (this.Handle == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        #region Process Control
        public void Kill()
        {
            if (!TerminateProcess(this.Handle, 1))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        public void Suspend()
        {
            uint status = NtSuspendProcess(this.Handle);
            if (status != STATUS_SUCCESS)
            {
                throw new Win32Exception($"NtSuspendProcess failed with status: {status}");
            }
        }

        public void Resume()
        {
            uint status = NtResumeProcess(this.Handle);
            if (status != STATUS_SUCCESS)
            {
                throw new Win32Exception($"NtResumeProcess failed with status: {status}");
            }
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
        #endregion

        #region Memory
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
        #endregion

        #region Process Info (Fast)
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
        #endregion

        #region Process Info (Slow / New)

        public ProcessIoCounters GetIoCounters()
        {
            int size = Marshal.SizeOf(typeof(ProcessIoCounters));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (NtQueryInformationProcess(this.Handle, 4, buffer, (uint)size, out _) != 0)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "NtQueryInformationProcess(IoCounters) failed.");
                }
                return (ProcessIoCounters)Marshal.PtrToStructure(buffer, typeof(ProcessIoCounters));
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public bool GetIsWow64()
        {
            if (!Environment.Is64BitOperatingSystem)
            {
                return false;
            }
            if (!IsWow64Process(this.Handle, out bool isWow64))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "IsWow64Process failed.");
            }
            return isWow64;
        }

        public ProcessSecurityInfo GetSecurityInfo()
        {
            var info = new ProcessSecurityInfo();
            try
            {
                info.IsWow64 = GetIsWow64();
            }
            catch { }

            try
            {
                if (!OpenProcessToken(this.Handle, TokenAccessFlags.Query, out IntPtr tokenHandle))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed.");
                }

                try
                {
                    info.UserName = GetTokenUser(tokenHandle);
                    info.IntegrityLevel = GetTokenIntegrityLevel(tokenHandle);
                    info.IsElevated = GetTokenIsElevated(tokenHandle);
                }
                finally
                {
                    CloseHandle(tokenHandle);
                }
            }
            catch (Win32Exception)
            {
                info.UserName = "Access Denied";
                info.IntegrityLevel = "Access Denied";
            }
            return info;
        }

        private string GetTokenUser(IntPtr tokenHandle)
        {
            if (!GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, 0, out uint length))
            {
                if (Marshal.GetLastWin32Error() != 122)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetTokenInformation(TokenUser) length failed.");
            }

            IntPtr buffer = Marshal.AllocHGlobal((int)length);
            try
            {
                if (!GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenUser, buffer, length, out _))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetTokenInformation(TokenUser) failed.");
                }

                TOKEN_USER user = (TOKEN_USER)Marshal.PtrToStructure(buffer, typeof(TOKEN_USER));
                uint nameLen = 256, domainLen = 256;
                StringBuilder name = new StringBuilder((int)nameLen);
                StringBuilder domain = new StringBuilder((int)domainLen);
                if (LookupAccountSid(null, user.User.Sid, name, ref nameLen, domain, ref domainLen, out _))
                {
                    return $"{domain}\\{name}";
                }
                else
                {
                    if (ConvertSidToStringSid(user.User.Sid, out IntPtr stringSid))
                    {
                        string result = Marshal.PtrToStringAuto(stringSid);
                        Marshal.FreeHGlobal(stringSid);
                        return result;
                    }
                }
                return "Unknown";
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private string GetTokenIntegrityLevel(IntPtr tokenHandle)
        {
            if (!GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, IntPtr.Zero, 0, out uint length))
            {
                if (Marshal.GetLastWin32Error() != 122)
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "GetTokenInformation(TokenIntegrityLevel) length failed.");
            }

            IntPtr buffer = Marshal.AllocHGlobal((int)length);
            try
            {
                if (!GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, buffer, length, out _))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetTokenInformation(TokenIntegrityLevel) failed.");
                }

                TOKEN_MANDATORY_LABEL label = (TOKEN_MANDATORY_LABEL)Marshal.PtrToStructure(buffer, typeof(TOKEN_MANDATORY_LABEL));
                uint subAuthorityCount = (uint)Marshal.ReadByte(label.Label.Sid, 1);
                IntPtr subAuthority = (IntPtr)(label.Label.Sid.ToInt64() + 8 + (subAuthorityCount - 1) * 4);
                uint integrityLevel = (uint)Marshal.ReadInt32(subAuthority);

                if (integrityLevel < 0x1000) return "Untrusted";
                if (integrityLevel < 0x2000) return "Low";
                if (integrityLevel < 0x3000) return "Medium";
                if (integrityLevel < 0x4000) return "High";
                if (integrityLevel < 0x5000) return "System";
                return "Unknown";
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private bool GetTokenIsElevated(IntPtr tokenHandle)
        {
            if (!GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenElevation, IntPtr.Zero, 0, out uint length))
            {
                if (Marshal.GetLastWin32Error() != 122)
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "GetTokenInformation(TokenElevation) length failed.");
            }

            IntPtr buffer = Marshal.AllocHGlobal((int)length);
            try
            {
                if (!GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenElevation, buffer, length, out _))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetTokenInformation(TokenElevation) failed.");
                }
                return Marshal.ReadInt32(buffer) == 1;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public ProcessMitigationInfo GetMitigationInfo()
        {
            var info = new ProcessMitigationInfo();
            IntPtr buffer = IntPtr.Zero;

            try
            {
                buffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PROCESS_MITIGATION_DEP_POLICY)));
                if (GetProcessMitigationPolicy(this.Handle, PROCESS_MITIGATION_POLICY.ProcessDEPPolicy, buffer, Marshal.SizeOf(typeof(PROCESS_MITIGATION_DEP_POLICY))))
                {
                    var policy = (PROCESS_MITIGATION_DEP_POLICY)Marshal.PtrToStructure(buffer, typeof(PROCESS_MITIGATION_DEP_POLICY));
                    info.DepEnabled = (policy.Flags & 0x1) == 0x1;
                    info.DepAtlThunkEmulationDisabled = (policy.Flags & 0x2) == 0x2;
                }
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;

                buffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PROCESS_MITIGATION_ASLR_POLICY)));
                if (GetProcessMitigationPolicy(this.Handle, PROCESS_MITIGATION_POLICY.ProcessASLRPolicy, buffer, Marshal.SizeOf(typeof(PROCESS_MITIGATION_ASLR_POLICY))))
                {
                    var policy = (PROCESS_MITIGATION_ASLR_POLICY)Marshal.PtrToStructure(buffer, typeof(PROCESS_MITIGATION_ASLR_POLICY));
                    info.AslrEnabled = (policy.Flags & 0x1) == 0x1;
                    info.AslrForceRelocateImages = (policy.Flags & 0x4) == 0x4;
                }
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;

                buffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY)));
                if (GetProcessMitigationPolicy(this.Handle, PROCESS_MITIGATION_POLICY.ProcessControlFlowGuardPolicy, buffer, Marshal.SizeOf(typeof(PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY))))
                {
                    var policy = (PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY)Marshal.PtrToStructure(buffer, typeof(PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY));
                    info.CfgEnabled = (policy.Flags & 0x1) == 0x1;
                }
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;

                buffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PROCESS_MITIGATION_DYNAMIC_CODE_POLICY)));
                if (GetProcessMitigationPolicy(this.Handle, PROCESS_MITIGATION_POLICY.ProcessDynamicCodePolicy, buffer, Marshal.SizeOf(typeof(PROCESS_MITIGATION_DYNAMIC_CODE_POLICY))))
                {
                    var policy = (PROCESS_MITIGATION_DYNAMIC_CODE_POLICY)Marshal.PtrToStructure(buffer, typeof(PROCESS_MITIGATION_DYNAMIC_CODE_POLICY));
                    info.DynamicCodeProhibited = (policy.Flags & 0x1) == 0x1;
                }
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;

                buffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY)));
                if (GetProcessMitigationPolicy(this.Handle, PROCESS_MITIGATION_POLICY.ProcessSystemCallDisablePolicy, buffer, Marshal.SizeOf(typeof(PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY))))
                {
                    var policy = (PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY)Marshal.PtrToStructure(buffer, typeof(PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY));
                    info.Win32kSystemCallsDisabled = (policy.Flags & 0x1) == 0x1;
                }
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }
            catch
            {
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            return info;
        }

        #endregion

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