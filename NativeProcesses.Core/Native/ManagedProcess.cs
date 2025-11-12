using NativeProcesses.Core.Engine;
using NativeProcesses.Core.Models;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NativeProcesses.Core.Native
{
    public class ManagedProcess : IDisposable
    {
        public int Pid { get; private set; }
        public IntPtr Handle { get; private set; }

        private const uint STATUS_SUCCESS = 0x00000000;

        private const int ProcessJobObjectInformation = 7;
        private const int ProcessDebugObjectHandle = 30;
        private const int ProcessPowerThrottlingState = 45;


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

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern uint QueryDosDevice(
            string lpDeviceName,
            [Out] StringBuilder lpTargetPath,
            int ucchMax);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetLogicalDriveStrings(
            uint nBufferLength,
            [Out] char[] lpBuffer);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            int MemoryInformationClass,
            IntPtr MemoryInformation,
            UIntPtr MemoryInformationLength,
            out UIntPtr ReturnLength);
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

        #region P/Invoke User32 & Shcore
        [DllImport("shcore.dll", SetLastError = true)]
        private static extern int GetProcessDpiAwareness(IntPtr hprocess, out PROCESS_DPI_AWARENESS value);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessUIContextInformation(IntPtr hProcess, ref UICONTEXT_INFORMATION pContextInfo);

        private const uint UICONTEXT_IMMERSIVE = 0x1;
        #endregion

        #region Structs & Enums
        private enum PROCESS_DPI_AWARENESS
        {
            PROCESS_DPI_UNAWARE = 0,
            PROCESS_SYSTEM_DPI_AWARE = 1,
            PROCESS_PER_MONITOR_DPI_AWARE = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UICONTEXT_INFORMATION
        {
            public uint dwFlags;
            public uint dwContext;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_POWER_THROTTLING_STATE
        {
            public uint Version;
            public uint ControlMask;
            public uint StateMask;
        }

        private const uint POWER_THROTTLING_PROCESS_ENFORCE = 0x1;

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
        private enum MEMORY_INFORMATION_CLASS
        {
            MemoryBasicInformation = 0
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public ushort PartitionId;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [Flags]
        public enum MemoryState : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_RESERVE = 0x2000,
            MEM_FREE = 0x10000
        }

        [Flags]
        public enum MemoryType : uint
        {
            MEM_PRIVATE = 0x20000,
            MEM_MAPPED = 0x40000,
            MEM_IMAGE = 0x1000000
        }

        [Flags]
        public enum MemoryProtect : uint
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400
        }
        #endregion

        #region Pfadkonvertierung
        private static readonly object _deviceMapLock = new object();
        private static Dictionary<string, string> _deviceMap;

        private static void EnsureDeviceMap()
        {
            lock (_deviceMapLock)
            {
                if (_deviceMap != null)
                {
                    return;
                }

                _deviceMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                char[] driveBuffer = new char[256];
                if (GetLogicalDriveStrings(256, driveBuffer) == 0)
                {
                    return;
                }

                foreach (var drive in new string(driveBuffer).Split(new[] { '\0' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    string driveLetter = drive.Substring(0, 2);
                    StringBuilder targetPath = new StringBuilder(1024);
                    if (QueryDosDevice(driveLetter, targetPath, 1024) != 0)
                    {
                        _deviceMap[targetPath.ToString()] = driveLetter;
                    }
                }
            }
        }

        private string ConvertNtPathToWin32Path(string ntPath)
        {
            EnsureDeviceMap();

            lock (_deviceMapLock)
            {
                foreach (var kvp in _deviceMap)
                {
                    if (ntPath.StartsWith(kvp.Key, StringComparison.OrdinalIgnoreCase))
                    {
                        return kvp.Value + ntPath.Substring(kvp.Key.Length);
                    }
                }
            }

            if (ntPath.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase))
            {
                return Environment.ExpandEnvironmentVariables("%SystemRoot%") + ntPath.Substring(11);
            }

            return ntPath;
        }
        #endregion
        #region Construktor and Dispose
        public ManagedProcess(int pid, ProcessAccessFlags access)
        {
            this.Pid = pid;
            this.Handle = OpenProcess(access, false, pid);
            if (this.Handle == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
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
        #endregion
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
        public void GetDpiAndUIContextInfo(out string dpiAwareness, out bool isImmersive)
        {
            dpiAwareness = "Unknown";
            isImmersive = false;

            try
            {
                int result = GetProcessDpiAwareness(this.Handle, out PROCESS_DPI_AWARENESS dpiValue);
                if (result == 0)
                {
                    dpiAwareness = dpiValue.ToString();
                }
                else
                {
                    dpiAwareness = new Win32Exception(result).Message;
                }
            }
            catch (Exception ex)
            {
                dpiAwareness = ex.Message;
            }

            try
            {
                var contextInfo = new UICONTEXT_INFORMATION();
                if (GetProcessUIContextInformation(this.Handle, ref contextInfo))
                {
                    if ((contextInfo.dwFlags & UICONTEXT_IMMERSIVE) == UICONTEXT_IMMERSIVE)
                    {
                        isImmersive = true;
                    }
                }
            }
            catch (Exception)
            {
            }
        }
        public void GetExtendedStatusFlags(out bool isDebuggerAttached, out bool isInJob, out bool isEcoMode)
        {
            isDebuggerAttached = false;
            isInJob = false;
            isEcoMode = false;

            IntPtr buffer = IntPtr.Zero;
            try
            {
                uint returnLength;

                buffer = Marshal.AllocHGlobal(IntPtr.Size);

                int statusJob = NtQueryInformationProcess(this.Handle, ProcessJobObjectInformation, buffer, (uint)IntPtr.Size, out returnLength);
                if (statusJob == 0 && Marshal.ReadIntPtr(buffer) != IntPtr.Zero)
                {
                    isInJob = true;
                }

                int statusDebug = NtQueryInformationProcess(this.Handle, ProcessDebugObjectHandle, buffer, (uint)IntPtr.Size, out returnLength);
                if (statusDebug == 0 && Marshal.ReadIntPtr(buffer) != IntPtr.Zero)
                {
                    isDebuggerAttached = true;
                }

                Marshal.FreeHGlobal(buffer);

                int size = Marshal.SizeOf(typeof(PROCESS_POWER_THROTTLING_STATE));
                buffer = Marshal.AllocHGlobal(size);
                int statusPower = NtQueryInformationProcess(this.Handle, ProcessPowerThrottlingState, buffer, (uint)size, out returnLength);
                if (statusPower == 0)
                {
                    PROCESS_POWER_THROTTLING_STATE state = (PROCESS_POWER_THROTTLING_STATE)Marshal.PtrToStructure(buffer, typeof(PROCESS_POWER_THROTTLING_STATE));
                    if ((state.ControlMask & POWER_THROTTLING_PROCESS_ENFORCE) == POWER_THROTTLING_PROCESS_ENFORCE)
                    {
                        isEcoMode = true;
                    }
                }
            }
            catch (Exception)
            {
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }
        public List<ProcessModuleInfo> GetLoadedModules(IEngineLogger logger)
        {
            try
            {
                var modules = PebModuleEnumerator.GetModules(this);
                for (int i = 0; i < modules.Count; i++)
                {
                    var mod = modules[i];
                    mod.FullDllName = ConvertNtPathToWin32Path(mod.FullDllName);
                    modules[i] = mod;
                }
                return modules;
            }
            catch (Exception ex)
            {
                logger?.Log(LogLevel.Debug, $"PEB module enumeration failed for PID {this.Pid}. Falling back to PSAPI.", ex);
                try
                {
                    return PsApiModuleEnumerator.GetModules(this);
                }
                catch (Exception ex2)
                {
                    logger?.Log(LogLevel.Error, $"PSAPI module enumeration failed for PID {this.Pid}.", ex2);
                    throw new Win32Exception($"Failed to enumerate modules with both PEB and PSAPI for PID {this.Pid}. Primary error: {ex.Message}", ex2);
                }
            }
        }

        public List<NativeHandleInfo> GetOpenHandles(IEngineLogger logger)
        {
            try
            {
                var lister = new NativeHandleLister(logger);
                var handles = lister.GetProcessHandles(this.Pid);
                for (int i = 0; i < handles.Count; i++)
                {
                    var h = handles[i];
                    if (!string.IsNullOrEmpty(h.Name))
                    {
                        h.Name = ConvertNtPathToWin32Path(h.Name);
                        handles[i] = h;
                    }
                }
                return handles;
            }
            catch (Exception ex)
            {
                logger?.Log(LogLevel.Debug, $"Failed to enumerate handles for PID {this.Pid}.", ex);
                throw;
            }
        }

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
        public List<Models.VirtualMemoryRegion> GetVirtualMemoryRegions()
        {
            var regions = new List<Models.VirtualMemoryRegion>();
            long currentAddress = 0;
            long maxAddress = Environment.Is64BitProcess ? 0x7FFFFFFFFFFF : 0x7FFFFFFF;

            IntPtr buffer = IntPtr.Zero;
            try
            {
                int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
                buffer = Marshal.AllocHGlobal(mbiSize);

                while (currentAddress < maxAddress)
                {
                    int status = NtQueryVirtualMemory(
                        this.Handle,
                        (IntPtr)currentAddress,
                        (int)MEMORY_INFORMATION_CLASS.MemoryBasicInformation,
                        buffer,
                        (UIntPtr)mbiSize,
                        out UIntPtr returnLength
                    );

                    if (status != 0)
                    {
                        break;
                    }

                    MEMORY_BASIC_INFORMATION mbi = (MEMORY_BASIC_INFORMATION)Marshal.PtrToStructure(buffer, typeof(MEMORY_BASIC_INFORMATION));

                    if ((long)mbi.RegionSize == 0)
                    {
                        break;
                    }

                    regions.Add(new Models.VirtualMemoryRegion(
                        mbi.BaseAddress,
                        mbi.AllocationBase,
                        (long)mbi.RegionSize,
                        mbi.State,
                        mbi.Type,
                        mbi.Protect,
                        mbi.AllocationProtect
                    ));

                    currentAddress = (long)mbi.BaseAddress + (long)mbi.RegionSize;

                    if (currentAddress < 0)
                    {
                        break;
                    }
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            return regions;
        }
        #endregion


    }
}
