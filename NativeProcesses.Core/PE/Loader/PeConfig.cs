using System;
using System.Runtime.InteropServices;
using NativeProcesses.Core.PE;

namespace NativeProcesses.Core.PE.Loader
{
    public static class PeConfig
    {
        private const ushort IMAGE_GUARD_CF_INSTRUMENTED = 0x0100;
        private const ushort IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT = 0x0400;

        // Wir definieren nur den Teil der LoadConfig, den wir wirklich brauchen (Security Cookie + SEH)
        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_LOAD_CONFIG_DIRECTORY32_PARTIAL
        {
            public uint Size;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint GlobalFlagsClear;
            public uint GlobalFlagsSet;
            public uint CriticalSectionDefaultTimeout;
            public uint DeCommitFreeBlockThreshold;
            public uint DeCommitTotalFreeThreshold;
            public uint LockPrefixTable;
            public uint MaximumAllocationSize;
            public uint VirtualMemoryThreshold;
            public uint ProcessHeapFlags;
            public uint ProcessAffinityMask;
            public ushort CsdVersion;
            public ushort DependentLoadFlags;
            public uint EditList;
            public uint SecurityCookie; // <--- DAS WICHTIGSTE
            public uint SEHandlerTable;
            public uint SEHandlerCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_LOAD_CONFIG_DIRECTORY64_PARTIAL
        {
            public uint Size;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint GlobalFlagsClear;
            public uint GlobalFlagsSet;
            public uint CriticalSectionDefaultTimeout;
            public ulong DeCommitFreeBlockThreshold;
            public ulong DeCommitTotalFreeThreshold;
            public ulong LockPrefixTable;
            public ulong MaximumAllocationSize;
            public ulong VirtualMemoryThreshold;
            public ulong ProcessAffinityMask;
            public uint ProcessHeapFlags;
            public ushort CsdVersion;
            public ushort DependentLoadFlags;
            public ulong EditList;
            public ulong SecurityCookie; // <--- DAS WICHTIGSTE
            public ulong SEHandlerTable;
            public ulong SEHandlerCount;
        }

        public static bool InitSecurityCookie(IntPtr moduleBase)
        {
            try
            {
                int e_lfanew = Marshal.ReadInt32(moduleBase, 0x3C);
                IntPtr ntHeader = IntPtr.Add(moduleBase, e_lfanew);
                IntPtr optHeader = IntPtr.Add(ntHeader, 24);
                ushort magic = (ushort)Marshal.ReadInt16(optHeader);

                uint configRva = 0;
                // uint configSize = 0;

                if (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    // LoadConfig ist Index 10 (Offset 112 + 10*8 = 192)
                    configRva = (uint)Marshal.ReadInt32(optHeader, 192);
                }
                else
                {
                    // LoadConfig ist Index 10 (Offset 96 + 10*8 = 176)
                    configRva = (uint)Marshal.ReadInt32(optHeader, 176);
                }

                if (configRva == 0) return true; // Kein Config Dir

                IntPtr configPtr = IntPtr.Add(moduleBase, (int)configRva);

                // Security Cookie RVA lesen
                IntPtr cookiePtrAddr; // Hier steht die ADRESSE des Cookies (VA)

                if (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    var cfg64 = Marshal.PtrToStructure<IMAGE_LOAD_CONFIG_DIRECTORY64_PARTIAL>(configPtr);
                    cookiePtrAddr = (IntPtr)cfg64.SecurityCookie;
                }
                else
                {
                    var cfg32 = Marshal.PtrToStructure<IMAGE_LOAD_CONFIG_DIRECTORY32_PARTIAL>(configPtr);
                    cookiePtrAddr = (IntPtr)cfg32.SecurityCookie;
                }

                if (cookiePtrAddr == IntPtr.Zero) return true;

                // Standard-Cookie generieren (basierend auf Timestamp oder Random)
                // Windows nimmt meistens Systemzeit ^ PID ^ ThreadID
                // Wir nehmen einfach einen zufälligen Wert, solange er != Default ist.

                long defaultCookieVal = (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC) ? 0x00002B992DDFA232 : 0xBB40E64E;

                // Lesen was aktuell drin steht
                long currentVal;
                if (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                    currentVal = Marshal.ReadInt64(cookiePtrAddr);
                else
                    currentVal = Marshal.ReadInt32(cookiePtrAddr);

                // Wenn es der Default-Compiler-Wert ist, müssen wir ihn initialisieren
                if (currentVal == defaultCookieVal || currentVal == 0)
                {
                    long newCookie = DateTime.Now.Ticks; // Zufallswert
                    if (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                    {
                        newCookie &= 0x0000FFFFFFFFFFFF; // 48-bit meistens auf x64
                        if (newCookie == 0) newCookie = 0x1234567812345678;
                        Marshal.WriteInt64(cookiePtrAddr, newCookie);
                    }
                    else
                    {
                        Marshal.WriteInt32(cookiePtrAddr, (int)newCookie);
                    }
                }

                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}