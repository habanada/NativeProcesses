using System;
using System.Runtime.InteropServices;
using NativeProcesses.Core.PE;

namespace NativeProcesses.Core.PE.Loader
{
    public static class PeTls
    {
        // PfnDllMain-Signatur für TLS Callbacks
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void TlsCallbackDelegate(IntPtr DllHandle, uint Reason, IntPtr Reserved);

        private const uint DLL_PROCESS_ATTACH = 1;

        // 1 = DLL_PROCESS_ATTACH (Default)
        public static bool ExecuteTlsCallbacks(IntPtr moduleBase, uint reason = 1)
        {
            if (moduleBase == IntPtr.Zero) return false;

            try
            {
                // Header navigieren
                int e_lfanew = Marshal.ReadInt32(moduleBase, 0x3C);
                IntPtr ntHeader = IntPtr.Add(moduleBase, e_lfanew);
                IntPtr optHeader = IntPtr.Add(ntHeader, 24);
                ushort magic = (ushort)Marshal.ReadInt16(optHeader);

                uint tlsRva = 0;

                if (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    // TLS Directory ist Index 9 (Offset 112 + 9*8 = 184)
                    tlsRva = (uint)Marshal.ReadInt32(optHeader, 184);
                }
                else
                {
                    // TLS Directory ist Index 9 (Offset 96 + 9*8 = 168)
                    tlsRva = (uint)Marshal.ReadInt32(optHeader, 168);
                }

                if (tlsRva == 0) return true; // Keine TLS Callbacks -> Success

                IntPtr tlsDirPtr = IntPtr.Add(moduleBase, (int)tlsRva);
                IntPtr callBacksPtrAddr; // Adresse, an der der Pointer auf das Callback-Array steht

                if (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    var tls64 = Marshal.PtrToStructure<PeHeaders.IMAGE_TLS_DIRECTORY64>(tlsDirPtr);
                    callBacksPtrAddr = (IntPtr)tls64.AddressOfCallBacks;
                }
                else
                {
                    var tls32 = Marshal.PtrToStructure<PeHeaders.IMAGE_TLS_DIRECTORY32>(tlsDirPtr);
                    callBacksPtrAddr = (IntPtr)tls32.AddressOfCallBacks;
                }

                if (callBacksPtrAddr == IntPtr.Zero) return true;

                // Wir iterieren durch das null-terminierte Array von Function Pointers
                int ptrSize = (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC) ? 8 : 4;
                int index = 0;

                while (true)
                {
                    IntPtr callbackFuncPtr;

                    if (ptrSize == 8)
                    {
                        long val = Marshal.ReadInt64(callBacksPtrAddr, index * ptrSize);
                        if (val == 0) break;
                        callbackFuncPtr = (IntPtr)val;
                    }
                    else
                    {
                        int val = Marshal.ReadInt32(callBacksPtrAddr, index * ptrSize);
                        if (val == 0) break;
                        callbackFuncPtr = (IntPtr)val;
                    }

                    // Callback ausführen
                    var callback = Marshal.GetDelegateForFunctionPointer<TlsCallbackDelegate>(callbackFuncPtr);

                    // Nutzung von 'reason' statt Hardcoded Constant
                    callback(moduleBase, reason, IntPtr.Zero);

                    index++;
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