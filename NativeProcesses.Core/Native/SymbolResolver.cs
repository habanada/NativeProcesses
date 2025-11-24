/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace NativeProcesses.Core.Native
{
    public class SymbolResolver : IDisposable
    {
        private IntPtr _hProcess;
        private bool _initialized;
        private static readonly object _lock = new object();

        private const uint SYMOPT_UNDNAME = 0x00000002;
        private const uint SYMOPT_DEFERRED_LOADS = 0x00000004;
        private const uint SYMOPT_LOAD_LINES = 0x00000010;

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool SymInitialize(IntPtr hProcess, string UserSearchPath, bool fInvadeProcess);

        [DllImport("dbghelp.dll", SetLastError = true)]
        private static extern bool SymCleanup(IntPtr hProcess);

        [DllImport("dbghelp.dll", SetLastError = true)]
        private static extern uint SymSetOptions(uint SymOptions);

        [DllImport("dbghelp.dll", SetLastError = true)]
        private static extern uint SymGetOptions();

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool SymFromAddrW(IntPtr hProcess, ulong Address, out ulong Displacement, IntPtr Symbol);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SYMBOL_INFO
        {
            public uint SizeOfStruct;
            public uint TypeIndex;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public ulong[] Reserved;
            public uint Index;
            public uint Size;
            public ulong ModBase;
            public uint Flags;
            public ulong Value;
            public ulong Address;
            public uint Register;
            public uint Scope;
            public uint Tag;
            public uint NameLen;
            public uint MaxNameLen;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1024)]
            public string Name;
        }

        public SymbolResolver(IntPtr processHandle)
        {
            _hProcess = processHandle;
            Initialize();
        }

        private void Initialize()
        {
            lock (_lock)
            {
                uint options = SymGetOptions();
                options |= SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS;
                SymSetOptions(options);

                // fInvadeProcess = true lädt Module automatisch
                if (SymInitialize(_hProcess, null, true))
                {
                    _initialized = true;
                }
            }
        }

        public string ResolveAddress(IntPtr address)
        {
            if (!_initialized) return null;

            ulong addr = (ulong)address.ToInt64();
            ulong displacement = 0;

            // Puffer für SYMBOL_INFO allozieren
            // SizeOfStruct (88) + (MaxNameLen * 2) für Unicode
            int bufferSize = Marshal.SizeOf(typeof(SYMBOL_INFO));
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                Marshal.StructureToPtr(new SYMBOL_INFO
                {
                    SizeOfStruct = (uint)sizeof(uint) * 2 + sizeof(ulong) * 2 + sizeof(uint) * 6 + sizeof(ulong) * 3, // Manuelle Berechnung der Basisgröße ohne String
                    MaxNameLen = 1024
                }, buffer, false);

                // Wir müssen den SizeOfStruct korrekt setzen (88 Bytes auf x64 für den Header)
                // Die Strukturdefinition oben enthält den String im Body, P/Invoke erwartet aber oft variable Größe.
                // Einfacherer Weg: Wir nutzen die Struktur direkt, da wir SizeConst definiert haben.

                var symInfo = new SYMBOL_INFO();
                symInfo.SizeOfStruct = 88; // Fest für x64 Basis
                symInfo.MaxNameLen = 1024;

                // Da SymFromAddrW einen Pointer auf den Puffer erwartet, in den es schreibt
                // und die Struktur dynamisch ist, nutzen wir Marshaling per Hand für den String.

                // Korrektur für stabilen P/Invoke:
                // Wir allozieren einen rohen Byte-Block, der groß genug ist.
                int rawSize = 2048;
                IntPtr rawBuffer = Marshal.AllocHGlobal(rawSize);
                ZeroMemory(rawBuffer, rawSize);

                // Setze SizeOfStruct und MaxNameLen im rohen Speicher
                Marshal.WriteInt32(rawBuffer, 0, 88); // SizeOfStruct
                Marshal.WriteInt32(rawBuffer, 76, 1024); // MaxNameLen (Offset 76 auf x64)

                bool result;
                lock (_lock)
                {
                    result = SymFromAddrW(_hProcess, addr, out displacement, rawBuffer);
                }

                if (result)
                {
                    // Name beginnt an Offset 84 (auf x64, nach Header)
                    // SYMBOL_INFO Header ist 88 Bytes, Name beginnt danach?
                    // Dokumentation sagt: Name ist das letzte Feld.
                    // Struktur Alignment beachten.
                    // Wir lesen den Namen ab Offset 84
                    string name = Marshal.PtrToStringUni(IntPtr.Add(rawBuffer, 84));
                    if (!string.IsNullOrEmpty(name))
                    {
                        if (displacement > 0)
                            return $"{name}+0x{displacement:X}";
                        else
                            return name;
                    }
                }
            }
            catch
            {
                // Symbol Resolution failed
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return null;
        }

        [DllImport("kernel32.dll", EntryPoint = "RtlZeroMemory", SetLastError = false)]
        private static extern void ZeroMemory(IntPtr dest, int size);

        public void Dispose()
        {
            if (_initialized)
            {
                lock (_lock)
                {
                    SymCleanup(_hProcess);
                }
                _initialized = false;
            }
        }
    }
}