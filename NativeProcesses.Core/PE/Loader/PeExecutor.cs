/*
   NativeProcesses Framework
   PeExecutor.cs - Full implementation of libpeconv loader logic in C#
*/
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using NativeProcesses.Core.PE;
using NativeProcesses.Core.PE.Export;

namespace NativeProcesses.Core.PE.Loader
{
    public class PeExecutor : IDisposable
    {
        #region P/Invoke Definitions
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);

        // we could use RtlInsertInvertedFunctionTable from ntdll with struct Inverted Function Table for stealth but we use RtlAddFunctionTable  to make us Visible and to have more stability!
        //we need to make the ntdll.dll readwrite with PAGE_READWRITE this would be a massive RED FLAG and would trigger EDR, also it would mean we have to check were we run Win7, 8, 10, 11 this 
        //strucktures change a lot its easier and safer not to do it - we coudl but we let it go...
        // we need RTL_INVERTED_FUNCTION_TABLE  we have LDR_DATA_TABLE_ENTRY 
        [DllImport("kernel32.dll")]
        static extern bool RtlAddFunctionTable(IntPtr FunctionTable, uint EntryCount, ulong BaseAddress);

        [DllImport("kernel32.dll")]
        private static extern bool RtlDeleteFunctionTable(IntPtr FunctionTable);

        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint MEM_RELEASE = 0x8000;

        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_EXECUTE_READ = 0x20;
        #endregion

        // Interne Status-Variablen
        private IntPtr _loadedImageBase = IntPtr.Zero;
        private UIntPtr _imageSize = UIntPtr.Zero;
        private bool _isDisposed = false;
        private IntPtr _pExceptionTable = IntPtr.Zero;
        private IntPtr _pebEntry = IntPtr.Zero;

        /// <summary>
        /// Gibt die Basisadresse des geladenen Moduls zurück (falls geladen).
        /// </summary>
        public IntPtr LoadedImageBase => _loadedImageBase;

        /// <summary>
        /// Lädt eine PE-Datei (Raw Bytes) vollständig in den Speicher.
        /// Führt Mapping, Relocations, Import Resolution, Security Cookie Init und TLS Callbacks aus.
        /// </summary>
        /// <param name="rawPe">Das Byte-Array der rohen PE-Datei (z.B. File.ReadAllBytes).</param>
        /// <returns>True bei Erfolg, sonst wird eine Exception geworfen.</returns>
        public bool Load(byte[] rawPe, string fakeDllName = "module.dll")
        {
            if (rawPe == null || rawPe.Length == 0)
                throw new ArgumentNullException(nameof(rawPe), "PE buffer is empty.");

            // Falls bereits was geladen war, freigeben
            if (_loadedImageBase != IntPtr.Zero) Free();

            try
            {
                // ---------------------------------------------------------
                // SCHRITT 1: Mapping (Raw -> Virtual)
                // ---------------------------------------------------------
                // libpeconv: pe_raw_to_virtual
                // Wir expandieren die Sections entsprechend ihrem VirtualAlignment.
                byte[] virtualPe = PeLoader.MapRawToVirtual(rawPe);
                _imageSize = (UIntPtr)virtualPe.Length;

                // ---------------------------------------------------------
                // SCHRITT 2: Allokation
                // ---------------------------------------------------------
                // Wir reservieren Speicher im aktuellen Prozess.
                // Wir nutzen PAGE_EXECUTE_READWRITE, damit wir Patchen (Imports/Relocs) und Ausführen können.
                // In einer strikteren Implementierung würde man erst RW, dann RX setzen.
                _loadedImageBase = VirtualAlloc(IntPtr.Zero, _imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                if (_loadedImageBase == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualAlloc failed to allocate memory for PE image.");
                }

                // ---------------------------------------------------------
                // SCHRITT 3: Relocations (Base Relocs)
                // ---------------------------------------------------------
                // libpeconv: relocate_module
                // Wir berechnen das Delta zwischen der Preferred ImageBase (im Header) und unserer _loadedImageBase.
                // RelocationsFixer wendet dies direkt auf unser `virtualPe` Byte-Array an.

                if (!RelocationsFixer.ApplyRelocations(virtualPe, (ulong)_loadedImageBase.ToInt64()))
                {
                    // Warnung: Relocations fehlgeschlagen. Das passiert oft bei Stripped Binaries.
                    // Wir brechen hier nicht hart ab, da Code evtl. Position Independent ist, 
                    // aber es ist ein kritisches Risiko.
                    // System.Diagnostics.Debug.WriteLine("[WARN] Applying relocations failed (or not needed).");
                }

                // ---------------------------------------------------------
                // SCHRITT 4: Import Resolution (IAT Fixing)
                // ---------------------------------------------------------
                // libpeconv: load_imports
                // Wir laden abhängige DLLs (LoadLibrary) und schreiben Funktionsadressen (GetProcAddress) in die IAT.

                if (!ImportsFixer.FixImports(virtualPe))
                {
                    throw new Exception("Failed to resolve imports. Dependent DLLs might be missing or incompatible.");
                }

                // ---------------------------------------------------------
                // SCHRITT 5: Kopieren in den nativen Speicher
                // ---------------------------------------------------------
                // Jetzt, wo das Byte-Array gepatcht ist, schieben wir es in den ausführbaren Speicher.
                Marshal.Copy(virtualPe, 0, _loadedImageBase, virtualPe.Length);
                // NEU: SCHRITT 5b - Exceptions
                if (!EnableExceptions(virtualPe))
                {
                    // Optional: Log warning. Ist nicht kritisch für Programmstart, aber für Stabilität.
                    // System.Diagnostics.Debug.WriteLine("SEH Registration failed or not needed.");
                }
                // NEU: SCHRITT 5c - PEB Linking (Make Visible)
                // ---------------------------------------------------------
                // Wir gaukeln Windows vor, dass diese DLL wirklich geladen ist.
                // Das erlaubt GetModuleHandle(fakeDllName) und API Calls, die das Modul suchen.

                _pebEntry = PePebLinker.LinkModuleToPeb(_loadedImageBase, (uint)_imageSize, "C:\\Windows\\System32\\" + fakeDllName);
                // ---------------------------------------------------------
                // SCHRITT 6: Security Cookie (Load Config)
                // ---------------------------------------------------------
                // libpeconv: fix_security_cookie
                // Wichtig für MSVC Binaries (Stack Canary /GS). Ohne das crasht es sofort bei __security_check_cookie.
                // Dies muss im NATIVEN Speicher passieren, da wir Pointer schreiben.

                if (!PeConfig.InitSecurityCookie(_loadedImageBase))
                {
                    // Warnung, aber kein Abbruch. Alte PEs haben keine LoadConfig.
                }

                // ---------------------------------------------------------
                // SCHRITT 7: TLS Callbacks
                // ---------------------------------------------------------
                // libpeconv: run_tls_callbacks
                // Führt Initialisierungscode aus (oft Anti-Debug oder Setup), bevor der EntryPoint läuft.

                if (!PeTls.ExecuteTlsCallbacks(_loadedImageBase))
                {
                    throw new Exception("Failed to execute TLS callbacks. The payload might have crashed during initialization.");
                }
            
                // ---------------------------------------------------------
                // SCHRITT 8: Finalisierung
                // ---------------------------------------------------------
                // Instruction Cache leeren, damit die CPU die neuen Opcodes auch wirklich sieht.
                FlushInstructionCache(IntPtr.Zero, _loadedImageBase, _imageSize);

                return true;
            }
            catch (Exception)
            {
                // Bei jedem Fehler aufräumen, um Memory Leaks zu vermeiden
                Free();
                throw;
            }
        }
        // ---------------------------------------------------------
        // Hilfsmethode für Exception Support
        // ---------------------------------------------------------
        private bool EnableExceptions(byte[] virtualPe)
        {
            try
            {
                // Wir nutzen deine PeLoader Logik, um Headers zu checken
                if (!PeLoader.GetImageBase(virtualPe, out _, out bool is64Bit))
                    return false;

                // SEH via RtlAddFunctionTable gibt es nur auf x64 (auf x86 läuft das über den Stack/FS Register)
                if (!is64Bit) return true;

                // Header lesen um Directory zu finden
                int e_lfanew = BitConverter.ToInt32(virtualPe, 0x3C);
                int optHeaderOffset = e_lfanew + 24;

                // Auf x64 ist DataDirectory bei Offset 112 im Optional Header
                // Directory Index 3 ist IMAGE_DIRECTORY_ENTRY_EXCEPTION
                int exceptionDirOffset = optHeaderOffset + 112 + (3 * 8); // 3 * sizeof(IMAGE_DATA_DIRECTORY)

                uint exceptionRva = BitConverter.ToUInt32(virtualPe, exceptionDirOffset);
                uint exceptionSize = BitConverter.ToUInt32(virtualPe, exceptionDirOffset + 4);

                if (exceptionRva == 0 || exceptionSize == 0) return true; // Keine Exceptions in der DLL

                // Pointer zur Tabelle im allozieren Speicher berechnen
                _pExceptionTable = IntPtr.Add(_loadedImageBase, (int)exceptionRva);

                // Anzahl der Einträge berechnen (Size / sizeof(RUNTIME_FUNCTION))
                // RUNTIME_FUNCTION ist 12 Bytes groß (3 * uint)
                uint entryCount = exceptionSize / 12;

                // Registrieren bei Windows
                return RtlAddFunctionTable(_pExceptionTable, entryCount, (ulong)_loadedImageBase.ToInt64());
            }
            catch
            {
                return false;
            }
        }
        /// <summary>
        /// Führt den EntryPoint der geladenen PE aus.
        /// </summary>
        public void Run()
        {
            if (_loadedImageBase == IntPtr.Zero) throw new InvalidOperationException("PE not loaded. Call Load() first.");

            // EntryPoint RVA aus Header lesen (direkt aus Memory)
            int e_lfanew = Marshal.ReadInt32(_loadedImageBase, 0x3C);
            IntPtr ntHeader = IntPtr.Add(_loadedImageBase, e_lfanew);
            IntPtr optHeader = IntPtr.Add(ntHeader, 24); // Optional Header Start

            ushort magic = (ushort)Marshal.ReadInt16(optHeader);
            uint entryPointRva;

            // Offset für AddressOfEntryPoint
            if (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                entryPointRva = (uint)Marshal.ReadInt32(optHeader, 16);
            else
                entryPointRva = (uint)Marshal.ReadInt32(optHeader, 16);

            if (entryPointRva == 0) return; // Kein EntryPoint (z.B. Resource DLL)

            IntPtr entryPointAddress = IntPtr.Add(_loadedImageBase, (int)entryPointRva);

            // DLL vs EXE Unterscheidung
            // Characteristics ist bei FileHeader (NT + 4) + Offset 18
            ushort characteristics = (ushort)Marshal.ReadInt16(ntHeader, 4 + 18);
            bool isDll = (characteristics & 0x2000) != 0;

            if (isDll)
            {
                var dllMain = Marshal.GetDelegateForFunctionPointer<DllMainDelegate>(entryPointAddress);
                // 1 = DLL_PROCESS_ATTACH
                bool result = dllMain(_loadedImageBase, 1, IntPtr.Zero);
                if (!result)
                {
                    throw new Exception("DllMain(DLL_PROCESS_ATTACH) returned false.");
                }
            }
            else
            {
                var exeMain = Marshal.GetDelegateForFunctionPointer<Action>(entryPointAddress);
                exeMain();
            }
        }

        /// <summary>
        /// Führt eine exportierte Funktion aus (void, keine Parameter).
        /// </summary>
        public void RunExport(string exportName)
        {
            if (_loadedImageBase == IntPtr.Zero) throw new InvalidOperationException("PE not loaded.");

            IntPtr funcAddr = PeExports.GetExportAddress(_loadedImageBase, exportName);

            if (funcAddr == IntPtr.Zero)
            {
                throw new EntryPointNotFoundException($"Export '{exportName}' not found in loaded image.");
            }

            var funcDelegate = Marshal.GetDelegateForFunctionPointer<Action>(funcAddr);
            funcDelegate();
        }

        /// <summary>
        /// Ruft eine exportierte Funktion mit einer spezifischen Signatur ab.
        /// </summary>
        public TDelegate GetExportDelegate<TDelegate>(string exportName) where TDelegate : Delegate
        {
            if (_loadedImageBase == IntPtr.Zero) throw new InvalidOperationException("PE not loaded.");

            IntPtr funcAddr = PeExports.GetExportAddress(_loadedImageBase, exportName);

            if (funcAddr == IntPtr.Zero)
            {
                throw new EntryPointNotFoundException($"Export '{exportName}' not found in loaded image.");
            }

            return Marshal.GetDelegateForFunctionPointer<TDelegate>(funcAddr);
        }

        private void Free()
        {
            if (_loadedImageBase != IntPtr.Zero)
            {
                // Erst aus dem PEB entfernen!
                if (_pebEntry != IntPtr.Zero)
                {
                    PePebLinker.UnlinkModuleFromPeb(_pebEntry);
                    _pebEntry = IntPtr.Zero;
                }
                // MEM_RELEASE (0x8000) gibt den Speicher komplett an das OS zurück.
                // dwSize muss 0 sein bei MEM_RELEASE.
                VirtualFree(_loadedImageBase, UIntPtr.Zero, MEM_RELEASE);
                _loadedImageBase = IntPtr.Zero;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_isDisposed)
            {
                // Wir geben den Speicher frei, wenn das Objekt zerstört wird.
                // Das bedeutet, die geladene DLL "entlädt" sich.
                Free();
                _isDisposed = true;
            }
        }

        ~PeExecutor()
        {
            Dispose(false);
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate bool DllMainDelegate(IntPtr hinstDLL, uint fdwReason, IntPtr lpvReserved);
    }
}