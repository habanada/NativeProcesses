/*
   NativeProcesses Framework
   PeExecutor.cs - Full implementation of libpeconv loader logic in C#
*/
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using NativeProcesses.Core.PE;
using NativeProcesses.Core.PE.Export;
using NativeProcesses.Core.PE.Resources;

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

        private IntPtr _hActCtx = IntPtr.Zero;
        private string _tempManifestPath = null;

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

        // DLL Main Reasons
        private const uint DLL_PROCESS_ATTACH = 1;
        private const uint DLL_THREAD_ATTACH = 2;
        private const uint DLL_THREAD_DETACH = 3;
        private const uint DLL_PROCESS_DETACH = 0;
        #endregion

        // Interne Status-Variablen
        private IntPtr _loadedImageBase = IntPtr.Zero;
        private UIntPtr _imageSize = UIntPtr.Zero;
        private bool _isDisposed = false;
        private IntPtr _pExceptionTable = IntPtr.Zero;
        private IntPtr _pebEntry = IntPtr.Zero;
        private bool _tlsCallbacksExecuted = false; // Schutz vor doppelter Ausführung
        /// <summary>
        /// Gibt die Basisadresse des geladenen Moduls zurück (falls geladen).
        /// </summary>
        public IntPtr LoadedImageBase => _loadedImageBase;

        /// <summary>
        /// Lädt eine PE-Datei (Raw Bytes) vollständig in den Speicher.
        /// Führt Mapping, Relocations, Import Resolution, Security Cookie Init und TLS Callbacks aus.
        /// Führt KEINEN Code aus (weder TLS noch DllMain). Das passiert erst in Run().
        /// /// </summary>
        /// <param name="rawPe">Das Byte-Array der rohen PE-Datei (z.B. File.ReadAllBytes).</param>
        /// <returns>True bei Erfolg, sonst wird eine Exception geworfen.</returns>
        public bool Load(byte[] rawPe, string fakeDllName = "module.dll")
        {
            if (rawPe == null || rawPe.Length == 0)
                throw new ArgumentNullException(nameof(rawPe), "PE buffer is empty.");

            // Aufräumen, falls schon was geladen war
            if (_loadedImageBase != IntPtr.Zero) Free();

            try
            {
                // 1. Mapping (Raw -> Virtual)
                // Wir erstellen das Speicherlayout lokal im Byte-Array
                byte[] virtualPe = PeLoader.MapRawToVirtual(rawPe);
                _imageSize = (UIntPtr)virtualPe.Length;

                // 2. Allokation
                // Wir reservieren den echten Speicher im Prozess
                _loadedImageBase = VirtualAlloc(IntPtr.Zero, _imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (_loadedImageBase == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());

                // 3. Relocations
                // Wir passen Adressen im 'virtualPe' Array an die neue '_loadedImageBase' an
                if (!RelocationsFixer.ApplyRelocations(virtualPe, (ulong)_loadedImageBase.ToInt64()))
                {
                    // Log: Relocations failed or not needed (z.B. bei .NET oder Position Independent Code)
                }

                // 4. Initialer Copy in den Speicher (WICHTIG für Ressourcen-Zugriff)
                // Wir kopieren das Image JETZT schon, damit wir Ressourcen (Manifest) lesen können.
                Marshal.Copy(virtualPe, 0, _loadedImageBase, virtualPe.Length);

                // 5. Activation Context vorbereiten
                // Liest das Manifest aus _loadedImageBase und erstellt den Kontext
                PrepareActivationContext(_loadedImageBase);

                // 6. Import Resolution (Unter dem Schutz des ActCtx)
                bool importsSuccess = false;

                ExecuteWithActCtx(() =>
                {
                    // ImportsFixer lädt DLLs (LoadLibrary). Dank ActCtx werden die richtigen Versionen (SxS) geladen.
                    // Er schreibt die Adressen in das 'virtualPe' Array (IAT).
                    importsSuccess = ImportsFixer.FixImports(virtualPe);
                });

                if (!importsSuccess)
                {
                    throw new Exception("Failed to resolve imports. Dependencies missing or ActCtx failed.");
                }

                // 7. Finaler Copy (IAT Update)
                // Da ImportsFixer in 'virtualPe' geschrieben hat, müssen wir das Image 
                // erneut in den Speicher kopieren (oder zumindest die Header/IAT Region).
                Marshal.Copy(virtualPe, 0, _loadedImageBase, virtualPe.Length);

                // 8. Exceptions (SEH)
                EnableExceptions(virtualPe);

                // 9. PEB Linking
                _pebEntry = PePebLinker.LinkModuleToPeb(_loadedImageBase, (uint)_imageSize, "C:\\Windows\\System32\\" + fakeDllName);

                // 10. Security Cookie
                PeConfig.InitSecurityCookie(_loadedImageBase);

                // Hinweis: TLS Callbacks werden hier NICHT mehr ausgeführt. 
                // Das passiert jetzt korrekt in Run(), wie im Windows Loader.

                // 11. Flush Cache
                FlushInstructionCache(IntPtr.Zero, _loadedImageBase, _imageSize);

                return true;
            }
            catch (Exception)
            {
                Free();
                throw;
            }
        }       // ---------------------------------------------------------
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
        private bool PrepareActivationContext(IntPtr moduleBase)
        {
            try
            {
                byte[] manifestData = PeResourceReader.GetManifest(moduleBase);

                if (manifestData == null || manifestData.Length == 0)
                    return false;

                _tempManifestPath = Path.GetTempFileName();
                File.WriteAllBytes(_tempManifestPath, manifestData);

                var actCtx = new NativeProcesses.Core.Native.ActivationContext.ACTCTX();
                actCtx.cbSize = Marshal.SizeOf(typeof(NativeProcesses.Core.Native.ActivationContext.ACTCTX));
                actCtx.dwFlags = 0;
                actCtx.lpSource = _tempManifestPath;

                _hActCtx = NativeProcesses.Core.Native.ActivationContext.CreateActCtx(ref actCtx);

                return (_hActCtx != NativeProcesses.Core.Native.ActivationContext.INVALID_HANDLE_VALUE);
            }
            catch
            {
                return false;
            }
        }

        private void ExecuteWithActCtx(Action action)
        {
            IntPtr cookie = IntPtr.Zero;
            bool active = false;

            if (_hActCtx != IntPtr.Zero && _hActCtx != NativeProcesses.Core.Native.ActivationContext.INVALID_HANDLE_VALUE)
            {
                active = NativeProcesses.Core.Native.ActivationContext.ActivateActCtx(_hActCtx, out cookie);
            }

            try
            {
                action();
            }
            finally
            {
                if (active)
                {
                    NativeProcesses.Core.Native.ActivationContext.DeactivateActCtx(0, cookie);
                }
            }
        }
        /// <summary>
        /// Führt TLS-Callbacks und den EntryPoint aus.
        /// Entspricht LdrpRunInitializeRoutines in ReactOS.
        /// </summary>
        public void Run()
        {
            if (_loadedImageBase == IntPtr.Zero) throw new InvalidOperationException("PE not loaded. Call Load() first.");

            // Header parsen um EntryPoint zu finden
            int e_lfanew = Marshal.ReadInt32(_loadedImageBase, 0x3C);
            IntPtr ntHeader = IntPtr.Add(_loadedImageBase, e_lfanew);
            IntPtr optHeader = IntPtr.Add(ntHeader, 24);
            ushort magic = (ushort)Marshal.ReadInt16(optHeader);

            uint entryPointRva = (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                ? (uint)Marshal.ReadInt32(optHeader, 16)
                : (uint)Marshal.ReadInt32(optHeader, 16);

            // Prüfen ob es eine DLL ist (Flag 0x2000 in FileHeader Characteristics)
            ushort characteristics = (ushort)Marshal.ReadInt16(ntHeader, 4 + 18);
            bool isDll = (characteristics & 0x2000) != 0;

            // ReactOS: LdrpRunInitializeRoutines
            // Reihenfolge:
            // 1. Activate ActCtx
            // 2. LdrpCallTlsInitializers (DLL_PROCESS_ATTACH)
            // 3. LdrpCallInitRoutine (EntryPoint)
            // 4. Deactivate ActCtx

            ExecuteWithActCtx(() =>
            {
                // 1. TLS Callbacks ausführen (falls vorhanden)
                // Wichtig: Diese laufen VOR dem EntryPoint!
                if (!_tlsCallbacksExecuted)
                {
                    PeTls.ExecuteTlsCallbacks(_loadedImageBase); // Führt aktuell fest DLL_PROCESS_ATTACH aus
                    _tlsCallbacksExecuted = true;
                }

                // 2. Entry Point ausführen
                if (entryPointRva != 0)
                {
                    IntPtr entryPointAddress = IntPtr.Add(_loadedImageBase, (int)entryPointRva);

                    if (isDll)
                    {
                        // DllMain(hInst, DLL_PROCESS_ATTACH, Reserved)
                        var dllMain = Marshal.GetDelegateForFunctionPointer<DllMainDelegate>(entryPointAddress);
                        dllMain(_loadedImageBase, DLL_PROCESS_ATTACH, IntPtr.Zero);
                    }
                    else
                    {
                        // ExeMain()
                        var exeMain = Marshal.GetDelegateForFunctionPointer<Action>(entryPointAddress);
                        exeMain();
                    }
                }
            });
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
            if (_hActCtx != IntPtr.Zero && _hActCtx != NativeProcesses.Core.Native.ActivationContext.INVALID_HANDLE_VALUE)
            {
                NativeProcesses.Core.Native.ActivationContext.ReleaseActCtx(_hActCtx);
                _hActCtx = IntPtr.Zero;
            }

            if (!string.IsNullOrEmpty(_tempManifestPath) && File.Exists(_tempManifestPath))
            {
                try { File.Delete(_tempManifestPath); } catch { }
                _tempManifestPath = null;
            }

            // ... (Rest deiner Free Methode: VirtualFree etc.) ...
            if (_loadedImageBase != IntPtr.Zero)
            {
                if (_pebEntry != IntPtr.Zero)
                {
                    PePebLinker.UnlinkModuleFromPeb(_pebEntry);
                    _pebEntry = IntPtr.Zero;
                }
                // Aufräumen Exception Table wenn nötig (RtlDeleteFunctionTable wäre hier gut)

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
        // Helper für Exception Support (aus deinem vorherigen Code)
    }
}


/*
 using System;
using System.IO;
using System.Windows.Forms; // Für MessageBox (Test-Output)
using NativeProcesses.Core.PE.Loader; // Dein Namespace

public static void TestManualMapping()
{
    // 1. Ziel-DLL auswählen
    // Wir nehmen 'gdi32.dll' aus System32, da sie Manifest-Abhängigkeiten hat
    // und sicher zu laden ist. Alternativ: Deine eigene Test-DLL.
    string targetDll = Path.Combine(Environment.SystemDirectory, "gdi32.dll");

    if (!File.Exists(targetDll))
    {
        MessageBox.Show("Test-DLL nicht gefunden!", "Fehler", MessageBoxButtons.OK, MessageBoxIcon.Error);
        return;
    }

    Console.WriteLine($"[Test] Lade {targetDll} manuell...");

    try
    {
        // Bytes lesen
        byte[] rawBytes = File.ReadAllBytes(targetDll);

        // 2. PeExecutor Instanz erstellen
        using (var executor = new PeExecutor())
        {
            // A. LOAD: Mappen, Relocations, Importe (unter ActCtx!), Security Cookie
            // Wir geben ihr einen Fake-Namen, damit sie im PEB sichtbar ist (für GetModuleHandle)
            bool success = executor.Load(rawBytes, "manual_gdi32.dll");

            if (success)
            {
                Console.WriteLine($"[Test] Load erfolgreich! Basis: 0x{executor.LoadedImageBase.ToString("X")}");

                // B. RUN: TLS Callbacks & DllMain (unter ActCtx!)
                // Hier wird DllMain mit DLL_PROCESS_ATTACH aufgerufen
                executor.Run();
                Console.WriteLine("[Test] Run (DllMain Attach) erfolgreich ausgeführt.");

                // C. OPTIONAL: Thread Attach testen (Das neue Feature!)
                // Simuliert, dass ein neuer Thread erstellt wurde.
                // Die DLL sollte (wenn sie TLS nutzt) darauf reagieren.
                Console.WriteLine("[Test] Simuliere Thread Attach...");
                executor.OnThreadAttach();
                
                // D. Export testen (Optional)
                // Wir rufen eine harmlose Funktion auf, um zu sehen, ob der Code läuft.
                // Hinweis: GDI32 exportiert kaum einfache Void-Funktionen ohne Params.
                // Bei einer eigenen DLL könntest du hier executor.RunExport("MyExport") rufen.
                
                MessageBox.Show($"DLL manuell geladen an: 0x{executor.LoadedImageBase.ToString("X")}\n" +
                                "Activation Context & Importe waren erfolgreich!\n" +
                                "Schau in den Debug-Output.", 
                                "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);

                // E. UNLOAD (Passiert automatisch beim Dispose)
                // executor.Dispose() ruft Free(), was DllMain(DLL_PROCESS_DETACH) unter ActCtx ausführt.
            }
            else
            {
                Console.WriteLine("[Test] Load fehlgeschlagen (false zurückgegeben).");
            }
        } 
        // Hier ist der Scope zu Ende -> Dispose -> Unload -> DllMain Detach
        Console.WriteLine("[Test] DLL erfolgreich entladen.");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[Test] Kritischer Fehler: {ex.Message}");
        MessageBox.Show($"Fehler beim Manual Mapping:\n{ex.Message}", "Fehler", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
}
 */