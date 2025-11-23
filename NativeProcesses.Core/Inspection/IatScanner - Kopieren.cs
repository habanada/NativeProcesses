//using System;
//using System.Collections.Generic;
//using System.IO;
//using System.Linq;
//using System.Runtime.InteropServices;
//using NativeProcesses.Core.Engine;
//using NativeProcesses.Core.Models;
//using NativeProcesses.Core.Native; // Hier ist dein SignatureVerifier
//using NativeProcesses.Core.PE;
//using NativeProcesses.Core.PE.Loader;

//namespace NativeProcesses.Core.Inspection
//{
//    public class IatScanner
//    {
//        private readonly IEngineLogger _logger;
//        private readonly SecurityInspector _inspector;

//        // Pfade für schnelles Whitelisting
//        private readonly string _system32Path;
//        private readonly string _sysWow64Path;
//        private readonly string _winSxsPath;

//        // Cache für Signaturen, um Disk-I/O zu sparen (wichtig bei 24k Checks!)
//        private static readonly Dictionary<string, bool> _signatureCache = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

//        #region P/Invoke
//        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
//        private static extern IntPtr LoadLibraryA(string lpFileName);

//        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
//        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

//        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
//        private static extern IntPtr GetProcAddress(IntPtr hModule, IntPtr lpProcName);
//        #endregion

//        public IatScanner(IEngineLogger logger)
//        {
//            _logger = logger;
//            _inspector = new SecurityInspector(logger);
//            _system32Path = Environment.GetFolderPath(Environment.SpecialFolder.System).ToLowerInvariant();
//            _sysWow64Path = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86).ToLowerInvariant();
//            _winSxsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "WinSxS").ToLowerInvariant();
//        }

//        public List<SecurityInspector.IatHookInfo> ScanModule(
//            ManagedProcess process,
//            ProcessModuleInfo moduleToScan,
//            List<ProcessModuleInfo> allModules,
//            List<VirtualMemoryRegion> regions)
//        {
//            var results = new List<SecurityInspector.IatHookInfo>();

//            // Filter 1: Wir scannen keine Module, die wir nicht von der Platte lesen können
//            if (string.IsNullOrEmpty(moduleToScan.FullDllName) || !File.Exists(moduleToScan.FullDllName))
//                return results;

//            // Filter 2: System-DLLs selbst scannen erzeugt extrem viele False Positives durch interne Shims.
//            // pe-sieve scannt standardmäßig nur das Hauptmodul (EXE) oder explizit gewählte.
//            // Wenn moduleToScan im System32 liegt, überspringen wir den IAT Scan oft, es sei denn, wir sind im "Paranoid Mode".
//            // Für jetzt lassen wir es zu, aber filtern strikt.

//            try
//            {
//                byte[] rawFile = File.ReadAllBytes(moduleToScan.FullDllName);
//                byte[] mappedImage = PeLoader.MapRawToVirtual(rawFile);
//                if (mappedImage == null) return results;

//                GCHandle handle = GCHandle.Alloc(mappedImage, GCHandleType.Pinned);
//                try
//                {
//                    IntPtr basePtr = handle.AddrOfPinnedObject();
//                    if (!PeLoader.GetImageBase(mappedImage, out _, out bool is64Bit)) return results;

//                    var dos = Marshal.PtrToStructure<PeHeaders.IMAGE_DOS_HEADER>(basePtr);
//                    IntPtr ntPtr = IntPtr.Add(basePtr, dos.e_lfanew);
//                    IntPtr optPtr = IntPtr.Add(ntPtr, 4 + Marshal.SizeOf<PeHeaders.IMAGE_FILE_HEADER>());

//                    uint importRva = 0;
//                    if (is64Bit)
//                    {
//                        var opt64 = Marshal.PtrToStructure<PeHeaders.IMAGE_OPTIONAL_HEADER64>(optPtr);
//                        if (opt64.NumberOfRvaAndSizes > PeHeaders.IMAGE_DIRECTORY_ENTRY_IMPORT)
//                            importRva = opt64.DataDirectory[PeHeaders.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
//                    }
//                    else
//                    {
//                        var opt32 = Marshal.PtrToStructure<PeHeaders.IMAGE_OPTIONAL_HEADER32>(optPtr);
//                        if (opt32.NumberOfRvaAndSizes > PeHeaders.IMAGE_DIRECTORY_ENTRY_IMPORT)
//                            importRva = opt32.DataDirectory[PeHeaders.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
//                    }

//                    if (importRva == 0) return results;

//                    int descriptorSize = Marshal.SizeOf<PeHeaders.IMAGE_IMPORT_DESCRIPTOR>();
//                    int currentOffset = 0;

//                    while (true)
//                    {
//                        IntPtr descPtr = IntPtr.Add(basePtr, (int)(importRva + currentOffset));
//                        var desc = Marshal.PtrToStructure<PeHeaders.IMAGE_IMPORT_DESCRIPTOR>(descPtr);

//                        if (desc.Name == 0 && desc.FirstThunk == 0) break;

//                        string dllName = Marshal.PtrToStringAnsi(IntPtr.Add(basePtr, (int)desc.Name));
//                        if (string.IsNullOrEmpty(dllName)) { currentOffset += descriptorSize; continue; }

//                        // Filter 3: Runtime-DLLs und API-Sets ignorieren
//                        if (dllName.StartsWith("mscoree", StringComparison.OrdinalIgnoreCase) ||
//                            dllName.StartsWith("api-ms-", StringComparison.OrdinalIgnoreCase) ||
//                            dllName.StartsWith("ext-ms-", StringComparison.OrdinalIgnoreCase))
//                        {
//                            currentOffset += descriptorSize; continue;
//                        }

//                        IntPtr hLib = LoadLibraryA(dllName);
//                        if (hLib == IntPtr.Zero) { currentOffset += descriptorSize; continue; }

//                        uint thunkRva = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
//                        uint iatRva = desc.FirstThunk;
//                        int index = 0;
//                        int ptrSize = is64Bit ? 8 : 4;

//                        while (true)
//                        {
//                            IntPtr thunkPtr = IntPtr.Add(basePtr, (int)(thunkRva + (index * ptrSize)));
//                            string funcName = null;
//                            IntPtr expectedAddr = IntPtr.Zero;

//                            // Thunk lokal parsen
//                            if (is64Bit)
//                            {
//                                ulong rawThunk = (ulong)Marshal.ReadInt64(thunkPtr);
//                                if (rawThunk == 0) break;
//                                if ((rawThunk & 0x8000000000000000) != 0)
//                                    expectedAddr = GetProcAddress(hLib, (IntPtr)(rawThunk & 0xFFFF));
//                                else
//                                {
//                                    uint nameRva = (uint)(rawThunk & 0x7FFFFFFF);
//                                    funcName = Marshal.PtrToStringAnsi(IntPtr.Add(basePtr, (int)nameRva + 2));
//                                    expectedAddr = GetProcAddress(hLib, funcName);
//                                }
//                            }
//                            else
//                            {
//                                uint rawThunk = (uint)Marshal.ReadInt32(thunkPtr);
//                                if (rawThunk == 0) break;
//                                if ((rawThunk & 0x80000000) != 0)
//                                    expectedAddr = GetProcAddress(hLib, (IntPtr)(rawThunk & 0xFFFF));
//                                else
//                                {
//                                    string nameStr = Marshal.PtrToStringAnsi(IntPtr.Add(basePtr, (int)rawThunk + 2));
//                                    funcName = nameStr;
//                                    expectedAddr = GetProcAddress(hLib, funcName);
//                                }
//                            }

//                            if (expectedAddr != IntPtr.Zero)
//                            {
//                                IntPtr remoteIatPtr = IntPtr.Add(moduleToScan.DllBase, (int)(iatRva + (index * ptrSize)));
//                                byte[] remoteValBytes = process.ReadMemory(remoteIatPtr, ptrSize);

//                                if (remoteValBytes != null)
//                                {
//                                    IntPtr actualAddr = is64Bit
//                                        ? (IntPtr)BitConverter.ToInt64(remoteValBytes, 0)
//                                        : (IntPtr)BitConverter.ToInt32(remoteValBytes, 0);

//                                    // === CRITICAL CHECK ===
//                                    if (actualAddr != expectedAddr)
//                                    {
//                                        // 99% der "Hooks" sind hier. Wir müssen prüfen:
//                                        // "Ist die tatsächliche Adresse (actualAddr) in irgendeinem vertrauenswürdigen System-Modul?"
//                                        if (!IsSafeSystemRedirect(actualAddr, allModules))
//                                        {
//                                            AnalyzeHook(moduleToScan, dllName, funcName, expectedAddr, actualAddr, allModules, regions, results, process);
//                                        }
//                                    }
//                                }
//                            }
//                            index++;
//                        }
//                        currentOffset += descriptorSize;
//                    }
//                }
//                finally { handle.Free(); }
//            }
//            catch (Exception ex)
//            {
//                _logger?.Log(LogLevel.Debug, $"IatScanner failed for {moduleToScan.BaseDllName}", ex);
//            }
//            return results;
//        }

//        /// <summary>
//        /// Prüft, ob eine Adresse in ein vertrauenswürdiges System-Modul zeigt.
//        /// Das eliminiert Forwarder (Kernel32->Kernelbase) und API-Sets als False Positives.
//        /// </summary>
//        private bool IsSafeSystemRedirect(IntPtr actualAddress, List<ProcessModuleInfo> allModules)
//        {
//            ulong addr = (ulong)actualAddress.ToInt64();

//            // 1. Welches Modul besitzt diese Adresse?
//            var targetMod = allModules.FirstOrDefault(m =>
//                addr >= (ulong)m.DllBase.ToInt64() &&
//                addr < (ulong)m.DllBase.ToInt64() + m.SizeOfImage);

//            if (targetMod == null)
//            {
//                // Zeigt nirgendwo hin (Heap, Stack, Unmapped) -> HOCHGRADIG VERDÄCHTIG (Shellcode!)
//                return false;
//            }

//            string path = targetMod.FullDllName?.ToLowerInvariant();
//            if (string.IsNullOrEmpty(path)) return false;

//            // 2. Ist dieses Modul ein System-Pfad?
//            bool isSystemPath = path.StartsWith(_system32Path) ||
//                                path.StartsWith(_sysWow64Path) ||
//                                path.Contains("\\winsxs\\") ||
//                                path.Contains("microsoft.net"); // .NET Framework hat viele interne Redirects

//            if (!isSystemPath) return false; // Zeigt in eine fremde, nicht-System DLL -> Verdächtig (aber evtl. signed)

//            // 3. Ist das Modul signiert von Microsoft? (Der ultimative Check)
//            // Wir nutzen den Cache, um nicht 24.000 mal die Festplatte zu fragen.
//            if (!_signatureCache.TryGetValue(path, out bool isSignedMs))
//            {
//                try
//                {
//                    var sig = SignatureVerifier.Verify(path); // DEIN Code
//                    isSignedMs = sig.IsSigned &&
//                                 (sig.SignerName.Contains("Microsoft") || sig.SignerName.Contains("Windows"));
//                }
//                catch { isSignedMs = false; }

//                _signatureCache[path] = isSignedMs;
//            }

//            return isSignedMs; // Wenn es Microsoft-signiert ist, ist der Redirect sicher.
//        }

//        private void AnalyzeHook(
//            ProcessModuleInfo moduleToScan,
//            string dllName,
//            string funcName,
//            IntPtr expected,
//            IntPtr actual,
//            List<ProcessModuleInfo> allModules,
//            List<VirtualMemoryRegion> regions,
//            List<SecurityInspector.IatHookInfo> results,
//            ManagedProcess process)
//        {
//            string targetLoc = _inspector.ResolveTargetAddress(actual, process, allModules, regions);

//            // Double Check: Wenn ResolveTargetAddress sagt, es ist eine signierte DLL, dann raus.
//            // (Passiert, wenn wir oben im Loop was übersehen haben oder der Pfad anders formatiert ist)
//            if (_inspector.IsSafeHookTarget(targetLoc, allModules)) return;

//            string severity = "Medium";

//            // Wenn es in privaten Speicher (Unbacked) zeigt -> CRITICAL (Shellcode / Manual Map)
//            if (targetLoc.StartsWith("PRIVATE") || targetLoc.Contains("Unbacked"))
//            {
//                severity = "Critical";
//            }
//            // Wenn es in ein Modul zeigt, das NICHT im Windows-Ordner liegt -> High
//            else if (!targetLoc.ToLower().Contains("windows"))
//            {
//                severity = "High";
//            }
//            else
//            {
//                // Wenn es im Windows Ordner liegt, aber wir es hier haben, ist es vllt. eine unsignierte DLL dort?
//                // Oder ein Hook von einer AV/EDR Software (die hängen sich oft rein).
//                severity = "Medium";
//            }

//            results.Add(new SecurityInspector.IatHookInfo
//            {
//                ModuleName = moduleToScan.BaseDllName,
//                FunctionName = $"{dllName}!{funcName}",
//                ExpectedAddress = expected,
//                ActualAddress = actual,
//                TargetModule = targetLoc,
//                IsSafe = false
//            });
//        }
//    }
//}