//using System;
//using System.Collections.Generic;
//using System.IO;
//using System.Linq;
//using System.Runtime.InteropServices;
//using NativeProcesses.Core.Engine;
//using NativeProcesses.Core.Models;
//using NativeProcesses.Core.Native;
//using NativeProcesses.Core.PE;
//using NativeProcesses.Core.PE.Loader;

//namespace NativeProcesses.Core.Inspection
//{
//    public class IatScanner
//    {
//        private readonly IEngineLogger _logger;
//        private readonly SecurityInspector _inspector;
//        private readonly string _system32Path;
//        private readonly string _sysWow64Path;

//        // Signatur-Cache
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
//        }

//        public List<SecurityInspector.IatHookInfo> ScanModule(
//            ManagedProcess process,
//            ProcessModuleInfo moduleToScan,
//            List<ProcessModuleInfo> allModules,
//            List<VirtualMemoryRegion> regions)
//        {
//            var results = new List<SecurityInspector.IatHookInfo>();

//            // --------------------------------------------------------------------------
//            // STEP 1: FILTERUNG (Wie pe-sieve "internal_module_filter")
//            // --------------------------------------------------------------------------

//            if (string.IsNullOrEmpty(moduleToScan.FullDllName)) return results;
//            string modulePath = moduleToScan.FullDllName.ToLowerInvariant();

//            // Check 1: Existiert die Datei?
//            if (!File.Exists(moduleToScan.FullDllName)) return results;

//            // Check 2: Ist es eine System-DLL? (Wir scannen keine IATs von Windows-Komponenten)
//            // Windows leitet intern ständig um (kernel32 -> kernelbase -> ntdll). Das zu scannen erzeugt 12k+ False Positives.
//            bool isSystemDll = modulePath.StartsWith(_system32Path) ||
//                               modulePath.StartsWith(_sysWow64Path) ||
//                               modulePath.Contains("\\winsxs\\");

//            // Wir scannen IMMER das Hauptmodul (die .exe), egal wo es liegt.
//            bool isMainModule = (moduleToScan.DllBase == GetMainModuleBase(process));

//            if (isSystemDll && !isMainModule)
//            {
//                // Wenn es eine System-DLL ist UND nicht das Hauptprogramm, überspringen wir den Scan.
//                // Das eliminiert 99% des Rauschens.
//                return results;
//            }

//            // Check 3: .NET Runtime ignorieren (zuviel JIT/Hooking intern)
//            if (modulePath.Contains("mscoree.dll") || modulePath.Contains("clr.dll")) return results;

//            // --------------------------------------------------------------------------
//            // STEP 2: SCANNEN
//            // --------------------------------------------------------------------------

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
//                    if (!dos.IsValid) return results; // Nutzung der neuen IsValid Property

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

//                        // Filter: Wir interessieren uns nicht für Imports aus API-Sets (virtuelle DLLs)
//                        if (string.IsNullOrEmpty(dllName) || dllName.StartsWith("api-ms-", StringComparison.OrdinalIgnoreCase) || dllName.StartsWith("ext-ms-", StringComparison.OrdinalIgnoreCase))
//                        {
//                            currentOffset += descriptorSize;
//                            continue;
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
//                            IntPtr expectedAddr = IntPtr.Zero;
//                            string funcName = "";

//                            // Thunk parsen
//                            if (is64Bit)
//                            {
//                                ulong rawThunk = (ulong)Marshal.ReadInt64(thunkPtr);
//                                if (rawThunk == 0) break;
//                                if ((rawThunk & 0x8000000000000000) != 0) // Ordinal
//                                    expectedAddr = GetProcAddress(hLib, (IntPtr)(rawThunk & 0xFFFF));
//                                else // Name
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
//                                if ((rawThunk & 0x80000000) != 0) // Ordinal
//                                    expectedAddr = GetProcAddress(hLib, (IntPtr)(rawThunk & 0xFFFF));
//                                else // Name
//                                {
//                                    funcName = Marshal.PtrToStringAnsi(IntPtr.Add(basePtr, (int)rawThunk + 2));
//                                    expectedAddr = GetProcAddress(hLib, funcName);
//                                }
//                            }

//                            if (expectedAddr != IntPtr.Zero)
//                            {
//                                // Remote Wert lesen
//                                IntPtr remoteIatPtr = IntPtr.Add(moduleToScan.DllBase, (int)(iatRva + (index * ptrSize)));
//                                byte[] remoteValBytes = process.ReadMemory(remoteIatPtr, ptrSize);

//                                if (remoteValBytes != null)
//                                {
//                                    IntPtr actualAddr = is64Bit
//                                        ? (IntPtr)BitConverter.ToInt64(remoteValBytes, 0)
//                                        : (IntPtr)BitConverter.ToInt32(remoteValBytes, 0);

//                                    if (actualAddr != expectedAddr)
//                                    {
//                                        // Hier prüft pe-sieve: "Ist die actualAddr wenigstens in EINER vertrauenswürdigen DLL?"
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

//        private IntPtr GetMainModuleBase(ManagedProcess process)
//        {
//            // Einfache Heuristik: Das erste Modul im PEB ist meist das Main Module.
//            // Da wir das hier nicht zur Hand haben, verlassen wir uns auf eine saubere Architektur im Aufrufer.
//            // Aber für IatScanner können wir versuchen, das erste Modul der Liste zu nehmen, wenn es .exe heißt.
//            return IntPtr.Zero; // (Implementierung siehe unten/optional)
//        }

//        private bool IsSafeSystemRedirect(IntPtr actualAddress, List<ProcessModuleInfo> allModules)
//        {
//            ulong addr = (ulong)actualAddress.ToInt64();

//            foreach (var mod in allModules)
//            {
//                ulong start = (ulong)mod.DllBase.ToInt64();
//                ulong end = start + mod.SizeOfImage;

//                if (addr >= start && addr < end)
//                {
//                    string path = mod.FullDllName?.ToLowerInvariant();
//                    if (string.IsNullOrEmpty(path)) return false;

//                    // Wenn es in System32 oder WinSxS landet, ist es meist OK (Forwarder)
//                    if (path.StartsWith(_system32Path) ||
//                        path.StartsWith(_sysWow64Path) ||
//                        path.Contains("\\winsxs\\") ||
//                        path.Contains("microsoft.net"))
//                    {
//                        return true;
//                    }

//                    // Signatur Check (Cache nutzen!)
//                    if (!_signatureCache.TryGetValue(path, out bool isSigned))
//                    {
//                        var sig = SignatureVerifier.Verify(path);
//                        isSigned = sig.IsSigned && (sig.SignerName.Contains("Microsoft") || sig.SignerName.Contains("Windows"));
//                        _signatureCache[path] = isSigned;
//                    }

//                    if (isSigned) return true; // Redirect in signiertes Modul -> OK.

//                    return false; // Redirect in unsigniertes Modul -> Hook!
//                }
//            }
//            return false; // Zeigt in den Heap/Shellcode -> CRITICAL Hook!
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
//            string severity = "Medium";

//            if (targetLoc.StartsWith("PRIVATE") || targetLoc.Contains("Unbacked"))
//            {
//                severity = "Critical"; // Zeigt auf Shellcode
//            }
//            else if (!targetLoc.ToLower().Contains("windows"))
//            {
//                severity = "High"; // Zeigt auf fremde DLL
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