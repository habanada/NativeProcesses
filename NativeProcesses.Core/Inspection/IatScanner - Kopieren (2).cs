///*
//   NativeProcesses Framework
//   IatScanner.cs - Forensic Edition
//   Classifies hooks by Trust Level (System, Microsoft, Trusted, Suspicious, Malicious)
//*/
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

//        // Cache für Signaturen (Pfad -> SignerInfo)
//        private static readonly Dictionary<string, (bool IsSigned, string Signer)> _signatureCache
//            = new Dictionary<string, (bool, string)>(StringComparer.OrdinalIgnoreCase);

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

//            if (string.IsNullOrEmpty(moduleToScan.FullDllName) || !File.Exists(moduleToScan.FullDllName))
//                return results;

//            // Filter: System-DLLs überspringen, außer es ist das Hauptmodul
//            // Das reduziert Rauschen enorm.
//            // bool isSystemDll = moduleToScan.FullDllName.ToLowerInvariant().StartsWith(_system32Path);
//            // if (isSystemDll) return results; // Optional: Deaktivieren für Deep Scan

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
//                    if (!dos.IsValid) return results;

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

//                        if (string.IsNullOrEmpty(dllName) ||
//                            dllName.StartsWith("api-ms-", StringComparison.OrdinalIgnoreCase) ||
//                            dllName.StartsWith("ext-ms-", StringComparison.OrdinalIgnoreCase) ||
//                            dllName.StartsWith("mscoree", StringComparison.OrdinalIgnoreCase))
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
//                            string funcName = null;
//                            IntPtr expectedAddr = IntPtr.Zero;

//                            if (is64Bit)
//                            {
//                                ulong rawThunk = (ulong)Marshal.ReadInt64(thunkPtr);
//                                if (rawThunk == 0) break;
//                                if ((rawThunk & 0x8000000000000000) != 0)
//                                {
//                                    expectedAddr = GetProcAddress(hLib, (IntPtr)(rawThunk & 0xFFFF));
//                                    funcName = $"Ordinal_{rawThunk & 0xFFFF}";
//                                }
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
//                                {
//                                    expectedAddr = GetProcAddress(hLib, (IntPtr)(rawThunk & 0xFFFF));
//                                    funcName = $"Ordinal_{rawThunk & 0xFFFF}";
//                                }
//                                else
//                                {
//                                    funcName = Marshal.PtrToStringAnsi(IntPtr.Add(basePtr, (int)rawThunk + 2));
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

//                                    // --- DIFFERENZ GEFUNDEN ---
//                                    if (actualAddr != expectedAddr)
//                                    {
//                                        // Jetzt klassifizieren wir den Hook, anstatt ihn zu verwerfen!
//                                        var trustInfo = AnalyzeHookTarget(actualAddr, allModules, regions);

//                                        // Filter: Wenn wir nur Malware wollen, ignorieren wir System/Microsoft/ThirdParty
//                                        // Aber für das "Mega Feature" geben wir alles zurück und lassen die UI filtern.

//                                        bool isSafe = trustInfo.Trust == HookTrustLevel.System ||
//                                                      trustInfo.Trust == HookTrustLevel.Microsoft ||
//                                                      trustInfo.Trust == HookTrustLevel.ThirdParty;

//                                        results.Add(new SecurityInspector.IatHookInfo
//                                        {
//                                            ModuleName = moduleToScan.BaseDllName,
//                                            FunctionName = $"{dllName}!{funcName}",
//                                            ExpectedAddress = expectedAddr,
//                                            ActualAddress = actualAddr,
//                                            TargetModule = trustInfo.TargetName,
//                                            TrustLevel = trustInfo.Trust,
//                                            Signer = trustInfo.Signer,
//                                            IsSafe = isSafe
//                                        });
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

//        private (HookTrustLevel Trust, string Signer, string TargetName) AnalyzeHookTarget(
//            IntPtr actualAddress,
//            List<ProcessModuleInfo> allModules,
//            List<VirtualMemoryRegion> regions)
//        {
//            ulong addr = (ulong)actualAddress.ToInt64();

//            // 1. Liegt es in einem Modul?
//            var targetMod = allModules.FirstOrDefault(m =>
//                addr >= (ulong)m.DllBase.ToInt64() &&
//                addr < (ulong)m.DllBase.ToInt64() + m.SizeOfImage);

//            if (targetMod != null)
//            {
//                string path = targetMod.FullDllName?.ToLowerInvariant();
//                string moduleName = targetMod.BaseDllName;

//                if (string.IsNullOrEmpty(path))
//                    return (HookTrustLevel.Suspicious, "Unknown", moduleName);

//                // Signatur Check (Cached)
//                if (!_signatureCache.TryGetValue(path, out var sigInfo))
//                {
//                    try
//                    {
//                        var sig = SignatureVerifier.Verify(path);
//                        sigInfo = (sig.IsSigned, sig.SignerName);
//                    }
//                    catch { sigInfo = (false, "Error"); }

//                    _signatureCache[path] = sigInfo;
//                }

//                if (sigInfo.IsSigned)
//                {
//                    if (sigInfo.Signer.Contains("Microsoft") || sigInfo.Signer.Contains("Windows"))
//                    {
//                        // Microsoft Signiert
//                        // System32?
//                        if (path.StartsWith(_system32Path) || path.StartsWith(_sysWow64Path) || path.Contains("\\winsxs\\"))
//                        {
//                            return (HookTrustLevel.System, sigInfo.Signer, moduleName);
//                        }
//                        // Visual Studio etc.
//                        return (HookTrustLevel.Microsoft, sigInfo.Signer, moduleName);
//                    }
//                    else
//                    {
//                        // Google, Mozilla, AVs
//                        return (HookTrustLevel.ThirdParty, sigInfo.Signer, moduleName);
//                    }
//                }
//                else
//                {
//                    return (HookTrustLevel.Suspicious, "Unsigned", moduleName);
//                }
//            }

//            // 2. Liegt es in Shellcode (Private/Unbacked)?
//            // Wir nutzen den Inspector Helper oder suchen manuell in Regions
//            string regionInfo = "Unbacked Memory";
//            var region = regions.FirstOrDefault(r =>
//                addr >= (ulong)r.BaseAddress.ToInt64() &&
//                addr < (ulong)r.BaseAddress.ToInt64() + (ulong)r.RegionSize);

//            if (region != null)
//            {
//                regionInfo = $"{region.Type} ({region.Protection})";
//            }

//            return (HookTrustLevel.Malicious, "None", regionInfo);
//        }
//    }
//}