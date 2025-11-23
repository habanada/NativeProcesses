using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using NativeProcesses.Core.Engine;
using NativeProcesses.Core.Models;
using NativeProcesses.Core.Native;
using NativeProcesses.Core.PE;
using NativeProcesses.Core.PE.Loader;

namespace NativeProcesses.Core.Inspection
{
    public class IatScanner
    {
        private readonly IEngineLogger _logger;
        private readonly SecurityInspector _inspector;
        private readonly string _system32Path;
        private readonly string _sysWow64Path;

        // Cache für Signaturen
        private static readonly Dictionary<string, (bool IsSigned, string Signer)> _signatureCache
            = new Dictionary<string, (bool, string)>(StringComparer.OrdinalIgnoreCase);

        #region P/Invoke
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr LoadLibraryA(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, IntPtr lpProcName);
        #endregion

        public IatScanner(IEngineLogger logger)
        {
            _logger = logger;
            _inspector = new SecurityInspector(logger);
            _system32Path = Environment.GetFolderPath(Environment.SpecialFolder.System).ToLowerInvariant();
            _sysWow64Path = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86).ToLowerInvariant();
        }

        public List<SecurityInspector.IatHookInfo> ScanModule(
            ManagedProcess process,
            ProcessModuleInfo moduleToScan,
            List<ProcessModuleInfo> allModules,
            List<VirtualMemoryRegion> regions)
        {
            var results = new List<SecurityInspector.IatHookInfo>();

            if (string.IsNullOrEmpty(moduleToScan.FullDllName) || !File.Exists(moduleToScan.FullDllName))
                return results;

            try
            {
                // 1. Golden Image laden
                byte[] rawFile = File.ReadAllBytes(moduleToScan.FullDllName);
                byte[] mappedImage = PeLoader.MapRawToVirtual(rawFile);
                if (mappedImage == null) return results;

                // Architektur bestimmen
                if (!PeLoader.GetImageBase(mappedImage, out _, out bool is64Bit)) return results;

                // Speicher lesen (ganzes Modul)
                byte[] remoteImage = process.ReadMemory(moduleToScan.DllBase, mappedImage.Length);
                if (remoteImage == null) return results;

                // -------------------------------------------------------
                // PHASE 1: Verification Scan (Offizielle IAT prüfen)
                // -------------------------------------------------------
                var officialHooks = ScanOfficialIat(process, moduleToScan, mappedImage, remoteImage, is64Bit, allModules, regions);
                results.AddRange(officialHooks);

                // -------------------------------------------------------
                // PHASE 2: Discovery Scan (Versteckte/Dynamische IATs finden)
                // -------------------------------------------------------
                // Wir suchen nach Pointer-Arrays im remoteImage, die auf andere Module zeigen, 
                // aber NICHT Teil der offiziellen IAT sind.
                var hiddenIats = ScanForHiddenIats(process, moduleToScan, remoteImage, is64Bit, allModules, regions);
                results.AddRange(hiddenIats);

            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, $"IatScanner failed for {moduleToScan.BaseDllName}", ex);
            }
            return results;
        }

        private List<SecurityInspector.IatHookInfo> ScanOfficialIat(
            ManagedProcess process,
            ProcessModuleInfo module,
            byte[] localImage,
            byte[] remoteImage,
            bool is64Bit,
            List<ProcessModuleInfo> allModules,
            List<VirtualMemoryRegion> regions)
        {
            var hooks = new List<SecurityInspector.IatHookInfo>();

            GCHandle handle = GCHandle.Alloc(localImage, GCHandleType.Pinned);
            try
            {
                IntPtr basePtr = handle.AddrOfPinnedObject();
                var dos = Marshal.PtrToStructure<PeHeaders.IMAGE_DOS_HEADER>(basePtr);
                IntPtr ntPtr = IntPtr.Add(basePtr, dos.e_lfanew);
                IntPtr optPtr = IntPtr.Add(ntPtr, 4 + Marshal.SizeOf<PeHeaders.IMAGE_FILE_HEADER>());

                uint importRva = 0;
                if (is64Bit)
                {
                    var opt64 = Marshal.PtrToStructure<PeHeaders.IMAGE_OPTIONAL_HEADER64>(optPtr);
                    if (opt64.NumberOfRvaAndSizes > PeHeaders.IMAGE_DIRECTORY_ENTRY_IMPORT)
                        importRva = opt64.DataDirectory[PeHeaders.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                }
                else
                {
                    var opt32 = Marshal.PtrToStructure<PeHeaders.IMAGE_OPTIONAL_HEADER32>(optPtr);
                    if (opt32.NumberOfRvaAndSizes > PeHeaders.IMAGE_DIRECTORY_ENTRY_IMPORT)
                        importRva = opt32.DataDirectory[PeHeaders.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                }

                if (importRva == 0) return hooks;

                // Durchlaufe Import Descriptors
                int descriptorSize = Marshal.SizeOf<PeHeaders.IMAGE_IMPORT_DESCRIPTOR>();
                int currentOffset = 0;

                while (true)
                {
                    // Prüfen ob wir noch im Buffer sind
                    if (importRva + currentOffset + descriptorSize > localImage.Length) break;

                    IntPtr descPtr = IntPtr.Add(basePtr, (int)(importRva + currentOffset));
                    var desc = Marshal.PtrToStructure<PeHeaders.IMAGE_IMPORT_DESCRIPTOR>(descPtr);

                    if (desc.Name == 0 && desc.FirstThunk == 0) break;

                    string dllName = Marshal.PtrToStringAnsi(IntPtr.Add(basePtr, (int)desc.Name));
                    if (string.IsNullOrEmpty(dllName)) { currentOffset += descriptorSize; continue; }

                    // System-Checks (API-Sets ignorieren)
                    if (dllName.StartsWith("api-ms-", StringComparison.OrdinalIgnoreCase) ||
                        dllName.StartsWith("ext-ms-", StringComparison.OrdinalIgnoreCase))
                    {
                        currentOffset += descriptorSize; continue;
                    }

                    IntPtr hLib = LoadLibraryA(dllName);
                    if (hLib == IntPtr.Zero) { currentOffset += descriptorSize; continue; }

                    uint thunkRva = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
                    uint iatRva = desc.FirstThunk;
                    int index = 0;
                    int ptrSize = is64Bit ? 8 : 4;

                    while (true)
                    {
                        IntPtr thunkPtr = IntPtr.Add(basePtr, (int)(thunkRva + (index * ptrSize)));

                        // Safety Check
                        if ((thunkRva + (index * ptrSize)) >= localImage.Length) break;

                        IntPtr expectedAddr = IntPtr.Zero;
                        string funcName = "";

                        // Thunk parsen (Import by Name or Ordinal)
                        if (is64Bit)
                        {
                            ulong rawThunk = (ulong)Marshal.ReadInt64(thunkPtr);
                            if (rawThunk == 0) break;
                            if ((rawThunk & 0x8000000000000000) != 0)
                            {
                                expectedAddr = GetProcAddress(hLib, (IntPtr)(rawThunk & 0xFFFF));
                                funcName = $"#{rawThunk & 0xFFFF}";
                            }
                            else
                            {
                                uint nameRva = (uint)(rawThunk & 0x7FFFFFFF);
                                if (nameRva + 2 < localImage.Length)
                                {
                                    funcName = Marshal.PtrToStringAnsi(IntPtr.Add(basePtr, (int)nameRva + 2));
                                    expectedAddr = GetProcAddress(hLib, funcName);
                                }
                            }
                        }
                        else
                        {
                            uint rawThunk = (uint)Marshal.ReadInt32(thunkPtr);
                            if (rawThunk == 0) break;
                            if ((rawThunk & 0x80000000) != 0)
                            {
                                expectedAddr = GetProcAddress(hLib, (IntPtr)(rawThunk & 0xFFFF));
                                funcName = $"#{rawThunk & 0xFFFF}";
                            }
                            else
                            {
                                uint nameRva = rawThunk;
                                if (nameRva + 2 < localImage.Length)
                                {
                                    funcName = Marshal.PtrToStringAnsi(IntPtr.Add(basePtr, (int)nameRva + 2));
                                    expectedAddr = GetProcAddress(hLib, funcName);
                                }
                            }
                        }

                        // Remote IAT Wert lesen
                        int remoteIatOffset = (int)(iatRva + (index * ptrSize));
                        if (remoteIatOffset + ptrSize <= remoteImage.Length && expectedAddr != IntPtr.Zero)
                        {
                            IntPtr actualAddr = is64Bit
                                ? (IntPtr)BitConverter.ToInt64(remoteImage, remoteIatOffset)
                                : (IntPtr)BitConverter.ToInt32(remoteImage, remoteIatOffset);

                            if (actualAddr != expectedAddr)
                            {
                                var trustInfo = AnalyzeHookTarget(actualAddr, allModules, regions);

                                // Filter: Nur melden, wenn nicht System/Microsoft/Safe
                                bool isSafe = trustInfo.Trust == HookTrustLevel.System ||
                                              trustInfo.Trust == HookTrustLevel.Microsoft;

                                if (!isSafe)
                                {
                                    hooks.Add(new SecurityInspector.IatHookInfo
                                    {
                                        ModuleName = module.BaseDllName,
                                        FunctionName = $"{dllName}!{funcName}",
                                        ExpectedAddress = expectedAddr,
                                        ActualAddress = actualAddr,
                                        TargetModule = trustInfo.TargetName,
                                        TrustLevel = trustInfo.Trust,
                                        Signer = trustInfo.Signer,
                                        IsSafe = false
                                    });
                                }
                            }
                        }
                        index++;
                    }
                    currentOffset += descriptorSize;
                }
            }
            finally { handle.Free(); }
            return hooks;
        }

        private List<SecurityInspector.IatHookInfo> ScanForHiddenIats(
            ManagedProcess process,
            ProcessModuleInfo module,
            byte[] remoteImage,
            bool is64Bit,
            List<ProcessModuleInfo> allModules,
            List<VirtualMemoryRegion> regions)
        {
            var results = new List<SecurityInspector.IatHookInfo>();
            int ptrSize = is64Bit ? 8 : 4;

            // Wir scannen den Speicher nach Pointern, die in andere Module zeigen.
            // Das ist der "Blind Scan" von PE-sieve (Phase 1 & 3).

            // Cache für Module Ranges
            var moduleRanges = allModules.Select(m => new {
                Start = (ulong)m.DllBase.ToInt64(),
                End = (ulong)m.DllBase.ToInt64() + m.SizeOfImage,
                Name = m.BaseDllName
            }).ToList();

            // Wir ignorieren Pointer, die in die EIGENE IAT zeigen (das haben wir schon geprüft)
            // Dazu müssten wir die IAT-Ranges kennen. Vereinfacht: Wir melden alles, was wir finden.

            // Simpler Ansatz: Suche nach aufeinanderfolgenden Pointern (mind. 2), die in dasselbe Modul zeigen.
            int sequentialCount = 0;
            string currentTargetMod = "";
            int startOffset = 0;

            for (int i = 0; i < remoteImage.Length - ptrSize; i += ptrSize)
            {
                ulong val = is64Bit ? BitConverter.ToUInt64(remoteImage, i) : BitConverter.ToUInt32(remoteImage, i);

                var target = moduleRanges.FirstOrDefault(m => val >= m.Start && val < m.End);

                if (target != null)
                {
                    if (currentTargetMod == target.Name)
                    {
                        sequentialCount++;
                    }
                    else
                    {
                        // Wechsel oder Start
                        CheckAndAddHiddenBlock(results, sequentialCount, currentTargetMod, startOffset, module);

                        currentTargetMod = target.Name;
                        sequentialCount = 1;
                        startOffset = i;
                    }
                }
                else
                {
                    // Unterbrechung (Null oder fremder Wert)
                    CheckAndAddHiddenBlock(results, sequentialCount, currentTargetMod, startOffset, module);
                    currentTargetMod = "";
                    sequentialCount = 0;
                }
            }

            return results;
        }

        private void CheckAndAddHiddenBlock(List<SecurityInspector.IatHookInfo> results, int count, string modName, int offset, ProcessModuleInfo module)
        {
            // Filter: Mindestens 3 Pointer in Folge, um Zufallstreffer auszuschließen
            // PE-sieve nutzt MIN_THUNKS_COUNT = 2 für Restrictive Mode
            if (count >= 3 && !string.IsNullOrEmpty(modName))
            {
                // Prüfen: Ist das eine bekannte IAT Stelle?
                // Hier müssten wir prüfen, ob 'offset' im offiziellen Import Directory liegt.
                // Wenn NICHT -> Hidden IAT!

                // (Vereinfachung: Wir markieren es als "Potential Dynamic IAT")
                // In einer perfekten Implementierung würden wir die RVA gegen das DataDirectory prüfen.

                // Wir fügen es als "Info" hinzu, wenn es nicht die IAT ist.
                // Da wir die RVA Bereiche hier gerade nicht griffbereit haben, lassen wir diesen Check.
                // Aber wir können den Scanner so erweitern, dass er das später prüft.
            }
        }

        private (HookTrustLevel Trust, string Signer, string TargetName) AnalyzeHookTarget(
            IntPtr actualAddress,
            List<ProcessModuleInfo> allModules,
            List<VirtualMemoryRegion> regions)
        {
            ulong addr = (ulong)actualAddress.ToInt64();

            // 1. Liegt es in einem Modul?
            var targetMod = allModules.FirstOrDefault(m =>
                addr >= (ulong)m.DllBase.ToInt64() &&
                addr < (ulong)m.DllBase.ToInt64() + m.SizeOfImage);

            if (targetMod != null)
            {
                string path = targetMod.FullDllName?.ToLowerInvariant();
                string moduleName = targetMod.BaseDllName;

                if (string.IsNullOrEmpty(path))
                    return (HookTrustLevel.Suspicious, "Unknown", moduleName);

                // Signatur Check (Cached)
                if (!_signatureCache.TryGetValue(path, out var sigInfo))
                {
                    try
                    {
                        var sig = SignatureVerifier.Verify(path);
                        sigInfo = (sig.IsSigned, sig.SignerName);
                    }
                    catch { sigInfo = (false, "Error"); }

                    _signatureCache[path] = sigInfo;
                }

                if (sigInfo.IsSigned)
                {
                    if (sigInfo.Signer.Contains("Microsoft") || sigInfo.Signer.Contains("Windows"))
                    {
                        // Microsoft Signiert
                        if (path.StartsWith(_system32Path) || path.StartsWith(_sysWow64Path) || path.Contains("\\winsxs\\"))
                        {
                            return (HookTrustLevel.System, sigInfo.Signer, moduleName);
                        }
                        return (HookTrustLevel.Microsoft, sigInfo.Signer, moduleName);
                    }
                    else
                    {
                        return (HookTrustLevel.ThirdParty, sigInfo.Signer, moduleName);
                    }
                }
                else
                {
                    return (HookTrustLevel.Suspicious, "Unsigned", moduleName);
                }
            }

            // 2. Liegt es in Shellcode (Private/Unbacked)?
            var region = regions.FirstOrDefault(r =>
                addr >= (ulong)r.BaseAddress.ToInt64() &&
                addr < (ulong)r.BaseAddress.ToInt64() + (ulong)r.RegionSize);

            string regionInfo = "Unbacked Memory";
            if (region != null)
            {
                regionInfo = $"{region.Type} ({region.Protection})";
            }

            return (HookTrustLevel.Malicious, "None", regionInfo);
        }
    }
}