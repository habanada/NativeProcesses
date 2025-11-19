using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using NativeProcesses.Core.Engine;
using NativeProcesses.Core.Models;
using NativeProcesses.Core.Native;

namespace NativeProcesses.Core.Inspection
{
    public class PeAnomalyScanner
    {
        private readonly IEngineLogger _logger;

        public PeAnomalyScanner(IEngineLogger logger)
        {
            _logger = logger;
        }

        public List<PeAnomalyInfo> ScanModule(ManagedProcess process, ProcessModuleInfo module)
        {
            var anomalies = new List<PeAnomalyInfo>();

            if (string.IsNullOrEmpty(module.FullDllName) || !File.Exists(module.FullDllName))
            {
                return anomalies;
            }

            try
            {
                byte[] diskHeader = ReadHeaderFromDisk(module.FullDllName);
                byte[] memHeader = process.ReadMemory(module.DllBase, 4096);

                if (diskHeader == null || memHeader == null || diskHeader.Length < 512 || memHeader.Length < 512)
                {
                    return anomalies;
                }

                var diskNt = ParseNtHeaders(diskHeader);
                var memNt = ParseNtHeaders(memHeader);

                int iocScore = 0;
                string iocDetails = "";

                if (memHeader[0] != 'M' || memHeader[1] != 'Z')
                {
                    iocScore += 10;
                    iocDetails += "[Critical] MZ Signature wiped. ";
                }

                if (diskNt.IsValid && memNt.IsValid)
                {
                    if (memNt.AddressOfEntryPoint != diskNt.AddressOfEntryPoint)
                    {
                        iocScore += 3;
                        iocDetails += $"[Suspicious] EP Modified (Disk: {diskNt.AddressOfEntryPoint:X} != Mem: {memNt.AddressOfEntryPoint:X}). ";
                    }

                    if (memNt.SizeOfImage != diskNt.SizeOfImage)
                    {
                        iocScore += 2;
                        iocDetails += $"[Info] SizeOfImage mismatch. ";
                    }

                    if (memNt.NumberOfSections != diskNt.NumberOfSections)
                    {
                        iocScore += 5;
                        iocDetails += $"[High] Section Count mismatch ({memNt.NumberOfSections} vs {diskNt.NumberOfSections}). ";
                    }

                    CheckSections(process, module, memHeader, memNt, anomalies, ref iocScore);
                }
                else
                {
                    iocScore += 5;
                    iocDetails += "[High] Invalid NT Headers in memory. ";
                }

                if (iocScore >= 5)
                {
                    anomalies.Add(new PeAnomalyInfo
                    {
                        ModuleName = module.BaseDllName,
                        AnomalyType = iocScore >= 10 ? "Process Hollowing / Stomping" : "Header Anomalies",
                        Details = $"IOC Score: {iocScore}. {iocDetails}",
                        Severity = iocScore >= 10 ? "Critical" : "High"
                    });
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, $"Scan failed for {module.BaseDllName}", ex);
            }

            return anomalies;
        }

        private void CheckSections(ManagedProcess process, ProcessModuleInfo module, byte[] memBuffer, NtHeaderInfo ntInfo, List<PeAnomalyInfo> anomalies, ref int score)
        {
            int sectionHeaderOffset = ntInfo.SectionHeaderOffset;
            int numberOfSections = ntInfo.NumberOfSections;
            int sectionSize = 40;

            for (int i = 0; i < numberOfSections; i++)
            {
                int currentOffset = sectionHeaderOffset + (i * sectionSize);
                if (currentOffset + sectionSize > memBuffer.Length) break;

                uint virtualAddress = BitConverter.ToUInt32(memBuffer, currentOffset + 12);
                uint virtualSize = BitConverter.ToUInt32(memBuffer, currentOffset + 8);
                uint characteristics = BitConverter.ToUInt32(memBuffer, currentOffset + 36);

                string name = System.Text.Encoding.ASCII.GetString(memBuffer, currentOffset, 8).TrimEnd('\0');

                bool isMemExecute = (characteristics & 0x20000000) != 0;
                bool isMemWrite = (characteristics & 0x80000000) != 0;

                if (isMemExecute && isMemWrite)
                {
                    IntPtr sectionAddress = IntPtr.Add(module.DllBase, (int)virtualAddress);
                    long readSize = Math.Min(virtualSize, 4096);

                    try
                    {
                        byte[] content = process.ReadMemory(sectionAddress, (int)readSize);

                        if (ShellcodeDetector.IsLikelyShellcode(content, out string reason))
                        {
                            if (reason != "Clean")
                            {
                                anomalies.Add(new PeAnomalyInfo
                                {
                                    ModuleName = module.BaseDllName,
                                    AnomalyType = "Malicious RWX Code",
                                    Details = $"Section '{name}' is RWX. {reason}",
                                    Severity = "Critical"
                                });
                            }
                        }
                    }
                    catch { }
                }

                if (name.Equals(".text", StringComparison.OrdinalIgnoreCase) && isMemWrite)
                {
                    score += 4;
                    anomalies.Add(new PeAnomalyInfo
                    {
                        ModuleName = module.BaseDllName,
                        AnomalyType = "Writable Code Section",
                        Details = $".text section has WRITE permission. Unusual for legit modules.",
                        Severity = "Medium"
                    });
                }
            }
        }

        private byte[] ReadHeaderFromDisk(string path)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var br = new BinaryReader(fs))
                {
                    return br.ReadBytes(4096);
                }
            }
            catch
            {
                return null;
            }
        }

        private NtHeaderInfo ParseNtHeaders(byte[] buffer)
        {
            var info = new NtHeaderInfo { IsValid = false };
            try
            {
                int e_lfanew = BitConverter.ToInt32(buffer, 0x3C);
                if (e_lfanew > buffer.Length - 256) return info;

                uint signature = BitConverter.ToUInt32(buffer, e_lfanew);
                if (signature != 0x00004550) return info;

                info.NumberOfSections = BitConverter.ToUInt16(buffer, e_lfanew + 4 + 2);
                ushort sizeOfOptionalHeader = BitConverter.ToUInt16(buffer, e_lfanew + 4 + 16);
                int optionalHeaderOffset = e_lfanew + 24;

                ushort magic = BitConverter.ToUInt16(buffer, optionalHeaderOffset);
                bool is64Bit = (magic == 0x20B);

                info.SizeOfImage = BitConverter.ToUInt32(buffer, optionalHeaderOffset + 56);
                info.AddressOfEntryPoint = BitConverter.ToUInt32(buffer, optionalHeaderOffset + 16);
                info.SectionHeaderOffset = optionalHeaderOffset + sizeOfOptionalHeader;
                info.IsValid = true;
            }
            catch
            {
                info.IsValid = false;
            }
            return info;
        }

        private class NtHeaderInfo
        {
            public bool IsValid;
            public int NumberOfSections;
            public uint AddressOfEntryPoint;
            public uint SizeOfImage;
            public int SectionHeaderOffset;
        }
    }
}