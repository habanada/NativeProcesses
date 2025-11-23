using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using NativeProcesses.Core.PE;

namespace NativeProcesses.Core.PE.Export
{
    public class ExportedFunction
    {
        public string Name { get; set; }
        public ushort Ordinal { get; set; }
        public uint FunctionRva { get; set; } // <--- Hier heißt es FunctionRva
        public bool IsForwarder { get; set; }
        public string ForwarderString { get; set; }
    }

    public static class PeExports
    {
        // ---------------------------------------------------------
        // LIVE MEMORY API (IntPtr) - Für PeExecutor / Loader
        // ---------------------------------------------------------

        public static IntPtr GetExportAddress(IntPtr moduleBase, string functionName)
        {
            if (moduleBase == IntPtr.Zero || string.IsNullOrEmpty(functionName)) return IntPtr.Zero;

            try
            {
                if (!GetExportDirectoryOffset(moduleBase, out uint exportRva, out uint exportSize)) return IntPtr.Zero;

                IntPtr exportDirPtr = IntPtr.Add(moduleBase, (int)exportRva);
                var exportDir = Marshal.PtrToStructure<PeHeaders.IMAGE_EXPORT_DIRECTORY>(exportDirPtr);

                IntPtr namesPtr = IntPtr.Add(moduleBase, (int)exportDir.AddressOfNames);
                IntPtr ordinalsPtr = IntPtr.Add(moduleBase, (int)exportDir.AddressOfNameOrdinals);
                IntPtr functionsPtr = IntPtr.Add(moduleBase, (int)exportDir.AddressOfFunctions);

                for (uint i = 0; i < exportDir.NumberOfNames; i++)
                {
                    uint nameRva = (uint)Marshal.ReadInt32(namesPtr, (int)(i * 4));
                    string currentName = Marshal.PtrToStringAnsi(IntPtr.Add(moduleBase, (int)nameRva));

                    if (string.Equals(currentName, functionName, StringComparison.Ordinal))
                    {
                        ushort ordinalIndex = (ushort)Marshal.ReadInt16(ordinalsPtr, (int)(i * 2));
                        if (ordinalIndex >= exportDir.NumberOfFunctions) return IntPtr.Zero;

                        uint funcRva = (uint)Marshal.ReadInt32(functionsPtr, (int)(ordinalIndex * 4));

                        if (funcRva >= exportRva && funcRva < exportRva + exportSize)
                        {
                            return IntPtr.Zero; // Forwarder handling skipped for live execution safety
                        }

                        return IntPtr.Add(moduleBase, (int)funcRva);
                    }
                }
            }
            catch { return IntPtr.Zero; }
            return IntPtr.Zero;
        }

        public static List<ExportedFunction> EnumExportedFunctions(IntPtr moduleBase)
        {
            var results = new List<ExportedFunction>();
            if (moduleBase == IntPtr.Zero) return results;

            try
            {
                if (!GetExportDirectoryOffset(moduleBase, out uint exportRva, out uint exportSize)) return results;

                IntPtr exportDirPtr = IntPtr.Add(moduleBase, (int)exportRva);
                var exportDir = Marshal.PtrToStructure<PeHeaders.IMAGE_EXPORT_DIRECTORY>(exportDirPtr);

                IntPtr namesPtr = IntPtr.Add(moduleBase, (int)exportDir.AddressOfNames);
                IntPtr ordinalsPtr = IntPtr.Add(moduleBase, (int)exportDir.AddressOfNameOrdinals);
                IntPtr functionsPtr = IntPtr.Add(moduleBase, (int)exportDir.AddressOfFunctions);

                for (uint i = 0; i < exportDir.NumberOfNames; i++)
                {
                    uint nameRva = (uint)Marshal.ReadInt32(namesPtr, (int)(i * 4));
                    string name = Marshal.PtrToStringAnsi(IntPtr.Add(moduleBase, (int)nameRva));

                    ushort ordinalIndex = (ushort)Marshal.ReadInt16(ordinalsPtr, (int)(i * 2));
                    if (ordinalIndex >= exportDir.NumberOfFunctions) continue;

                    uint funcRva = (uint)Marshal.ReadInt32(functionsPtr, (int)(ordinalIndex * 4));

                    bool isForwarder = (funcRva >= exportRva && funcRva < exportRva + exportSize);
                    string forwarderStr = null;

                    if (isForwarder)
                    {
                        forwarderStr = Marshal.PtrToStringAnsi(IntPtr.Add(moduleBase, (int)funcRva));
                    }

                    results.Add(new ExportedFunction
                    {
                        Name = name,
                        Ordinal = (ushort)(exportDir.Base + ordinalIndex),
                        FunctionRva = funcRva,
                        IsForwarder = isForwarder,
                        ForwarderString = forwarderStr
                    });
                }
            }
            catch { }
            return results;
        }

        // ---------------------------------------------------------
        // STATIC BUFFER API (byte[]) - Für PeReconstructor / Dumps
        // ---------------------------------------------------------

        public static ExportedFunction GetExportEntry(byte[] mappedImage, string functionName)
        {
            if (mappedImage == null || mappedImage.Length == 0) return null;

            try
            {
                int e_lfanew = BitConverter.ToInt32(mappedImage, 0x3C);
                if (e_lfanew > mappedImage.Length - 256) return null;

                int ntOffset = e_lfanew;
                ushort magic = BitConverter.ToUInt16(mappedImage, ntOffset + 24);
                bool is64 = (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC);

                int dataDirOffset = is64 ? 112 : 96;
                int exportDirEntryOffset = ntOffset + 24 + dataDirOffset;

                uint exportRva = BitConverter.ToUInt32(mappedImage, exportDirEntryOffset);
                uint exportSize = BitConverter.ToUInt32(mappedImage, exportDirEntryOffset + 4);

                if (exportRva == 0 || exportSize == 0 || exportRva >= mappedImage.Length) return null;

                int dirOffset = (int)exportRva;

                uint numberOfFunctions = BitConverter.ToUInt32(mappedImage, dirOffset + 20);
                uint numberOfNames = BitConverter.ToUInt32(mappedImage, dirOffset + 24);
                uint addressOfFunctions = BitConverter.ToUInt32(mappedImage, dirOffset + 28);
                uint addressOfNames = BitConverter.ToUInt32(mappedImage, dirOffset + 32);
                uint addressOfOrdinals = BitConverter.ToUInt32(mappedImage, dirOffset + 36);

                for (int i = 0; i < numberOfNames; i++)
                {
                    uint nameRva = BitConverter.ToUInt32(mappedImage, (int)addressOfNames + (i * 4));
                    if (nameRva == 0 || nameRva >= mappedImage.Length) continue;

                    string currentName = ReadString(mappedImage, (int)nameRva);

                    if (string.Equals(currentName, functionName, StringComparison.OrdinalIgnoreCase))
                    {
                        ushort ordinalIndex = BitConverter.ToUInt16(mappedImage, (int)addressOfOrdinals + (i * 2));
                        if (ordinalIndex >= numberOfFunctions) return null;

                        uint funcRva = BitConverter.ToUInt32(mappedImage, (int)addressOfFunctions + (ordinalIndex * 4));

                        bool isForwarder = (funcRva >= exportRva && funcRva < (exportRva + exportSize));
                        string fwdStr = isForwarder ? ReadString(mappedImage, (int)funcRva) : null;

                        return new ExportedFunction
                        {
                            Name = currentName,
                            FunctionRva = funcRva, // FIX: Property Name angepasst
                            Ordinal = ordinalIndex,
                            IsForwarder = isForwarder,
                            ForwarderString = fwdStr
                        };
                    }
                }
            }
            catch { }
            return null;
        }

        // Helper
        private static bool GetExportDirectoryOffset(IntPtr moduleBase, out uint rva, out uint size)
        {
            rva = 0; size = 0;
            try
            {
                int e_lfanew = Marshal.ReadInt32(moduleBase, 0x3C);
                IntPtr ntHeader = IntPtr.Add(moduleBase, e_lfanew);
                IntPtr optHeader = IntPtr.Add(ntHeader, 24);
                ushort magic = (ushort)Marshal.ReadInt16(optHeader);

                if (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    rva = (uint)Marshal.ReadInt32(optHeader, 112);
                    size = (uint)Marshal.ReadInt32(optHeader, 116);
                }
                else
                {
                    rva = (uint)Marshal.ReadInt32(optHeader, 96);
                    size = (uint)Marshal.ReadInt32(optHeader, 100);
                }
                return rva != 0;
            }
            catch { return false; }
        }

        private static string ReadString(byte[] buffer, int offset)
        {
            int end = offset;
            while (end < buffer.Length && buffer[end] != 0) end++;
            return Encoding.ASCII.GetString(buffer, offset, end - offset);
        }
    }
}