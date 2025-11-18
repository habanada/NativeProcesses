using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using NativeProcesses.Core.Native;

namespace NativeProcesses.Core.Inspection
{
    public class PeEmulation
    {
        // Simuliert den Windows Loader: Liest Datei, mappt Sektionen, wendet Relocations an.
        public static byte[] MapAndRelocate(string filePath, IntPtr targetBaseAddress)
        {
            byte[] rawFile = File.ReadAllBytes(filePath);

            // 1. Header Parsen (DOS & NT)
            var dosHeader = ByteArrayToStructure<PeStructs.IMAGE_DOS_HEADER>(rawFile, 0);
            if (!dosHeader.IsValid) throw new Exception("Invalid DOS Header");

            int ntOffset = dosHeader.e_lfanew;
            uint sig = BitConverter.ToUInt32(rawFile, ntOffset); // PE\0\0

            // File Header
            int fileHeaderOffset = ntOffset + 4;
            var fileHeader = ByteArrayToStructure<PeStructs.IMAGE_FILE_HEADER>(rawFile, fileHeaderOffset);

            // Optional Header
            int optHeaderOffset = fileHeaderOffset + Marshal.SizeOf(typeof(PeStructs.IMAGE_FILE_HEADER));
            ushort magic = BitConverter.ToUInt16(rawFile, optHeaderOffset);
            bool is64 = (magic == PeStructs.IMAGE_NT_OPTIONAL_HDR64_MAGIC);

            uint sizeOfImage = 0;
            uint sizeOfHeaders = 0;
            ulong originalImageBase = 0;
            uint relocDirRva = 0;
            uint relocDirSize = 0;

            // Lese wichtige Werte aus Optional Header
            if (is64)
            {
                var opt64 = ByteArrayToStructure<PeStructs.IMAGE_OPTIONAL_HEADER64>(rawFile, optHeaderOffset);
                sizeOfImage = opt64.SizeOfImage;
                sizeOfHeaders = opt64.SizeOfHeaders;
                originalImageBase = opt64.ImageBase;
                if (opt64.NumberOfRvaAndSizes > PeStructs.IMAGE_DIRECTORY_ENTRY_BASERELOC)
                {
                    relocDirRva = opt64.DataDirectory[PeStructs.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                    relocDirSize = opt64.DataDirectory[PeStructs.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                }
            }
            else
            {
                var opt32 = ByteArrayToStructure<PeStructs.IMAGE_OPTIONAL_HEADER32>(rawFile, optHeaderOffset);
                sizeOfImage = opt32.SizeOfImage;
                sizeOfHeaders = opt32.SizeOfHeaders;
                originalImageBase = opt32.ImageBase;
                if (opt32.NumberOfRvaAndSizes > PeStructs.IMAGE_DIRECTORY_ENTRY_BASERELOC)
                {
                    relocDirRva = opt32.DataDirectory[PeStructs.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                    relocDirSize = opt32.DataDirectory[PeStructs.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                }
            }

            // 2. Mapping (Raw -> Virtual)
            // Wir erstellen ein Byte-Array, das so groß ist wie das Image im Speicher
            byte[] virtualImage = new byte[sizeOfImage];

            // Header kopieren
            Array.Copy(rawFile, 0, virtualImage, 0, Math.Min(rawFile.Length, sizeOfHeaders));

            // Section Headers parsen und Sektionen kopieren
            int sectionHeadersOffset = optHeaderOffset + fileHeader.SizeOfOptionalHeader;
            int sectionSize = Marshal.SizeOf(typeof(PeStructs.IMAGE_SECTION_HEADER));

            for (int i = 0; i < fileHeader.NumberOfSections; i++)
            {
                int entryOffset = sectionHeadersOffset + (i * sectionSize);
                var section = ByteArrayToStructure<PeStructs.IMAGE_SECTION_HEADER>(rawFile, entryOffset);

                if (section.SizeOfRawData > 0 && section.PointerToRawData > 0)
                {
                    // Kopiere Raw Data an die Virtual Address
                    // Wichtig: Math.Min, falls VirtualSize > SizeOfRawData (BSS) oder RawData über Dateiende hinausgeht
                    int copySize = Math.Min((int)section.SizeOfRawData, (int)section.VirtualSize);
                    if (copySize == 0) copySize = (int)section.SizeOfRawData; // Fallback

                    if (section.VirtualAddress + copySize <= virtualImage.Length &&
                        section.PointerToRawData + copySize <= rawFile.Length)
                    {
                        Array.Copy(rawFile, (int)section.PointerToRawData, virtualImage, (int)section.VirtualAddress, copySize);
                    }
                }
            }

            // 3. Relocating (Delta Application)
            // Das ist der Schritt, den PE-sieve macht und deine alte Version übersprungen hat.
            long delta = (long)targetBaseAddress - (long)originalImageBase;

            if (delta != 0 && relocDirRva > 0 && relocDirSize > 0)
            {
                ApplyRelocations(virtualImage, relocDirRva, relocDirSize, delta);
            }

            return virtualImage;
        }

        private static void ApplyRelocations(byte[] image, uint dirRva, uint dirSize, long delta)
        {
            uint currentOffset = 0;
            while (currentOffset < dirSize)
            {
                uint blockRva = BitConverter.ToUInt32(image, (int)(dirRva + currentOffset));
                uint blockSize = BitConverter.ToUInt32(image, (int)(dirRva + currentOffset + 4));

                if (blockSize == 0) break; // Sicherheit

                // Einträge starten nach dem Block-Header (8 Bytes)
                int entryCount = (int)(blockSize - 8) / 2;

                for (int i = 0; i < entryCount; i++)
                {
                    int entryOffset = (int)(dirRva + currentOffset + 8 + (i * 2));
                    ushort entry = BitConverter.ToUInt16(image, entryOffset);

                    ushort type = (ushort)(entry >> 12);
                    int offset = entry & 0x0FFF;

                    int targetRva = (int)(blockRva + offset);

                    // Safety Check: Nicht außerhalb des Images schreiben
                    if (targetRva + 8 > image.Length) continue;

                    switch (type)
                    {
                        case PeStructs.IMAGE_REL_BASED_HIGHLOW: // 32-Bit Patch
                            uint original32 = BitConverter.ToUInt32(image, targetRva);
                            uint patched32 = (uint)(original32 + delta);
                            BitConverter.GetBytes(patched32).CopyTo(image, targetRva);
                            break;

                        case PeStructs.IMAGE_REL_BASED_DIR64: // 64-Bit Patch
                            ulong original64 = BitConverter.ToUInt64(image, targetRva);
                            ulong patched64 = (ulong)((long)original64 + delta);
                            BitConverter.GetBytes(patched64).CopyTo(image, targetRva);
                            break;

                        case PeStructs.IMAGE_REL_BASED_ABSOLUTE:
                            // Padding, nix tun
                            break;
                    }
                }
                currentOffset += blockSize;
            }
        }

        private static T ByteArrayToStructure<T>(byte[] bytes, int offset) where T : struct
        {
            int size = Marshal.SizeOf(typeof(T));
            if (offset + size > bytes.Length) return default(T);

            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                return (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject() + offset, typeof(T));
            }
            finally
            {
                handle.Free();
            }
        }
    }
}