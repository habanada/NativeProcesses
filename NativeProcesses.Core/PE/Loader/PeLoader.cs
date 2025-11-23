using System;
using System.IO;
using System.Runtime.InteropServices;
using NativeProcesses.Core.PE;

namespace NativeProcesses.Core.PE.Loader
{
    public static class PeLoader
    {
        public static byte[] MapRawToVirtual(byte[] rawPe)
        {
            if (rawPe == null || rawPe.Length < 512) throw new ArgumentException("Invalid raw PE data");

            GCHandle handle = GCHandle.Alloc(rawPe, GCHandleType.Pinned);
            try
            {
                IntPtr ptr = handle.AddrOfPinnedObject();
                PeHeaders.IMAGE_DOS_HEADER dosHeader = Marshal.PtrToStructure<PeHeaders.IMAGE_DOS_HEADER>(ptr);

                if (!dosHeader.IsValid) throw new FormatException("Invalid DOS Signature");

                IntPtr ntPtr = IntPtr.Add(ptr, dosHeader.e_lfanew);
                uint ntSig = (uint)Marshal.ReadInt32(ntPtr);
                if (ntSig != PeHeaders.IMAGE_NT_SIGNATURE) throw new FormatException("Invalid NT Signature");

                IntPtr fileHeaderPtr = IntPtr.Add(ntPtr, 4);
                PeHeaders.IMAGE_FILE_HEADER fileHeader = Marshal.PtrToStructure<PeHeaders.IMAGE_FILE_HEADER>(fileHeaderPtr);

                IntPtr optHeaderPtr = IntPtr.Add(fileHeaderPtr, Marshal.SizeOf<PeHeaders.IMAGE_FILE_HEADER>());
                ushort magic = (ushort)Marshal.ReadInt16(optHeaderPtr);

                uint sizeOfImage = 0;
                uint sizeOfHeaders = 0;
                uint sectionAlignment = 0;

                if (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    var opt64 = Marshal.PtrToStructure<PeHeaders.IMAGE_OPTIONAL_HEADER64>(optHeaderPtr);
                    sizeOfImage = opt64.SizeOfImage;
                    sizeOfHeaders = opt64.SizeOfHeaders;
                    sectionAlignment = opt64.SectionAlignment;
                }
                else if (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                {
                    var opt32 = Marshal.PtrToStructure<PeHeaders.IMAGE_OPTIONAL_HEADER32>(optHeaderPtr);
                    sizeOfImage = opt32.SizeOfImage;
                    sizeOfHeaders = opt32.SizeOfHeaders;
                    sectionAlignment = opt32.SectionAlignment;
                }
                else
                {
                    throw new FormatException("Unknown Optional Header Magic");
                }

                byte[] virtualPe = new byte[sizeOfImage];
                Array.Copy(rawPe, 0, virtualPe, 0, Math.Min(rawPe.Length, sizeOfHeaders));

                IntPtr sectionHeaderPtr = IntPtr.Add(optHeaderPtr, fileHeader.SizeOfOptionalHeader);
                int sectionSize = Marshal.SizeOf<PeHeaders.IMAGE_SECTION_HEADER>();

                for (int i = 0; i < fileHeader.NumberOfSections; i++)
                {
                    IntPtr currentSecPtr = IntPtr.Add(sectionHeaderPtr, i * sectionSize);
                    var sec = Marshal.PtrToStructure<PeHeaders.IMAGE_SECTION_HEADER>(currentSecPtr);

                    uint rawSize = sec.SizeOfRawData;
                    uint rawOffset = sec.PointerToRawData;
                    uint virtualAddr = sec.VirtualAddress;
                    uint virtualSize = sec.VirtualSize;

                    if (virtualSize == 0) virtualSize = rawSize;

                    if (rawSize > 0 && rawOffset > 0 && rawOffset + rawSize <= rawPe.Length)
                    {
                        uint sizeToCopy = Math.Min(rawSize, virtualSize);
                        if (virtualAddr + sizeToCopy <= virtualPe.Length)
                        {
                            Array.Copy(rawPe, rawOffset, virtualPe, virtualAddr, sizeToCopy);
                        }
                    }
                }

                return virtualPe;
            }
            finally
            {
                if (handle.IsAllocated) handle.Free();
            }
        }

        public static bool GetImageBase(byte[] peBuffer, out ulong imageBase, out bool is64Bit)
        {
            imageBase = 0;
            is64Bit = false;
            if (peBuffer.Length < 512) return false;

            GCHandle handle = GCHandle.Alloc(peBuffer, GCHandleType.Pinned);
            try
            {
                IntPtr ptr = handle.AddrOfPinnedObject();
                var dos = Marshal.PtrToStructure<PeHeaders.IMAGE_DOS_HEADER>(ptr);
                if (!dos.IsValid) return false;

                IntPtr ntPtr = IntPtr.Add(ptr, dos.e_lfanew);
                IntPtr optPtr = IntPtr.Add(ntPtr, 4 + Marshal.SizeOf<PeHeaders.IMAGE_FILE_HEADER>());
                ushort magic = (ushort)Marshal.ReadInt16(optPtr);

                if (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    is64Bit = true;
                    var opt64 = Marshal.PtrToStructure<PeHeaders.IMAGE_OPTIONAL_HEADER64>(optPtr);
                    imageBase = opt64.ImageBase;
                    return true;
                }
                else if (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                {
                    is64Bit = false;
                    var opt32 = Marshal.PtrToStructure<PeHeaders.IMAGE_OPTIONAL_HEADER32>(optPtr);
                    imageBase = opt32.ImageBase;
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
            finally
            {
                handle.Free();
            }
        }
    }
}