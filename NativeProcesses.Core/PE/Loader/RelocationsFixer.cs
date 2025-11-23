using System;
using System.Runtime.InteropServices;
using NativeProcesses.Core.PE;

namespace NativeProcesses.Core.PE.Loader
{
    public static class RelocationsFixer
    {
        public static bool ApplyRelocations(byte[] virtualPe, ulong newBaseAddress)
        {
            if (!PeLoader.GetImageBase(virtualPe, out ulong originalBase, out bool is64Bit))
                return false;

            if (originalBase == newBaseAddress) return true;

            long delta = (long)newBaseAddress - (long)originalBase;

            GCHandle handle = GCHandle.Alloc(virtualPe, GCHandleType.Pinned);
            try
            {
                IntPtr ptr = handle.AddrOfPinnedObject();
                var dos = Marshal.PtrToStructure<PeHeaders.IMAGE_DOS_HEADER>(ptr);
                IntPtr ntPtr = IntPtr.Add(ptr, dos.e_lfanew);
                IntPtr optPtr = IntPtr.Add(ntPtr, 4 + Marshal.SizeOf<PeHeaders.IMAGE_FILE_HEADER>());

                uint relocRva = 0;
                uint relocSize = 0;

                if (is64Bit)
                {
                    var opt64 = Marshal.PtrToStructure<PeHeaders.IMAGE_OPTIONAL_HEADER64>(optPtr);
                    if (opt64.NumberOfRvaAndSizes > PeHeaders.IMAGE_DIRECTORY_ENTRY_BASERELOC)
                    {
                        relocRva = opt64.DataDirectory[PeHeaders.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                        relocSize = opt64.DataDirectory[PeHeaders.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                    }
                }
                else
                {
                    var opt32 = Marshal.PtrToStructure<PeHeaders.IMAGE_OPTIONAL_HEADER32>(optPtr);
                    if (opt32.NumberOfRvaAndSizes > PeHeaders.IMAGE_DIRECTORY_ENTRY_BASERELOC)
                    {
                        relocRva = opt32.DataDirectory[PeHeaders.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                        relocSize = opt32.DataDirectory[PeHeaders.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                    }
                }

                if (relocRva == 0 || relocSize == 0) return true;

                uint parsedSize = 0;
                while (parsedSize < relocSize)
                {
                    IntPtr blockPtr = IntPtr.Add(ptr, (int)(relocRva + parsedSize));
                    var block = Marshal.PtrToStructure<PeHeaders.IMAGE_BASE_RELOCATION>(blockPtr);

                    if (block.SizeOfBlock == 0) break;

                    uint entriesCount = (block.SizeOfBlock - 8) / 2;
                    IntPtr entryPtr = IntPtr.Add(blockPtr, 8);

                    for (uint i = 0; i < entriesCount; i++)
                    {
                        ushort entry = (ushort)Marshal.ReadInt16(entryPtr, (int)(i * 2));
                        ushort type = (ushort)(entry >> 12);
                        ushort offset = (ushort)(entry & 0xFFF);

                        uint rva = block.VirtualAddress + offset;
                        IntPtr relocTargetPtr = IntPtr.Add(ptr, (int)rva);

                        if (rva >= virtualPe.Length) continue;

                        if (type == PeHeaders.IMAGE_REL_BASED_HIGHLOW)
                        {
                            uint originalVal = (uint)Marshal.ReadInt32(relocTargetPtr);
                            uint newVal = (uint)(originalVal + delta);
                            Marshal.WriteInt32(relocTargetPtr, (int)newVal);
                        }
                        else if (type == PeHeaders.IMAGE_REL_BASED_DIR64)
                        {
                            ulong originalVal = (ulong)Marshal.ReadInt64(relocTargetPtr);
                            ulong newVal = (ulong)((long)originalVal + delta);
                            Marshal.WriteInt64(relocTargetPtr, (long)newVal);
                        }
                    }
                    parsedSize += block.SizeOfBlock;
                }
                return true;
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