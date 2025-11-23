using System;
using System.Runtime.InteropServices;
using System.Text;
using NativeProcesses.Core.PE;

namespace NativeProcesses.Core.PE.Resources
{
    public static class PeResourceReader
    {
        private const uint RT_VERSION = 16;
        private const uint RT_MANIFEST = 24;

        public static byte[] GetManifest(IntPtr moduleBase)
        {
            return GetResourceBytes(moduleBase, RT_MANIFEST, 1);
        }

        public static byte[] GetVersionInfo(IntPtr moduleBase)
        {
            return GetResourceBytes(moduleBase, RT_VERSION, 1);
        }

        public static byte[] GetResourceBytes(IntPtr moduleBase, uint typeId, uint nameId)
        {
            if (moduleBase == IntPtr.Zero) return null;

            try
            {
                int e_lfanew = Marshal.ReadInt32(moduleBase, 0x3C);
                IntPtr ntHeader = IntPtr.Add(moduleBase, e_lfanew);
                IntPtr optHeader = IntPtr.Add(ntHeader, 24);
                ushort magic = (ushort)Marshal.ReadInt16(optHeader);

                uint rsrcRva = 0;
                uint rsrcSize = 0;

                if (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    rsrcRva = (uint)Marshal.ReadInt32(optHeader, 112 + (2 * 8));
                    rsrcSize = (uint)Marshal.ReadInt32(optHeader, 112 + (2 * 8) + 4);
                }
                else
                {
                    rsrcRva = (uint)Marshal.ReadInt32(optHeader, 96 + (2 * 8));
                    rsrcSize = (uint)Marshal.ReadInt32(optHeader, 96 + (2 * 8) + 4);
                }

                if (rsrcRva == 0 || rsrcSize == 0) return null;

                IntPtr resourceBase = IntPtr.Add(moduleBase, (int)rsrcRva);

                IntPtr typeEntry = FindEntryById(resourceBase, resourceBase, typeId);
                if (typeEntry == IntPtr.Zero) return null;

                uint typeOffset = GetOffsetToSubDir(typeEntry);
                IntPtr nameBase = IntPtr.Add(resourceBase, (int)typeOffset);

                IntPtr nameEntry = IntPtr.Zero;

                if (nameId == 0)
                {
                    nameEntry = GetFirstEntry(nameBase);
                }
                else
                {
                    nameEntry = FindEntryById(resourceBase, nameBase, nameId);
                }

                if (nameEntry == IntPtr.Zero) return null;

                uint nameOffset = GetOffsetToSubDir(nameEntry);
                IntPtr langBase = IntPtr.Add(resourceBase, (int)nameOffset);

                IntPtr langEntry = GetFirstEntry(langBase);
                if (langEntry == IntPtr.Zero) return null;

                uint dataEntryOffset = GetOffsetToData(langEntry);
                IntPtr dataEntryPtr = IntPtr.Add(resourceBase, (int)dataEntryOffset);

                var dataEntry = Marshal.PtrToStructure<PeHeaders.IMAGE_RESOURCE_DATA_ENTRY>(dataEntryPtr);

                IntPtr dataPtr = IntPtr.Add(moduleBase, (int)dataEntry.OffsetToData);

                byte[] buffer = new byte[dataEntry.Size];
                Marshal.Copy(dataPtr, buffer, 0, (int)dataEntry.Size);

                return buffer;
            }
            catch
            {
                return null;
            }
        }

        private static IntPtr FindEntryById(IntPtr rootBase, IntPtr dirBase, uint id)
        {
            var dir = Marshal.PtrToStructure<PeHeaders.IMAGE_RESOURCE_DIRECTORY>(dirBase);
            int entriesCount = dir.NumberOfNamedEntries + dir.NumberOfIdEntries;
            int entrySize = Marshal.SizeOf<PeHeaders.IMAGE_RESOURCE_DIRECTORY_ENTRY>();

            IntPtr firstEntryPtr = IntPtr.Add(dirBase, Marshal.SizeOf<PeHeaders.IMAGE_RESOURCE_DIRECTORY>());

            for (int i = 0; i < entriesCount; i++)
            {
                IntPtr currentPtr = IntPtr.Add(firstEntryPtr, i * entrySize);
                var entry = Marshal.PtrToStructure<PeHeaders.IMAGE_RESOURCE_DIRECTORY_ENTRY>(currentPtr);

                if ((entry.Name & 0x80000000) == 0)
                {
                    if (entry.Name == id) return currentPtr;
                }
            }
            return IntPtr.Zero;
        }

        private static IntPtr GetFirstEntry(IntPtr dirBase)
        {
            var dir = Marshal.PtrToStructure<PeHeaders.IMAGE_RESOURCE_DIRECTORY>(dirBase);
            int entriesCount = dir.NumberOfNamedEntries + dir.NumberOfIdEntries;
            if (entriesCount == 0) return IntPtr.Zero;

            return IntPtr.Add(dirBase, Marshal.SizeOf<PeHeaders.IMAGE_RESOURCE_DIRECTORY>());
        }

        private static uint GetOffsetToSubDir(IntPtr entryPtr)
        {
            var entry = Marshal.PtrToStructure<PeHeaders.IMAGE_RESOURCE_DIRECTORY_ENTRY>(entryPtr);
            if ((entry.OffsetToData & 0x80000000) != 0)
            {
                return entry.OffsetToData & 0x7FFFFFFF;
            }
            return 0;
        }

        private static uint GetOffsetToData(IntPtr entryPtr)
        {
            var entry = Marshal.PtrToStructure<PeHeaders.IMAGE_RESOURCE_DIRECTORY_ENTRY>(entryPtr);
            if ((entry.OffsetToData & 0x80000000) == 0)
            {
                return entry.OffsetToData;
            }
            return 0;
        }
    }
}