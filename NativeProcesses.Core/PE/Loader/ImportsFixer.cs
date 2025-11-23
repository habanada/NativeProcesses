using System;
using System.Runtime.InteropServices;
using NativeProcesses.Core.PE;

namespace NativeProcesses.Core.PE.Loader
{
    public static class ImportsFixer
    {
        #region P/Invoke
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr LoadLibraryA(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, IntPtr lpProcName); // Für Ordinals
        #endregion

        /// <summary>
        /// Lösen die Importe für das gemappte PE-Image auf.
        /// Das Image muss bereits "Virtual" gemappt sein (durch PeLoader).
        /// </summary>
        public static bool FixImports(byte[] virtualPe)
        {
            if (virtualPe == null || virtualPe.Length < 512) return false;

            GCHandle handle = GCHandle.Alloc(virtualPe, GCHandleType.Pinned);
            try
            {
                IntPtr basePtr = handle.AddrOfPinnedObject();

                if (!PeLoader.GetImageBase(virtualPe, out _, out bool is64Bit))
                    return false;

                // DOS & NT Header parsen, um DataDirectory zu finden
                var dos = Marshal.PtrToStructure<PeHeaders.IMAGE_DOS_HEADER>(basePtr);
                IntPtr ntPtr = IntPtr.Add(basePtr, dos.e_lfanew);
                IntPtr optPtr = IntPtr.Add(ntPtr, 4 + Marshal.SizeOf<PeHeaders.IMAGE_FILE_HEADER>());

                uint importRva = 0;
                uint importSize = 0;

                if (is64Bit)
                {
                    var opt64 = Marshal.PtrToStructure<PeHeaders.IMAGE_OPTIONAL_HEADER64>(optPtr);
                    if (opt64.NumberOfRvaAndSizes > PeHeaders.IMAGE_DIRECTORY_ENTRY_IMPORT)
                    {
                        importRva = opt64.DataDirectory[PeHeaders.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                        importSize = opt64.DataDirectory[PeHeaders.IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
                    }
                }
                else
                {
                    var opt32 = Marshal.PtrToStructure<PeHeaders.IMAGE_OPTIONAL_HEADER32>(optPtr);
                    if (opt32.NumberOfRvaAndSizes > PeHeaders.IMAGE_DIRECTORY_ENTRY_IMPORT)
                    {
                        importRva = opt32.DataDirectory[PeHeaders.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                        importSize = opt32.DataDirectory[PeHeaders.IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
                    }
                }

                if (importRva == 0 || importSize == 0) return true; // Keine Imports, ist okay (z.B. reine Ressource-DLL)

                // Durchlaufe die Import Descriptors
                int descriptorSize = Marshal.SizeOf<PeHeaders.IMAGE_IMPORT_DESCRIPTOR>();
                int currentOffset = 0;

                while (true)
                {
                    IntPtr descPtr = IntPtr.Add(basePtr, (int)(importRva + currentOffset));
                    var desc = Marshal.PtrToStructure<PeHeaders.IMAGE_IMPORT_DESCRIPTOR>(descPtr);

                    // Ende der Liste ist ein Null-Block
                    if (desc.Name == 0 && desc.FirstThunk == 0) break;

                    // 1. DLL Name holen und laden
                    string dllName = Marshal.PtrToStringAnsi(IntPtr.Add(basePtr, (int)desc.Name));
                    if (string.IsNullOrEmpty(dllName)) return false;

                    IntPtr hLib = LoadLibraryA(dllName);
                    if (hLib == IntPtr.Zero)
                    {
                        // DLL nicht gefunden. Abbruch oder Fehler.
                        // Für Robustheit könnten wir versuchen weiterzumachen, aber meist crasht die Exe dann eh.
                        return false;
                    }

                    // 2. Thunks verarbeiten
                    // OriginalFirstThunk (INT) ist die Lookup Table. FirstThunk (IAT) ist das Ziel.
                    // Wenn OriginalFirstThunk 0 ist, nutzen wir FirstThunk (Bindung).
                    uint thunkRva = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
                    uint iatRva = desc.FirstThunk;

                    if (is64Bit)
                    {
                        if (!ProcessThunks64(basePtr, hLib, thunkRva, iatRva)) return false;
                    }
                    else
                    {
                        if (!ProcessThunks32(basePtr, hLib, thunkRva, iatRva)) return false;
                    }

                    currentOffset += descriptorSize;
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

        private static unsafe bool ProcessThunks64(IntPtr basePtr, IntPtr hLib, uint thunkRva, uint iatRva)
        {
            int ptrSize = 8;
            int index = 0;

            while (true)
            {
                IntPtr thunkPtr = IntPtr.Add(basePtr, (int)(thunkRva + (index * ptrSize)));
                IntPtr iatPtr = IntPtr.Add(basePtr, (int)(iatRva + (index * ptrSize)));

                // Wir lesen direkt ulong (64-bit Thunk Data)
                ulong rawThunk = (ulong)Marshal.ReadInt64(thunkPtr);
                if (rawThunk == 0) break; // Ende der Thunks

                IntPtr funcAddr = IntPtr.Zero;

                // Check IMAGE_ORDINAL_FLAG64 (0x8000000000000000)
                bool isOrdinal = (rawThunk & 0x8000000000000000) != 0;

                if (isOrdinal)
                {
                    // Import by Ordinal (Maske entfernen)
                    ushort ordinal = (ushort)(rawThunk & 0xFFFF);
                    funcAddr = GetProcAddress(hLib, (IntPtr)ordinal);
                }
                else
                {
                    // Import by Name
                    // rawThunk ist RVA zur IMAGE_IMPORT_BY_NAME Struktur
                    // Struktur: [Hint (2 bytes)] [Name (ASCIIZ)]
                    uint nameRva = (uint)(rawThunk & 0x7FFFFFFF); // 31 Bit RVA
                    IntPtr nameStructPtr = IntPtr.Add(basePtr, (int)nameRva);

                    // Name beginnt bei Offset 2 (nach Hint)
                    string funcName = Marshal.PtrToStringAnsi(IntPtr.Add(nameStructPtr, 2));
                    funcAddr = GetProcAddress(hLib, funcName);
                }

                if (funcAddr == IntPtr.Zero)
                {
                    // Import nicht gefunden -> Image ist defekt
                    return false;
                }

                // Adresse in die IAT schreiben
                Marshal.WriteInt64(iatPtr, funcAddr.ToInt64());

                index++;
            }
            return true;
        }

        private static unsafe bool ProcessThunks32(IntPtr basePtr, IntPtr hLib, uint thunkRva, uint iatRva)
        {
            int ptrSize = 4;
            int index = 0;

            while (true)
            {
                IntPtr thunkPtr = IntPtr.Add(basePtr, (int)(thunkRva + (index * ptrSize)));
                IntPtr iatPtr = IntPtr.Add(basePtr, (int)(iatRva + (index * ptrSize)));

                uint rawThunk = (uint)Marshal.ReadInt32(thunkPtr);
                if (rawThunk == 0) break;

                IntPtr funcAddr = IntPtr.Zero;

                // Check IMAGE_ORDINAL_FLAG32 (0x80000000)
                bool isOrdinal = (rawThunk & 0x80000000) != 0;

                if (isOrdinal)
                {
                    ushort ordinal = (ushort)(rawThunk & 0xFFFF);
                    funcAddr = GetProcAddress(hLib, (IntPtr)ordinal);
                }
                else
                {
                    uint nameRva = rawThunk; // RVA
                    IntPtr nameStructPtr = IntPtr.Add(basePtr, (int)nameRva);
                    string funcName = Marshal.PtrToStringAnsi(IntPtr.Add(nameStructPtr, 2));
                    funcAddr = GetProcAddress(hLib, funcName);
                }

                if (funcAddr == IntPtr.Zero) return false;

                // Adresse in die IAT schreiben
                Marshal.WriteInt32(iatPtr, funcAddr.ToInt32());

                index++;
            }
            return true;
        }
    }
}