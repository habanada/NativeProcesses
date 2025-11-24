using System;
using System.Runtime.InteropServices;
using NativeProcesses.Core.PE;

namespace NativeProcesses.Core.PE.Loader
{
    public static class PePebLinker
    {
        #region P/Invoke
        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(
            IntPtr ProcessHandle,
            int ProcessInformationClass,
            out PROCESS_BASIC_INFORMATION ProcessInformation,
            int ProcessInformationLength,
            out int ReturnLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        private const int ProcessBasicInformation = 0;
        #endregion

        /// <summary>
        /// Fügt das manuell gemappte Modul in den PEB (Ldr) des aktuellen Prozesses ein.
        /// Gibt einen Pointer auf den erstellten Entry zurück (für späteres Unlink).
        /// </summary>
        public static IntPtr LinkModuleToPeb(IntPtr moduleBase, uint imageSize, string fullPath)
        {
            try
            {
                // 1. PEB Adresse holen
                var pbi = new PROCESS_BASIC_INFORMATION();
                int status = NtQueryInformationProcess(
                    System.Diagnostics.Process.GetCurrentProcess().Handle,
                    ProcessBasicInformation,
                    out pbi,
                    Marshal.SizeOf(pbi),
                    out _);

                if (status != 0 || pbi.PebBaseAddress == IntPtr.Zero) return IntPtr.Zero;

                // 2. Ldr Pointer finden
                // PEB->Ldr Offset: x64 = 0x18, x86 = 0x0C
                bool is64 = (IntPtr.Size == 8);
                int ldrOffset = is64 ? 0x18 : 0x0C;

                IntPtr ldrPtr = Marshal.ReadIntPtr(pbi.PebBaseAddress, ldrOffset);
                if (ldrPtr == IntPtr.Zero) return IntPtr.Zero;

                // 3. Listen-Köpfe im PEB_LDR_DATA finden
                // PEB_LDR_DATA Layout:
                // [Reserved 8/4 bytes] ...
                // InLoadOrderModuleList (LIST_ENTRY)  <- Offset x64: 0x10, x86: 0x0C
                // InMemoryOrderModuleList (LIST_ENTRY)
                // InInitializationOrderModuleList (LIST_ENTRY)

                int loadOrderListOffset = is64 ? 0x10 : 0x0C;
                int memOrderListOffset = loadOrderListOffset + Marshal.SizeOf<PeHeaders.LIST_ENTRY>();

                // Wir linken in LoadOrder und MemoryOrder (InitOrder lassen wir oft weg, da wir Init manuell machen)
                IntPtr loadOrderHead = IntPtr.Add(ldrPtr, loadOrderListOffset);
                IntPtr memOrderHead = IntPtr.Add(ldrPtr, memOrderListOffset);

                // 4. Neuen Entry erstellen (Unmanaged Memory, da er im PEB leben muss)
                int entrySize = is64 ? 0x120 : 0x90; // Groß genug für LDR_ENTRY
                IntPtr newEntryPtr = Marshal.AllocHGlobal(entrySize);

                // Speicher nullen (wichtig!)
                byte[] empty = new byte[entrySize];
                Marshal.Copy(empty, 0, newEntryPtr, entrySize);

                // 5. Daten füllen
                var entry = new PeHeaders.LDR_DATA_TABLE_ENTRY_PARTIAL();
                entry.DllBase = moduleBase;
                entry.SizeOfImage = imageSize;
                entry.EntryPoint = IntPtr.Zero; // Setzen wir oft auf 0, um OS-Loader nicht zu verwirren

                // Strings vorbereiten (Unicode)
                string fileName = System.IO.Path.GetFileName(fullPath);

                // FullDllName
                entry.FullDllName.Length = (ushort)(fullPath.Length * 2);
                entry.FullDllName.MaximumLength = (ushort)((fullPath.Length + 1) * 2);
                entry.FullDllName.Buffer = Marshal.StringToHGlobalUni(fullPath);

                // BaseDllName
                entry.BaseDllName.Length = (ushort)(fileName.Length * 2);
                entry.BaseDllName.MaximumLength = (ushort)((fileName.Length + 1) * 2);
                entry.BaseDllName.Buffer = Marshal.StringToHGlobalUni(fileName);

                // Struktur in den Speicher schreiben
                // Wir schreiben die Felder manuell, da wir Offsets brauchen, um die Listen zu patchen
                Marshal.StructureToPtr(entry, newEntryPtr, false);

                // 6. In die Listen einhängen (Blackbone Logic: InsertTailList)
                InsertTailList(loadOrderHead, newEntryPtr); // Offset 0 im Entry

                // Offset für MemoryOrder im Entry berechnen
                int memEntryOffset = Marshal.SizeOf<PeHeaders.LIST_ENTRY>();
                InsertTailList(memOrderHead, IntPtr.Add(newEntryPtr, memEntryOffset));

                return newEntryPtr;
            }
            catch
            {
                return IntPtr.Zero;
            }
        }

        public static void UnlinkModuleFromPeb(IntPtr entryPtr)
        {
            if (entryPtr == IntPtr.Zero) return;

            try
            {
                // Strings freigeben
                var entry = Marshal.PtrToStructure<PeHeaders.LDR_DATA_TABLE_ENTRY_PARTIAL>(entryPtr);
                if (entry.FullDllName.Buffer != IntPtr.Zero) Marshal.FreeHGlobal(entry.FullDllName.Buffer);
                if (entry.BaseDllName.Buffer != IntPtr.Zero) Marshal.FreeHGlobal(entry.BaseDllName.Buffer);

                // Aus Listen entfernen
                // LoadOrder (Offset 0)
                RemoveEntryList(entryPtr);

                // MemoryOrder (Offset SizeOf(LIST_ENTRY))
                int memEntryOffset = Marshal.SizeOf<PeHeaders.LIST_ENTRY>();
                RemoveEntryList(IntPtr.Add(entryPtr, memEntryOffset));

                // Entry selbst freigeben
                Marshal.FreeHGlobal(entryPtr);
            }
            catch { }
        }

        // Standard Windows Linked List Implementierung
        private static void InsertTailList(IntPtr listHead, IntPtr entry)
        {
            // ListHead->Blink zeigt auf das letzte Element
            var headStruct = Marshal.PtrToStructure<PeHeaders.LIST_ENTRY>(listHead);
            IntPtr blink = headStruct.Blink; // Das aktuelle letzte Element

            // entry->Flink = ListHead
            Marshal.WriteIntPtr(entry, 0, listHead); // Flink ist Offset 0

            // entry->Blink = Blink
            Marshal.WriteIntPtr(entry, IntPtr.Size, blink); // Blink ist Offset IntPtr.Size

            // Blink->Flink = entry (Das alte letzte Element zeigt jetzt auf uns)
            // Flink ist Offset 0 im struct, also schreiben wir direkt an die Adresse 'blink'
            Marshal.WriteIntPtr(blink, 0, entry);

            // ListHead->Blink = entry (Head zeigt rückwärts auf uns als neues letztes Element)
            // Blink ist Offset IntPtr.Size im Head
            Marshal.WriteIntPtr(listHead, IntPtr.Size, entry);
        }

        private static void RemoveEntryList(IntPtr entry)
        {
            var entryStruct = Marshal.PtrToStructure<PeHeaders.LIST_ENTRY>(entry);
            IntPtr flink = entryStruct.Flink;
            IntPtr blink = entryStruct.Blink;

            // Blink->Flink = Flink
            Marshal.WriteIntPtr(blink, 0, flink);

            // Flink->Blink = Blink
            Marshal.WriteIntPtr(flink, IntPtr.Size, blink);
        }
    }
}