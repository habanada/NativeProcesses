using System;
using System.Runtime.InteropServices;
using System.Text;

namespace NativeProcesses.Core.PE.Loader
{
    /// <summary>
    /// Implementierung des Windows API Set Schema Parsers (v6 für Win10+).
    /// Löst virtuelle DLL-Namen (api-ms-*) in ihre logischen Hosts (kernelbase.dll, etc.) auf.
    /// </summary>
    public static class PeApiSet
    {
        #region Strukturen (Schema V6)

        // Das Schema Layout für Windows 10/11
        [StructLayout(LayoutKind.Sequential)]
        private struct API_SET_NAMESPACE
        {
            public uint Version;
            public uint Size;
            public uint Flags;
            public uint Count;      // Anzahl der Einträge
            public uint EntryOffset; // Offset zum Array der Einträge
            public uint HashOffset;
            public uint HashFactor;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct API_SET_NAMESPACE_ENTRY
        {
            public uint Flags;
            public uint NameOffset; // Offset zum Namen (api-ms-win...)
            public uint NameLength;
            public uint HashedLength;
            public uint ValueOffset; // Offset zu den Ziel-Werten (Hosts)
            public uint ValueCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct API_SET_VALUE_ENTRY
        {
            public uint Flags;
            public uint NameOffset;
            public uint NameLength;
            public uint ValueOffset; // Offset zum Host-Namen (z.B. kernelbase.dll)
            public uint ValueLength;
        }

        // Nötig um PEB zu finden
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
            public IntPtr PebBaseAddress; // <--- Das brauchen wir
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }
        #endregion

        /// <summary>
        /// Prüft, ob der DLL-Name virtuell ist, und gibt den echten Host-Namen zurück.
        /// Falls kein API-Set vorliegt, wird der originale Name zurückgegeben.
        /// </summary>
        public static string ResolveSchema(string dllName)
        {
            if (string.IsNullOrEmpty(dllName)) return dllName;

            // Schneller Check: API Sets fangen meist mit "api-" oder "ext-" an.
            if (!dllName.StartsWith("api-", StringComparison.OrdinalIgnoreCase) &&
                !dllName.StartsWith("ext-", StringComparison.OrdinalIgnoreCase))
            {
                return dllName;
            }

            // Wir entfernen .dll für den Vergleich, da das Schema oft ohne Extension speichert
            string lookupName = dllName;
            if (lookupName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                lookupName = lookupName.Substring(0, lookupName.Length - 4);

            try
            {
                // 1. PEB Adresse holen
                var pbi = new PROCESS_BASIC_INFORMATION();
                NtQueryInformationProcess(System.Diagnostics.Process.GetCurrentProcess().Handle, 0, out pbi, Marshal.SizeOf(pbi), out _);

                if (pbi.PebBaseAddress == IntPtr.Zero) return dllName;

                // 2. ApiSetMap Pointer aus PEB lesen
                // x64: Offset 0x68, x86: Offset 0x38
                bool is64 = IntPtr.Size == 8;
                int apiSetMapOffset = is64 ? 0x68 : 0x38;

                IntPtr apiSetMapPtr = Marshal.ReadIntPtr(pbi.PebBaseAddress, apiSetMapOffset);
                if (apiSetMapPtr == IntPtr.Zero) return dllName;

                // 3. Schema Header lesen
                var schema = Marshal.PtrToStructure<API_SET_NAMESPACE>(apiSetMapPtr);
                if (schema.Version < 6) return dllName; // Wir unterstützen hier nur V6 (Win 10/11)

                // 4. Durch Einträge iterieren
                // Die Einträge beginnen bei apiSetMapPtr + schema.EntryOffset
                IntPtr entriesBase = IntPtr.Add(apiSetMapPtr, (int)schema.EntryOffset);
                int entrySize = Marshal.SizeOf<API_SET_NAMESPACE_ENTRY>();

                for (uint i = 0; i < schema.Count; i++)
                {
                    IntPtr currentEntryPtr = IntPtr.Add(entriesBase, (int)(i * entrySize));
                    var entry = Marshal.PtrToStructure<API_SET_NAMESPACE_ENTRY>(currentEntryPtr);

                    // Namen lesen
                    IntPtr namePtr = IntPtr.Add(apiSetMapPtr, (int)entry.NameOffset);
                    string entryName = Marshal.PtrToStringUni(namePtr, (int)entry.NameLength / 2); // Length ist in Bytes, String ist UTF-16

                    // Vergleich: API Sets haben oft Suffixe. Wir prüfen, ob der Eintrag im gesuchten Namen enthalten ist.
                    // Das Schema ist komplex, aber ein StartsWith-Check auf den Schema-Eintrag reicht meistens.
                    // Blackbone schneidet den letzten Bindestrich ab für den Vergleich.

                    if (string.Compare(lookupName, 0, entryName, 0, entryName.Length, StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        // TREFFER! Jetzt den Host auflösen (Value)
                        if (entry.ValueCount > 0)
                        {
                            // Wir nehmen einfach den ersten Value Entry (meist gibt es nur einen oder einen Default)
                            IntPtr valueEntryPtr = IntPtr.Add(apiSetMapPtr, (int)entry.ValueOffset);
                            var valEntry = Marshal.PtrToStructure<API_SET_VALUE_ENTRY>(valueEntryPtr);

                            if (valEntry.ValueLength > 0)
                            {
                                IntPtr hostNamePtr = IntPtr.Add(apiSetMapPtr, (int)valEntry.ValueOffset);
                                string hostName = Marshal.PtrToStringUni(hostNamePtr, (int)valEntry.ValueLength / 2);

                                return hostName;
                            }
                        }
                    }
                }
            }
            catch
            {
                // Fallback im Fehlerfall
                return dllName;
            }

            return dllName;
        }
    }
}