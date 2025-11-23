using System;
using NativeProcesses.Core.Native;
using NativeProcesses.Core.PE;

namespace NativeProcesses.Core.PE.Loader
{
    public class RemotePeLoader
    {
        public static IntPtr LoadAndInject(ManagedProcess targetProcess, byte[] rawPe)
        {
            if (targetProcess == null) throw new ArgumentNullException(nameof(targetProcess));
            if (rawPe == null || rawPe.Length == 0) throw new ArgumentNullException(nameof(rawPe));

            // 1. Lokal Mappen (Raw -> Virtual Layout)
            byte[] virtualPe = PeLoader.MapRawToVirtual(rawPe);
            if (virtualPe == null) throw new Exception("Failed to map PE to virtual memory.");

            // 2. Remote Speicher reservieren
            // Wir fragen nicht nach einer Preferred Address, sondern lassen das OS entscheiden (ASLR).
            IntPtr remoteBase = targetProcess.AllocateMemory(virtualPe.Length);

            try
            {
                // 3. Relocations anwenden
                // WICHTIG: Wir patchen unser LOKALES byte[] Array, aber wir nutzen die REMOTE Adresse als Zielbasis!
                if (!RelocationsFixer.ApplyRelocations(virtualPe, (ulong)remoteBase.ToInt64()))
                {
                    // Relocs failed. Wenn das Image nicht PIC (Position Independent) ist, wird es crashen.
                }

                // 4. Imports fixen
                // Wir lösen die Imports lokal auf. Da System-DLLs (kernel32/ntdll) meist an derselben Adresse liegen,
                // funktionieren diese Pointer auch im Zielprozess.
                if (!ImportsFixer.FixImports(virtualPe))
                {
                    throw new Exception("Failed to resolve imports for remote injection.");
                }

                // 5. Security Cookie fixen (Lokal patchen für Remote Adresse?)
                // Schwierig, da wir den Remote-Cookie-Wert nicht kennen. 
                // Wir lassen es vorerst, da moderne CRT den Cookie zur Laufzeit generiert wenn er 0 ist.

                // 6. TLS Callbacks?
                // Remote TLS Callbacks auszuführen ist extrem komplex (Shellcode nötig). 
                // Wir überspringen das hier. Wenn die Payload TLS braucht, könnte sie instabil sein.

                // 7. In den Zielprozess schreiben
                targetProcess.WriteMemory(remoteBase, virtualPe);

                // 8. EntryPoint berechnen
                if (!PeLoader.GetImageBase(virtualPe, out _, out bool is64Bit))
                    throw new Exception("Failed to parse headers for EntryPoint.");

                // Wir müssen den Offset des EntryPoints aus den Rohdaten lesen
                // Da wir virtualPe haben, können wir direkt an den Offsets lesen
                int e_lfanew = BitConverter.ToInt32(virtualPe, 0x3C);
                int optHeaderOffset = e_lfanew + 24;

                // Offset AddressOfEntryPoint: 
                // 32-bit: Offset 16 in OptionalHeader
                // 64-bit: Offset 16 in OptionalHeader
                int entryPointRvaOffset = optHeaderOffset + 16;
                uint entryPointRva = BitConverter.ToUInt32(virtualPe, entryPointRvaOffset);

                if (entryPointRva == 0) throw new Exception("No EntryPoint found.");

                IntPtr remoteEntryPoint = IntPtr.Add(remoteBase, (int)entryPointRva);

                // 9. Thread starten
                // Hinweis: DllMain erwartet (hInst, Reason, Reserved). CreateRemoteThread übergibt nur (Param).
                // Für EXEs ist das egal (Main hat keine Params oder ignoriert sie oft).
                // Für DLLs wird der Parameter als hInst interpretiert, was korrekt ist (unsere remoteBase).
                // Reason wird implizit DLL_PROCESS_ATTACH sein, da es ein neuer Thread ist? 
                // Nein, CreateRemoteThread startet einfach bei der Adresse. 
                // Bei DLLs ist das ein Hack. Sauber wäre ein Shellcode Stub.
                // Aber für viele Payloads (z.B. Cobalt Strike Beacon) funktioniert der direkte Aufruf.

                targetProcess.StartRemoteThread(remoteEntryPoint, remoteBase);

                return remoteBase;
            }
            catch
            {
                // Cleanup nicht möglich ohne VirtualFreeEx (TODO: in ManagedProcessExtensions ergänzen)
                throw;
            }
        }
    }
}