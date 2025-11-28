//using System;
//using System.Runtime.InteropServices;
//using NativeProcesses.Core.Native;
//using NativeProcesses.Core.PE;

//namespace NativeProcesses.Core.PE.Loader
//{
//    public class RemotePeLoader
//    {
//        public static IntPtr LoadAndInject(ManagedProcess targetProcess, byte[] rawPe)
//        {
//            if (targetProcess == null) throw new ArgumentNullException(nameof(targetProcess));
//            if (rawPe == null || rawPe.Length == 0) throw new ArgumentNullException(nameof(rawPe));

//            // 1. Lokal Mappen (Header Expansion)
//            byte[] virtualPe = PeLoader.MapRawToVirtual(rawPe);

//            // 2. Alloc Remote
//            IntPtr remoteBase = targetProcess.AllocateMemory(virtualPe.Length);

//            try
//            {
//                // 3. Relocations (Lokal patchen für Remote Adresse)
//                RelocationsFixer.ApplyRelocations(virtualPe, (ulong)remoteBase.ToInt64());

//                // 4. Imports Remotely Resolven (Der neue Fix!)
//                // Wir schreiben zuerst das halb-fertige Image, damit wir Offsets haben? 
//                // Nein, Resolve schreibt direkt in den Prozessspeicher, braucht aber das Mapping.
//                // Wir schreiben erst das Image rüber, damit RemoteImportResolver.EnsureRemoteModuleLoaded funktioniert?
//                // Nein, ImportResolver braucht nur Lesezugriff auf 'virtualPe' und Schreibzugriff auf 'targetProcess'.

//                // Wir müssen 'virtualPe' schreiben, DAMIT der IAT Platz da ist.
//                targetProcess.WriteMemory(remoteBase, virtualPe);

//                // Jetzt fixen wir die IAT im Remote Prozess
//                bool is64 = !targetProcess.GetIsWow64();
//                RemoteImportResolver.ResolveAndWrite(targetProcess, virtualPe, remoteBase, is64);

//                // 5. EntryPoint & TLS vorbereiten
//                int e_lfanew = BitConverter.ToInt32(virtualPe, 0x3C);
//                uint epRva = BitConverter.ToUInt32(virtualPe, e_lfanew + 24 + 16); // AddressOfEntryPoint
//                IntPtr remoteEp = IntPtr.Add(remoteBase, (int)epRva);

//                bool isDll = (BitConverter.ToUInt16(virtualPe, e_lfanew + 4 + 18) & 0x2000) != 0;

//                // 6. Shellcode generieren (TLS + DllMain)
//                byte[] shellcode = RemoteTlsShellcode.Generate(virtualPe, remoteBase, remoteEp, isDll);

//                IntPtr executionPtr = remoteEp; // Fallback ohne TLS

//                if (shellcode != null)
//                {
//                    IntPtr shellcodePtr = targetProcess.AllocateMemory(shellcode.Length);
//                    targetProcess.WriteMemory(shellcodePtr, shellcode);
//                    executionPtr = shellcodePtr;
//                }

//                // 7. Ausführen
//                targetProcess.StartRemoteThread(executionPtr, IntPtr.Zero);

//                return remoteBase;
//            }
//            catch
//            {
//                // Cleanup TODO: VirtualFreeEx
//                throw;
//            }
//        }
//    }
//}