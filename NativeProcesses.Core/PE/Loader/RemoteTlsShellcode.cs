//using System;
//using System.Collections.Generic;
//using System.IO;
//using System.Runtime.InteropServices;
//using NativeProcesses.Core.PE;

//namespace NativeProcesses.Core.PE.Loader
//{
//    public static class RemoteTlsShellcode
//    {
//        public static byte[] Generate(byte[] peImage, IntPtr remoteBase, IntPtr entryPoint, bool isDll)
//        {
//            // 1. TLS Callbacks finden
//            var callbacks = GetTlsCallbacks(peImage, remoteBase);

//            // Wenn keine Callbacks und keine DLL Main Args nötig -> Kein Stub nötig, direkt EntryPoint
//            if (callbacks.Count == 0 && !isDll) return null;

//            using (var ms = new MemoryStream())
//            using (var writer = new BinaryWriter(ms))
//            {
//                // --- x64 Shellcode (Simplified) ---
//                // Align Stack
//                writer.Write(new byte[] { 0x48, 0x83, 0xE4, 0xF0 }); // AND RSP, -16
//                writer.Write(new byte[] { 0x48, 0x83, 0xEC, 0x28 }); // SUB RSP, 0x28 (Shadow Space)

//                // 1. Execute TLS Callbacks
//                foreach (var cb in callbacks)
//                {
//                    // RCX = ModuleBase (DllHandle)
//                    writer.Write(new byte[] { 0x48, 0xB9 });
//                    writer.Write(remoteBase.ToInt64());

//                    // RDX = Reason (1 = DLL_PROCESS_ATTACH)
//                    writer.Write(new byte[] { 0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00 });

//                    // R8 = Reserved (0)
//                    writer.Write(new byte[] { 0x4D, 0x31, 0xC0 }); // XOR R8, R8

//                    // MOV RAX, CallbackAddr
//                    writer.Write(new byte[] { 0x48, 0xB8 });
//                    writer.Write(cb.ToInt64());

//                    // CALL RAX
//                    writer.Write(new byte[] { 0xFF, 0xD0 });
//                }

//                // 2. Execute EntryPoint
//                // RCX = ModuleBase (DllHandle / hInstance)
//                writer.Write(new byte[] { 0x48, 0xB9 });
//                writer.Write(remoteBase.ToInt64());

//                if (isDll)
//                {
//                    // RDX = Reason (1 = DLL_PROCESS_ATTACH)
//                    writer.Write(new byte[] { 0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00 });

//                    // R8 = Reserved (0)
//                    writer.Write(new byte[] { 0x4D, 0x31, 0xC0 });
//                }

//                // MOV RAX, EntryPoint
//                writer.Write(new byte[] { 0x48, 0xB8 });
//                writer.Write(entryPoint.ToInt64());

//                // CALL RAX
//                writer.Write(new byte[] { 0xFF, 0xD0 });

//                // Cleanup & Ret
//                writer.Write(new byte[] { 0x48, 0x83, 0xC4, 0x28 }); // ADD RSP, 0x28
//                writer.Write(new byte[] { 0xC3 }); // RET

//                return ms.ToArray();
//            }
//        }

//        private static List<IntPtr> GetTlsCallbacks(byte[] image, IntPtr remoteBase)
//        {
//            var list = new List<IntPtr>();
//            int e_lfanew = BitConverter.ToInt32(image, 0x3C);
//            // Assume x64 for now as requested for "Realität"
//            int optHeader = e_lfanew + 24;
//            int tlsDirOffset = optHeader + 112 + (9 * 8); // DataDirectory[9]

//            uint tlsRva = BitConverter.ToUInt32(image, tlsDirOffset);
//            if (tlsRva == 0) return list;

//            // Read Image_TLS_Directory64 from local buffer
//            int dirOffset = (int)tlsRva;
//            // AddressOfCallbacks is at offset 24 in IMAGE_TLS_DIRECTORY64
//            ulong callbacksVa = BitConverter.ToUInt64(image, dirOffset + 24);

//            if (callbacksVa == 0) return list;

//            // Convert VA to RVA (assuming linear mapping) to find offset in buffer
//            // Problem: AddressOfCallbacks is a VA inside the image.
//            // If we haven't relocated locally yet, this VA is based on PreferredImageBase.
//            // We need to find the RVA of the Callbacks Array.

//            ulong imageBase = BitConverter.ToUInt64(image, optHeader + 24);
//            uint callbacksArrayRva = (uint)(callbacksVa - imageBase);

//            int currentOffset = (int)callbacksArrayRva;
//            while (true)
//            {
//                ulong cbVa = BitConverter.ToUInt64(image, currentOffset);
//                if (cbVa == 0) break;

//                // Relocate to NEW remote base
//                ulong rva = cbVa - imageBase;
//                list.Add((IntPtr)((long)remoteBase + (long)rva));

//                currentOffset += 8;
//            }

//            return list;
//        }
//    }
//}