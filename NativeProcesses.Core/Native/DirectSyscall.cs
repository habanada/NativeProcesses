///*
//   NativeProcesses Framework
//   DirectSyscall.cs - "JIT Trampoline" Edition (Final Version)
//   Combines Halo's Gate resolution with JIT Code Overwriting.
   
//   Strategy:
//   1. Use kernel32!VirtualProtect ONCE to setup the JIT stub (Bootstrap).
//   2. Use the stub itself to execute NtProtectVirtualMemory syscalls for all future operations.
//*/
//using System;
//using System.ComponentModel;
//using System.Runtime.CompilerServices;
//using System.Runtime.InteropServices;

//namespace NativeProcesses.Core.Native
//{
//    public class DirectSyscall : IDisposable
//    {
//        // x64 Syscall Stub
//        // mov r10, rcx
//        // mov eax, <SSN>
//        // syscall
//        // ret
//        private static readonly byte[] SyscallStub64 = new byte[]
//        {
//            0x4C, 0x8B, 0xD1,             // mov r10, rcx
//            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, SSN (Offset 4)
//            0x0F, 0x05,                   // syscall
//            0xC3                          // ret
//        };

//        private IntPtr _stubAddress;
//        private int _currentSsn = -1;

//        // Initialer Bootstrap Flag
//        private bool _isInitialized = false;

//        public DirectSyscall()
//        {
//            PrepareJitMemory();
//        }

//        /// <summary>
//        /// Dummy-Methode, deren Speicher wir kapern.
//        /// </summary>
//        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
//        private static void JitStub()
//        {
//            // Platzhalter-Code, damit der JIT genug Platz reserviert
//            var a = 1; var b = 2; var c = a + b; var d = c * a;
//            return;
//        }

//        private void PrepareJitMemory()
//        {
//            // 1. Methode finden
//            var method = typeof(DirectSyscall).GetMethod(nameof(JitStub), System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
//            if (method == null) throw new Exception("JitStub method not found.");

//            // 2. JIT-Kompilierung erzwingen
//            RuntimeHelpers.PrepareMethod(method.MethodHandle);

//            // 3. Adresse holen
//            _stubAddress = method.MethodHandle.GetFunctionPointer();

//            // 4. Initialer Write mit P/Invoke (Das "Notwendige Übel" für den Bootstrap)
//            // Wir schreiben den nackten Stub (SSN 0). Er ist noch nicht nutzbar.
//            ProtectAndWritePInvoke(_stubAddress, SyscallStub64);
//            _isInitialized = true;
//        }

//        /// <summary>
//        /// Setzt die Syscall-Nummer (SSN).
//        /// </summary>
//        public void SetSyscall(int ssn)
//        {
//            if (_currentSsn == ssn) return;

//            // Wir müssen die SSN an Offset 4 in den Speicher patchen.
//            // Da der Speicher RX ist, müssen wir ihn kurz auf RWX ändern.

//            // Da wir hier gerade den Stub selbst ändern, können wir ihn nicht benutzen, um seine eigenen Rechte zu ändern 
//            // (das würde abstürzen, während wir ihn umschreiben).
//            // Daher nutzen wir für das Patchen des Stubs selbst weiterhin P/Invoke.
//            // Das ist okay, da dies nur passiert, wenn wir die API wechseln (z.B. von NtOpenProcess zu NtAlloc).
//            // Strategie: Instanziiere EINE DirectSyscall pro API, dann passiert das nur 1x.

//            // SSN in den Byte-Array-Puffer schreiben (Offset 4)
//            byte[] patch = new byte[4];
//            Buffer.BlockCopy(BitConverter.GetBytes(ssn), 0, patch, 0, 4);

//            // Im Speicher patchen (Offset 4 bytes vom Start)
//            IntPtr patchAddr = IntPtr.Add(_stubAddress, 4);
//            ProtectAndWritePInvoke(patchAddr, patch);

//            _currentSsn = ssn;
//        }

//        // Hilfsmethode für das Schreiben (Nutzt kernel32!VirtualProtect)
//        private void ProtectAndWritePInvoke(IntPtr address, byte[] data)
//        {
//            // 1. RWX setzen
//            if (!Kernel32.VirtualProtect(address, (UIntPtr)data.Length, 0x40 /* PAGE_EXECUTE_READWRITE */, out uint oldProtect))
//            {
//                throw new Win32Exception(Marshal.GetLastWin32Error());
//            }

//            // 2. Schreiben
//            Marshal.Copy(data, 0, address, data.Length);

//            // 3. Rechte wiederherstellen (Wichtig für Evasion!)
//            Kernel32.VirtualProtect(address, (UIntPtr)data.Length, oldProtect, out _);
//        }

//        // --- Delegates ---

//        // Generischer Syscall Delegate (für die meisten NT-Funktionen bis 6 Argumente)
//        // Die Argumente müssen exakt matchen.

//        // Beispiel für NtAllocateVirtualMemory
//        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
//        public delegate int NtAllocateDelegate(
//            IntPtr ProcessHandle,
//            ref IntPtr BaseAddress,
//            IntPtr ZeroBits,
//            ref IntPtr RegionSize,
//            uint AllocationType,
//            uint Protect
//        );

//        // Beispiel für NtProtectVirtualMemory
//        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
//        public delegate int NtProtectDelegate(
//            IntPtr ProcessHandle,
//            ref IntPtr BaseAddress,
//            ref IntPtr RegionSize,
//            uint NewProtect,
//            out uint OldProtect
//        );

//        // Beispiel für NtWriteVirtualMemory
//        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
//        public delegate int NtWriteDelegate(
//            IntPtr ProcessHandle,
//            IntPtr BaseAddress,
//            byte[] Buffer,
//            uint NumberOfBytesToWrite,
//            out uint NumberOfBytesWritten
//        );

//        // Beispiel für NtCreateThreadEx
//        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
//        public delegate int NtCreateThreadExDelegate(
//            out IntPtr threadHandle,
//            uint desiredAccess,
//            IntPtr objectAttributes,
//            IntPtr processHandle,
//            IntPtr startAddress,
//            IntPtr parameter,
//            bool createSuspended,
//            int stackZeroBits,
//            int sizeOfStackCommit,
//            int sizeOfStackReserve,
//            IntPtr bytesBuffer
//        );

//        // Beispiel für NtWaitForSingleObject
//        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
//        public delegate int NtWaitForSingleObjectDelegate(
//            IntPtr Handle,
//            bool Alertable,
//            IntPtr Timeout
//        );

//        public T GetDelegate<T>() where T : Delegate
//        {
//            return Marshal.GetDelegateForFunctionPointer<T>(_stubAddress);
//        }

//        public void Dispose()
//        {
//            if (_stubAddress != IntPtr.Zero)
//            {
//                // Stub unschädlich machen (RET)
//                ProtectAndWritePInvoke(_stubAddress, new byte[] { 0xC3 });
//                _stubAddress = IntPtr.Zero;
//            }
//        }

      
//    }
//}