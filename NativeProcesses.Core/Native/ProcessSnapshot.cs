/*
   NativeProcesses Framework  |
   © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using NativeProcesses.Core.Engine;

namespace NativeProcesses.Core.Native
{
    public class ProcessSnapshot : IDisposable
    {
        private IntPtr _processHandle; // Handle auf den Originalprozess
        private IntPtr _snapshotHandle; // Handle auf den PSS Snapshot
        public IntPtr CloneProcessHandle { get; private set; } // Handle auf den VA Clone (zum Lesen)
        private bool _isDisposed = false;
        private readonly IEngineLogger _logger;

        public ProcessSnapshot(ManagedProcess process, IEngineLogger logger = null)
        {
            _processHandle = process.Handle;
            _logger = logger;

            // Capture Flags: Wir wollen den VA (Virtual Address) Clone und Thread Infos
            var flags = PssDefines.PSS_CAPTURE_FLAGS.PSS_CAPTURE_VA_CLONE |
                        PssDefines.PSS_CAPTURE_FLAGS.PSS_CAPTURE_THREADS |
                        PssDefines.PSS_CAPTURE_FLAGS.PSS_CAPTURE_VA_SPACE;

            int result = PssDefines.PssCaptureSnapshot(_processHandle, flags, 0, out _snapshotHandle);
            if (result != 0) // ERROR_SUCCESS = 0
            {
                throw new Win32Exception(result, "PssCaptureSnapshot failed.");
            }

            // Wir müssen das Handle für den VA Clone abfragen, um Speicher zu lesen
            QueryCloneHandle();
        }

        private void QueryCloneHandle()
        {
            int size = Marshal.SizeOf(typeof(PssDefines.PSS_VA_CLONE_INFORMATION));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                int result = PssDefines.PssQuerySnapshot(
                    _snapshotHandle,
                    PssDefines.PSS_QUERY_INFORMATION_CLASS.PssQueryVaCloneInformation,
                    buffer,
                    size);

                if (result != 0)
                {
                    throw new Win32Exception(result, "PssQuerySnapshot (VaClone) failed.");
                }

                var info = (PssDefines.PSS_VA_CLONE_INFORMATION)Marshal.PtrToStructure(buffer, typeof(PssDefines.PSS_VA_CLONE_INFORMATION));
                CloneProcessHandle = info.VaCloneHandle;

                if (CloneProcessHandle == IntPtr.Zero)
                {
                    _logger?.Log(LogLevel.Warning, "PssCaptureSnapshot succeeded, but VaCloneHandle is NULL.");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public void Dispose()
        {
            if (!_isDisposed)
            {
                if (_snapshotHandle != IntPtr.Zero)
                {
                    // Snapshot freigeben. Das schließt auch das CloneProcessHandle.
                    PssDefines.PssFreeSnapshot(_processHandle, _snapshotHandle);
                    _snapshotHandle = IntPtr.Zero;
                }
                _isDisposed = true;
            }
        }
    }
}