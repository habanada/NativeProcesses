using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using NativeProcesses.Core.Engine;

namespace NativeProcesses.Core.Native
{
    public static class SnapshotDumper
    {
        /// <summary>
        /// Erstellt einen stealthy Minidump über PSS Snapshotting.
        /// </summary>
        public static string CreateSafeDump(int pid, IEngineLogger logger)
        {
            string tempFile = Path.GetTempFileName();

            // Wir brauchen Handle-Rechte für Snapshot
            var access = ProcessAccessFlags.QueryInformation |
                         ProcessAccessFlags.VmRead |
                         ProcessAccessFlags.DuplicateHandle |
                         ProcessAccessFlags.CreateProcess; // PSS braucht das manchmal

            ManagedProcess liveProc = null;
            ProcessSnapshot snapshot = null;

            try
            {
                liveProc = new ManagedProcess(pid, access);

                // 1. Snapshot erstellen (Copy-on-Write Clone im Kernel)
                // Nutzt deine existierende ProcessSnapshot Klasse
                snapshot = new ProcessSnapshot(liveProc, logger);

                if (snapshot.CloneProcessHandle == IntPtr.Zero)
                {
                    throw new Exception("Snapshot Clone Handle ist Invalid.");
                }

                // 2. Dump schreiben (Vom Clone Handle, NICHT vom Live Prozess!)
                using (FileStream fs = new FileStream(tempFile, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
                {
                    bool success = NativeDefinitions.DbgHelp.MiniDumpWriteDump(
                        snapshot.CloneProcessHandle, // <-- Der Trick: Wir dumpen den Clone
                        (uint)pid,
                        fs.SafeFileHandle.DangerousGetHandle(),
                        NativeDefinitions.DbgHelp.MiniDumpType.MiniDumpWithFullMemory |
                        NativeDefinitions.DbgHelp.MiniDumpType.MiniDumpWithHandleData,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        IntPtr.Zero
                    );

                    if (!success)
                    {
                        int err = Marshal.GetLastWin32Error();
                        throw new System.ComponentModel.Win32Exception(err);
                    }
                }

                return tempFile;
            }
            catch (Exception ex)
            {
                logger?.Log(LogLevel.Error, $"Dump generation failed for PID {pid}", ex);
                // Datei löschen bei Fehler
                if (File.Exists(tempFile)) try { File.Delete(tempFile); } catch { }
                return null;
            }
            finally
            {
                snapshot?.Dispose();
                liveProc?.Dispose();
            }
        }
    }
}