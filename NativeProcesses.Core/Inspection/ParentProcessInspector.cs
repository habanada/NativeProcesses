/*
   NativeProcesses Framework  |
   © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using NativeProcesses.Core.Engine;
using NativeProcesses.Core.Native;
using static NativeProcesses.Core.Native.NtProcessInfoStructs;
using static NativeProcesses.Core.Native.NativeDefinitions;

namespace NativeProcesses.Core.Inspection
{
    public class ParentProcessInspector
    {
        private readonly IEngineLogger _logger;

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            IntPtr processInformation,
            uint processInformationLength,
            out uint returnLength);

        public ParentProcessInspector(IEngineLogger logger)
        {
            _logger = logger;
        }

        public PeAnomalyInfo CheckForParentSpoofing(int pid, ManagedProcess process)
        {
            try
            {
                // 1. Parent PID via NTAPI auslesen
                int parentPid = GetParentPid(process);
                if (parentPid <= 0) return null;

                // 2. Existiert der Parent überhaupt noch?
                Process parentProc = null;
                try
                {
                    parentProc = Process.GetProcessById(parentPid);
                }
                catch (ArgumentException)
                {
                    // Parent existiert nicht mehr.
                    // Das ist bei kurzlebigen Loadern normal.
                    // Aber wenn der Parent angeblich "winlogon.exe" oder "services.exe" ist, 
                    // diese aber nicht existieren (unwahrscheinlich) oder die PID nicht passt, ist das verdächtig.
                    // Wir markieren es hier als "Info", wenn wir den Namen kennen würden (was wir ohne Process-Objekt schwer können).
                    return null;
                }
                catch (Exception)
                {
                    return null; // Zugriff verweigert o.ä.
                }

                // 3. Plausibilitäts-Check: Startzeit
                // Ein Kind kann nicht VOR seinem Vater geboren werden.
                try
                {
                    Process childProc = Process.GetProcessById(pid);

                    // Wir geben etwas Toleranz (z.B. Sysprep oder Kernel-Eigenheiten), aber grob muss es stimmen.
                    if (childProc.StartTime < parentProc.StartTime)
                    {
                        return new PeAnomalyInfo
                        {
                            ModuleName = "Process Structure",
                            AnomalyType = "Parent Process Spoofing",
                            Details = $"Child (PID {pid}) started at {childProc.StartTime}, but Parent '{parentProc.ProcessName}' (PID {parentPid}) started LATER at {parentProc.StartTime}. This is logically impossible and indicates PID reuse or spoofing (e.g., via UpdateProcThreadAttribute).",
                            Severity = "High"
                        };
                    }
                }
                catch (System.ComponentModel.Win32Exception)
                {
                    // Zugriff auf StartTime verweigert (oft bei System-Prozessen)
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Debug, $"Parent check failed for PID {pid}", ex);
            }

            return null;
        }

        private int GetParentPid(ManagedProcess process)
        {
            bool isWow64 = process.GetIsWow64();
            IntPtr pbiPtr = IntPtr.Zero;

            try
            {
                if (isWow64)
                {
                    // 32-Bit Prozess auf 64-Bit System
                    // Wir müssen ProcessWow64Information abfragen, um die Adresse des 32-Bit PEB zu bekommen,
                    // aber die Parent PID steht im nativen PROCESS_BASIC_INFORMATION Struct, das immer verfügbar ist.
                    // NT liefert immer 64-bit PBI für 64-bit Kernel.
                }

                // Wir nutzen PROCESS_BASIC_INFORMATION (Architecture independent logic via Marshalling)
                // Auf 64-Bit OS ist PBI 64-Bit.

                int pbiSize = Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION_64));
                pbiPtr = Marshal.AllocHGlobal(pbiSize);

                int status = NtQueryInformationProcess(
                    process.Handle,
                    ProcessInformationClass.ProcessBasicInformation,
                    pbiPtr,
                    (uint)pbiSize,
                    out _);

                if (status != 0) // STATUS_SUCCESS
                {
                    return -1;
                }

                // Wir lesen als 64-Bit Struktur (funktioniert auf x64 OS auch für WoW64 Prozesse korrekt für diesen Zweck)
                // Wenn wir auf 32-Bit OS wären, müssten wir _32 nutzen. Wir gehen von x64 OS aus (Standard heute).
                if (IntPtr.Size == 8)
                {
                    var pbi = (PROCESS_BASIC_INFORMATION_64)Marshal.PtrToStructure(pbiPtr, typeof(PROCESS_BASIC_INFORMATION_64));
                    return (int)pbi.InheritedFromUniqueProcessId;
                }
                else
                {
                    var pbi = (PROCESS_BASIC_INFORMATION_32)Marshal.PtrToStructure(pbiPtr, typeof(PROCESS_BASIC_INFORMATION_32));
                    return (int)pbi.InheritedFromUniqueProcessId;
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Error, "GetParentPid failed.", ex);
                return -1;
            }
            finally
            {
                if (pbiPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pbiPtr);
                }
            }
        }
    }
}