// Füge diese Klasse am Ende der Datei oder in Models hinzu
using NativeProcesses.Core.Engine;
using NativeProcesses.Core.Models;
using NativeProcesses.Core.Native;
using System;

public class PhantomModuleInfo
{
    public IntPtr BaseAddress;
    public long Size;
    public string NtPath; // Der Kernel-Pfad (z.B. \Device\HarddiskVolume1\Windows\...)
    public bool IsExecutable;
    public string DetectionMethod; // "Unlinked" oder "Shamtom"
}