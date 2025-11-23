namespace NativeProcesses.Core.Inspection
{
    public enum HookTrustLevel
    {
        Malicious,      // Zeigt auf Shellcode / Unbacked Memory (ROT)
        Suspicious,     // Zeigt auf unsignierte DLL (ORANGE)
        ThirdParty,     // Signiert von Drittanbieter (Google, Mozilla etc.) (BLAU)
        Microsoft,      // Signiert von Microsoft (aber nicht im System32) (GRÜN)
        System          // System32 + Microsoft Signed (GRAU/AUSGEBLENDET)
    }
}