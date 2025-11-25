/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Microsoft.Diagnostics.Runtime;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NativeProcesses.Core.Inspection.Heuristics
{
    public class RatPatternScanner
    {
        // Typische RAT Befehle
        private static readonly HashSet<string> RatCommands = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "PING", "PONG", "KEEPALIVE", "GETLOGS", "SCREENSHOT", "CAM", "MIC", "DL", "EXEC", "PASSWORDS", "PLUGIN", "VISIT", "DDOS"
        };

        // Bekannte böse Mutex-Muster oder Namen
        private static readonly HashSet<string> SuspiciousMutexPatterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "qazwsx", "winlogon", "svchost", "explorer", // Fake System Mutexes
            "dc_mutex", "async_mutex", "nanocore_mutex", "nj-q8"
        };

        // C2 Packet Header Marker (Erste 4 Bytes von typischen RAT-Paketen)
        // QuasarRAT / TinyNuke / etc. nutzen oft Längen-Präfixe oder Magic Bytes
        private static readonly byte[][] C2Markers = new byte[][]
        {
            new byte[] { 0x00, 0x00, 0x00, 0x0C }, // Längen-Präfix (klein)
            new byte[] { 0x49, 0x4E, 0x56, 0x4B }, // "INVK" (Invoke)
            new byte[] { 0x50, 0x49, 0x4E, 0x47 }  // "PING"
        };

        public IEnumerable<HeuristicResult> Scan(ClrHeap heap)
        {
            var results = new List<HeuristicResult>();

            int pipeCount = 0;
            int webClientCount = 0;
            int timerCount = 0;
            int suspiciousDelegates = 0;

            // Flags um Duplikate zu vermeiden
            bool ratQueueFound = false;
            bool loaderPatternFound = false;
            bool dispatcherFound = false;

            foreach (var obj in heap.EnumerateObjects())
            {
                if (obj.Type == null) continue;
                string typeName = obj.Type.Name;
                if (string.IsNullOrEmpty(typeName)) continue;

                // --- BEHAVIOR: Mutex Detection ---
                if (typeName == "System.Threading.Mutex")
                {
                    CheckMutex(obj, results);
                }

                // --- BEHAVIOR: Timer Loops (Beaconing) ---
                else if (typeName == "System.Threading.Timer" || typeName == "System.Windows.Forms.Timer")
                {
                    timerCount++;
                    if (timerCount == 10) // Wenn > 10 Timer -> Heavy Polling / Beaconing
                    {
                        results.Add(CreateResult("High Timer Activity", ScanCategory.General, ThreatScore.Medium, obj.Address, "Multiple Timers detected (Potential Beaconing/Polling)", "Count > 10"));
                    }
                    CheckTimerCallback(obj, results);
                }

                // --- BEHAVIOR: Named Pipes ---
                else if (typeName.Contains("NamedPipeServerStream") || typeName.Contains("NamedPipeClientStream"))
                {
                    pipeCount++;
                    if (pipeCount == 1)
                        results.Add(CreateResult("IPC / Named Pipe Usage", ScanCategory.General, ThreatScore.Low, obj.Address, "Pipe Stream Object detected", typeName));
                }

                // --- BEHAVIOR: Command Dispatcher ---
                // Dictionary<String, Delegate> oder Dictionary<String, Action> ist typisch für RAT Command Handler
                else if (!dispatcherFound && typeName.StartsWith("System.Collections.Generic.Dictionary"))
                {
                    if (typeName.Contains("String") && (typeName.Contains("Delegate") || typeName.Contains("Action") || typeName.Contains("MethodInfo")))
                    {
                        results.Add(CreateResult("Command Dispatcher Pattern", ScanCategory.StealerArtifact, ThreatScore.High, obj.Address, "Dictionary mapping Strings to Code (Commands)", typeName));
                        dispatcherFound = true;
                    }
                }

                // --- NETWORK: WebClient / HttpClient Misuse ---
                else if (typeName == "System.Net.WebClient" || typeName == "System.Net.Http.HttpClient")
                {
                    webClientCount++;
                    CheckWebClient(obj, results);
                }

                // --- NETWORK: C2 Packets (Byte Arrays) ---
                else if (obj.IsArray && obj.Type.ElementType == ClrElementType.UInt8)
                {
                    var arr = obj.AsArray();
                    // C2 Pakete sind oft klein (Header)
                    if (arr.Length > 4 && arr.Length < 256)
                    {
                        CheckC2Packet(obj, results);
                    }
                }

                // --- CODE: Delegate Misuse (Shellcode) ---
                else if (IsDelegateType(obj.Type))
                {
                    if (IsSuspiciousDelegate(obj))
                    {
                        suspiciousDelegates++;
                        if (suspiciousDelegates <= 5)
                            results.Add(CreateResult("Delegate to Unmanaged Code", ScanCategory.CodeInjection, ThreatScore.Critical, obj.Address, "Delegate points to raw memory/shellcode", typeName));
                    }
                }

                // --- CODE: Command Loop (Queue) ---
                else if (!ratQueueFound && (typeName.StartsWith("System.Collections.Generic.Queue") || typeName.StartsWith("System.Collections.Generic.List")))
                {
                    if (typeName.Contains("String"))
                    {
                        if (CheckForRatCommands(obj))
                        {
                            results.Add(CreateResult("RAT Command Loop Detected", ScanCategory.StealerArtifact, ThreatScore.Critical, obj.Address, "Queue contains RAT commands (PING/CAP/EXEC)", typeName));
                            ratQueueFound = true;
                        }
                    }
                }

                // --- CODE: Loader Pattern ---
                else if (!loaderPatternFound && !typeName.StartsWith("System") && !typeName.StartsWith("Microsoft"))
                {
                    if (IsLoaderPattern(obj))
                    {
                        results.Add(CreateResult("Dynamic Assembly Loader Pattern", ScanCategory.CodeInjection, ThreatScore.High, obj.Address, "Object holds both Raw Bytes and Loaded Assembly", typeName));
                        loaderPatternFound = true;
                    }
                }

                // --- ARTIFACTS: Hardcoded Class Names ---
                if (CheckHardcodedNames(typeName, obj.Address, results)) continue;
            }

            if (webClientCount > 5)
            {
                results.Add(CreateResult("WebClient Flood", ScanCategory.Network, ThreatScore.Medium, 0, "High number of WebClient/HttpClient instances", $"Count: {webClientCount}"));
            }

            return results;
        }

        // --- Helper Methods ---

        private void CheckMutex(ClrObject obj, List<HeuristicResult> results)
        {
            try
            {
                // Wir versuchen den Namen zu lesen (internal fields variieren je nach .NET Version, oft in SafeWaitHandle oder direkt)
                // Bei ClrMD ist das schwer direkt zu lesen, da Mutex ein Wrapper um ein OS-Handle ist.
                // Wir suchen hier nach dem String-Feld "id" oder "name", das manche Wrapper haben.
                // Fallback: Wir verlassen uns auf Strings im Heap (StringScanner), die wie Mutex aussehen.
                // Aber wir können prüfen, ob das Objekt "verwaist" ist oder statisch gehalten wird.
            }
            catch { }
        }

        private void CheckTimerCallback(ClrObject obj, List<HeuristicResult> results)
        {
            try
            {
                // Timer -> m_callback -> MethodPtr
                var callback = obj.ReadObjectField("m_callback");
                if (!callback.IsNull)
                {
                    if (IsSuspiciousDelegate(callback))
                    {
                        results.Add(CreateResult("Malicious Timer Callback", ScanCategory.CodeInjection, ThreatScore.Critical, obj.Address, "Timer triggers Shellcode/Unmanaged Code", "Timer"));
                    }
                }
            }
            catch { }
        }

        private void CheckWebClient(ClrObject obj, List<HeuristicResult> results)
        {
            try
            {
                // Versuch, die BaseAddress zu lesen (WebClient)
                var baseAddressObj = obj.ReadObjectField("m_baseAddress");

                // Fallback für HttpClient: BaseAddress Property
                if (baseAddressObj.IsNull)
                {
                    // HttpClient Struktur ist komplexer, oft in "BaseAddress" Property (Backing Field)
                    // Wir schauen einfach generisch nach Strings im Objekt, falls m_baseAddress fehlt.
                    // (Für dieses Beispiel bleiben wir beim sauberen Feld-Zugriff, wenn möglich)
                }

                if (!baseAddressObj.IsNull && baseAddressObj.Type.IsString)
                {
                    string url = baseAddressObj.AsString(1024);

                    // --- NEU: Aufruf der NetworkHeuristics Klasse ---
                    if (NetworkHeuristics.IsSuspiciousUrl(url, out string reason))
                    {
                        results.Add(CreateResult("Suspicious WebClient Target", ScanCategory.Network, ThreatScore.High, obj.Address, $"WebClient connecting to suspicious target: {url}", reason));
                    }
                }
            }
            catch { }
        }

        private void CheckC2Packet(ClrObject obj, List<HeuristicResult> results)
        {
            try
            {
                var arr = obj.AsArray();
                byte[] header = new byte[4];
                for (int i = 0; i < 4; i++) header[i] = arr.GetValue<byte>(i);

                foreach (var marker in C2Markers)
                {
                    if (header[0] == marker[0] && header[1] == marker[1] && header[2] == marker[2] && header[3] == marker[3])
                    {
                        results.Add(CreateResult("Potential C2 Packet Header", ScanCategory.Network, ThreatScore.Medium, obj.Address, "Byte array starts with known RAT magic bytes", BitConverter.ToString(header)));
                        return;
                    }
                }
            }
            catch { }
        }

        private bool IsDelegateType(ClrType type)
        {
            if (type == null) return false;
            ClrType current = type;
            while (current != null)
            {
                if (current.Name == "System.Delegate" || current.Name == "System.MulticastDelegate") return true;
                current = current.BaseType;
            }
            return false;
        }

        private bool IsSuspiciousDelegate(ClrObject obj)
        {
            try
            {
                var methodPtr = obj.ReadField<ulong>("_methodPtr");
                var runtime = obj.Type.Heap.Runtime;
                var method = runtime.GetMethodByInstructionPointer(methodPtr);

                // Zeigt auf User-Mode Speicher, aber nicht auf eine bekannte .NET Methode -> Shellcode
                if (method == null && methodPtr > 0x10000 && methodPtr < 0x7FFFFFFFFFFF)
                {
                    return true;
                }
            }
            catch { }
            return false;
        }

        private bool CheckForRatCommands(ClrObject obj)
        {
            try
            {
                var itemsField = obj.ReadObjectField("_items");
                if (itemsField.IsNull) itemsField = obj.ReadObjectField("_array");

                if (!itemsField.IsNull && itemsField.IsArray)
                {
                    var arr = itemsField.AsArray();
                    int len = Math.Min(arr.Length, 20);

                    for (int i = 0; i < len; i++)
                    {
                        var strObj = arr.GetObjectValue(i);
                        if (!strObj.IsNull && strObj.Type.IsString)
                        {
                            string val = strObj.AsString(128);
                            if (!string.IsNullOrEmpty(val) && RatCommands.Contains(val.ToUpperInvariant()))
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        private bool IsLoaderPattern(ClrObject obj)
        {
            try
            {
                bool hasByteArray = false;
                bool hasAssembly = false;

                foreach (var field in obj.Type.Fields)
                {
                    if (field.Type == null) continue;
                    if (field.Type.Name == "System.Byte[]") hasByteArray = true;
                    if (field.Type.Name == "System.Reflection.Assembly") hasAssembly = true;
                }
                return hasByteArray && hasAssembly;
            }
            catch { return false; }
        }

        private bool CheckHardcodedNames(string name, ulong address, List<HeuristicResult> results)
        {
            if (name.Contains("Client.Network") || name.Contains("NanoCore"))
            {
                results.Add(CreateResult("RAT Signature: NanoCore", ScanCategory.StealerArtifact, ThreatScore.Critical, address, "NanoCore class detected", name));
                return true;
            }
            if (name.Contains("RecoveredApplication") || name.Contains("AccountGrabber"))
            {
                results.Add(CreateResult("RAT Signature: Stealer", ScanCategory.StealerArtifact, ThreatScore.High, address, "Stealer artifact detected", name));
                return true;
            }
            if (name.Contains("ConfusedByAttribute"))
            {
                results.Add(CreateResult("Obfuscator: ConfuserEx", ScanCategory.Obfuscation, ThreatScore.Medium, address, "ConfuserEx artifact", name));
                return true;
            }
            return false;
        }

        private HeuristicResult CreateResult(string rule, ScanCategory cat, ThreatScore score, ulong addr, string details, string artifact)
        {
            return new HeuristicResult(rule, cat, score, details, addr.ToString("X"), artifact);
        }
    }
}