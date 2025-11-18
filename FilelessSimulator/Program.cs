using System;
using System.IO;
using System.Reflection;
using System.Threading;

namespace FilelessSimulator
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Title = "NativeProcesses - Fileless Malware Test";
            int pid = System.Diagnostics.Process.GetCurrentProcess().Id;

            Console.WriteLine($"[*] Process started. PID: {pid}");
            Console.WriteLine("--------------------------------------------------");
            Console.WriteLine("This tool simulates 'Fileless' .NET Malware execution.");
            Console.WriteLine("It loads an assembly directly from a byte array into memory.");
            Console.WriteLine("Your scanner should detect this as a 'Floating Assembly'.");
            Console.WriteLine("--------------------------------------------------");

            // 1. Wir brauchen eine "Payload" DLL.
            // Zu Demonstrationszwecken laden wir einfach eine harmlose System-DLL 
            // oder das Programm selbst in ein Byte-Array. 
            // In echter Malware wäre dieses Byte-Array verschlüsselt oder käme aus dem Netzwerk.
            string targetPath = typeof(Program).Assembly.Location; // Wir laden uns selbst rekursiv

            Console.WriteLine($"[*] Reading file bytes from disk: {Path.GetFileName(targetPath)}");
            byte[] assemblyBytes = File.ReadAllBytes(targetPath);

            Console.WriteLine($"[*] Size in memory: {assemblyBytes.Length:N0} bytes");

            // 2. DER KRITISCHE SCHRITT: Assembly.Load(byte[])
            // Das erzeugt im CLR-Speicher ein Modul mit dem Layout "Flat" statt "Mapped".
            // ClrMD (und dein Tool) erkennt, dass es keine Datei-Bindung auf dem Datenträger gibt.
            try
            {
                Console.WriteLine("[!] Executing Assembly.Load(bytes)...");
                Assembly floatingAssembly = Assembly.Load(assemblyBytes);

                Console.WriteLine("[+] Assembly loaded successfully!");
                Console.WriteLine($"    FullName: {floatingAssembly.FullName}");
                Console.WriteLine($"    Location: '{floatingAssembly.Location}' (Should be empty or meaningless)");
                Console.WriteLine($"    IsDynamic: {floatingAssembly.IsDynamic}"); // Sollte false sein, sonst wäre es eine andere Detection
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error loading assembly: {ex.Message}");
            }

            Console.WriteLine("\n[!] SUSPICIOUS STATE ACTIVE.");
            Console.WriteLine($"[!] Scan PID {pid} now with 'DotNetMalware' flag enabled.");
            Console.WriteLine("[*] Press ENTER to exit...");
            Console.ReadLine();
        }
    }
}