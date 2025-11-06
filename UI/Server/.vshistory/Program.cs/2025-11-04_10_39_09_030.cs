using NativeProcesses;
using NativeProcesses.Core;
using NativeProcesses.Network;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace ProcessServer
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Starting Process Server...");

            string certPath = "cert.pfx";
            string certPass = "password";
            string token = "MySecretToken";
            int port = 8888;
            X509Certificate2 cert = null;

            if (!File.Exists(certPath))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"FATAL ERROR: Certificate file not found: {Path.GetFullPath(certPath)}");
                Console.WriteLine("Please create a self-signed certificate (e.g., with PowerShell) and export it as cert.pfx");
                Console.WriteLine("PowerShell: New-SelfSignedCertificate -DnsName \"localhost\" -CertStoreLocation \"cert:\\CurrentUser\\My\" -FriendlyName \"ProcessServerTest\"");
                Console.WriteLine("After that, export it from certmgr.msc (Personal Store) as 'cert.pfx' with a password.");
                Console.ReadLine();
                return;
            }

            try
            {
                cert = new X509Certificate2(certPath, certPass, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
                Console.WriteLine("Certificate loaded: " + cert.Subject);
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"FATAL ERROR: Could not load certificate '{certPath}'.");
                Console.WriteLine("Check the password and ensure the file is a valid .pfx (Try exporting with TripleDES-SHA1).");
                Console.WriteLine(ex.Message);
                Console.ReadLine();
                return;
            }

            var provider = new PollingProcessProvider(TimeSpan.FromSeconds(3));
            var logger = new ConsoleLogger();
            var service = new ProcessService(provider, logger);

            service.DetailOptions.LoadSignatureInfo = true;
            service.DetailOptions.LoadMitigationInfo = true;

            var server = new SecureTcpServer(port, cert,token);
            var hostInstance = new ProcessNetworkHost(service, server, provider);

            service.Start();
            _ = server.StartAsync();

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"Server listening on port {port}...");
            Console.WriteLine($"Token: {token}");
            Console.WriteLine("Press ENTER to stop the server.");
            Console.ReadLine();

            Console.WriteLine("Shutting down...");
            hostInstance.ShutdownServer();
            Console.WriteLine("Server stopped.");
        }
    }

    public class ConsoleLogger : IEngineLogger
    {
        private readonly object _lock = new object();
        public void Log(LogLevel level, string message, Exception ex = null)
        {
            lock (_lock)
            {
                switch (level)
                {
                    case LogLevel.Error:
                        Console.ForegroundColor = ConsoleColor.Red;
                        break;
                    case LogLevel.Warning:
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        break;
                    case LogLevel.Info:
                        Console.ForegroundColor = ConsoleColor.White;
                        break;
                    case LogLevel.Debug:
                        Console.ForegroundColor = ConsoleColor.Gray;
                        break;
                }
              //  if (!message.Contains("Failed to get") && !message.Contains("Failed to open"))
                {
                    Console.WriteLine($"[{level}] {message}");
                    if (ex != null)
                    {
                        Console.WriteLine(ex.ToString());
                    }
                }
                Console.ResetColor();
            }
        }
    }
}

