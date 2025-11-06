using NativeProcesses;
using NativeProcesses.Core;
using NativeProcesses.Network;
using System;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ProcessServer
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Starting Process Server...");

            string host = Dns.GetHostName();
            string token = "MySecretToken";
            int port = 8888;
            X509Certificate2 cert = null;

            try
            {
                cert = GetOrCreateTestCert(host);
                Console.WriteLine("Certificate loaded: " + cert.Subject);
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("FATAL ERROR: Could not create or find certificate.");
                Console.WriteLine("Please run this server as Administrator once to create the cert.");
                Console.WriteLine(ex.Message);
                Console.ReadLine();
                return;
            }

            var provider = new PollingProcessProvider(TimeSpan.FromSeconds(3));
            var logger = new ConsoleLogger();
            var service = new ProcessService(provider, logger);

            service.DetailOptions.LoadSignatureInfo = true;
            service.DetailOptions.LoadMitigationInfo = true;

            var server = new SecureTcpServer(port, cert, token);
            var hostInstance = new ProcessNetworkHost(service, server, provider);

            service.Start();
            server.StartAsync().Wait();

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"Server listening on port {port}...");
            Console.WriteLine($"Token: {token}");
            Console.WriteLine("Press ENTER to stop the server.");
            Console.ReadLine();

            Console.WriteLine("Shutting down...");
            hostInstance.ShutdownServer();
            Console.WriteLine("Server stopped.");
        }

        private static X509Certificate2 GetOrCreateTestCert(string hostName)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindBySubjectName, hostName, false);
            store.Close();

            if (certs.Count > 0)
            {
                return certs[0];
            }

            using (RSA rsa = RSA.Create(2048))
            {
                var req = new CertificateRequest($"cn={hostName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                req.CertificateExtensions.Add(
                    new X509KeyUsageExtension(X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, false));

                req.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

                var sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddDnsName(hostName);
                sanBuilder.AddDnsName("localhost");
                sanBuilder.AddIpAddress(IPAddress.Loopback);
                req.CertificateExtensions.Add(sanBuilder.Build());

                X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(5));
                cert.FriendlyName = "ProcessServer Test Cert";

                byte[] pfxBytes = cert.Export(X509ContentType.Pfx, (string)null);
                X509Certificate2 persistentCert = new X509Certificate2(pfxBytes, (string)null, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);

                store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                store.Add(persistentCert);
                store.Close();

                return persistentCert;
            }
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
                Console.WriteLine($"[{level}] {message}");
                if (ex != null)
                {
                    Console.WriteLine(ex.ToString());
                }
                Console.ResetColor();
            }
        }
    }
}
