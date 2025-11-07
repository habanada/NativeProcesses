/*

 ██████   █████            █████     ███                       ███████████                                                                       
░░██████ ░░███            ░░███     ░░░                       ░░███░░░░░███                                                                      
 ░███░███ ░███   ██████   ███████   ████  █████ █████  ██████  ░███    ░███ ████████   ██████   ██████   ██████   █████   █████   ██████   █████ 
 ░███░░███░███  ░░░░░███ ░░░███░   ░░███ ░░███ ░░███  ███░░███ ░██████████ ░░███░░███ ███░░███ ███░░███ ███░░███ ███░░   ███░░   ███░░███ ███░░  
 ░███ ░░██████   ███████   ░███     ░███  ░███  ░███ ░███████  ░███░░░░░░   ░███ ░░░ ░███ ░███░███ ░░░ ░███████ ░░█████ ░░█████ ░███████ ░░█████ 
 ░███  ░░█████  ███░░███   ░███ ███ ░███  ░░███ ███  ░███░░░   ░███         ░███     ░███ ░███░███  ███░███░░░   ░░░░███ ░░░░███░███░░░   ░░░░███
 █████  ░░█████░░████████  ░░█████  █████  ░░█████   ░░██████  █████        █████    ░░██████ ░░██████ ░░██████  ██████  ██████ ░░██████  ██████ 
░░░░░    ░░░░░  ░░░░░░░░    ░░░░░  ░░░░░    ░░░░░     ░░░░░░  ░░░░░        ░░░░░      ░░░░░░   ░░░░░░   ░░░░░░  ░░░░░░  ░░░░░░   ░░░░░░  ░░░░░░  
                                                                                                                            
 *  NativeProcesses Framework
 *  High-performance Windows process monitoring and control library
 *  Copyright (C) 2025  Selahattin Erkoc
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *  --------------------------------------------------------------
 *  Summary:
 *  Internal and educational use is permitted, including modification
 *  and private distribution. Public distribution of binaries must
 *  include full corresponding source code under the same license.
 *  --------------------------------------------------------------
 */
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

            var server = new SecureTcpServer(port, cert,token,logger);
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
                /*
                 I have future Plans to restrict the flooding of PID error messages 
                 */
             // if (!message.Contains("Failed to get") && !message.Contains("Failed to open")) 
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

