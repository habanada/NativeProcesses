/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using NativeProcesses.Core;
using static NativeProcesses.Core.NativeProcessLister;

namespace NativeProcesses.Network
{
    public class SecureTcpServer
    {
        private readonly TcpListener _listener;
        private readonly X509Certificate2 _cert;
        private readonly string _authToken;
        private readonly List<SslStream> _clients = new List<SslStream>();
        private readonly object _clientLock = new object();
        private CancellationTokenSource _cts;
        private readonly IEngineLogger _logger;

        private readonly ConcurrentDictionary<SslStream, SemaphoreSlim> _writeLocks = new ConcurrentDictionary<SslStream, SemaphoreSlim>();

        public event Action<SslStream, string, string> MessageReceived;

        public SecureTcpServer(int port, X509Certificate2 certificate, string authToken, IEngineLogger logger = null)
        {
            _listener = new TcpListener(IPAddress.Any, port);
            _cert = certificate;
            _authToken = authToken;
            _cts = new CancellationTokenSource();
            _logger = logger;
        }

        public async Task StartAsync()
        {
            _listener.Start();
            while (!_cts.Token.IsCancellationRequested)
            {
                try
                {
                    TcpClient client = await _listener.AcceptTcpClientAsync();
                    _ = Task.Run(() => HandleClientAsync(client));
                }
                catch (SocketException ex) when (_cts.Token.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger?.Log(LogLevel.Error, "Error in the server accept client loop", ex);
                }
            }
        }

        public void Stop()
        {
            if (_cts.IsCancellationRequested) return;

            _cts.Cancel();
            _listener.Stop();

            List<SslStream> clientsCopy;
            lock (_clientLock)
            {
                clientsCopy = new List<SslStream>(_clients);
                _clients.Clear();
            }

            foreach (SslStream client in clientsCopy)
            {
                try
                {
                    SendMessageAsync(client, "server_shutdown", null).Wait(500);
                    _logger?.Log(LogLevel.Info, $"Server shutdown.");
                    client.Close();
                }
                catch
                {
                }
            }
        }

        private async Task HandleClientAsync(TcpClient client)
        {
            SslStream ssl = null;
            string clientIp = "Unknown";
            try
            {
                clientIp = client.Client.RemoteEndPoint?.ToString() ?? "Unknown";
                using (client)
                using (ssl = new SslStream(client.GetStream(), false))
                {
                    await ssl.AuthenticateAsServerAsync(_cert, false, System.Security.Authentication.SslProtocols.Tls12, false);

                    NetworkMessage authMsg = await ReceiveMessageAsync(ssl);
                    if (authMsg == null || authMsg.Type != "auth" || !SecureTokenEquals(authMsg.Data, _authToken))
                    {
                        await SendMessageAsync(ssl, "auth_failed", null);
                        _logger?.Log(LogLevel.Warning, $"Client {clientIp} auth failed.");
                        return;
                    }

                    _writeLocks.TryAdd(ssl, new SemaphoreSlim(1, 1));

                    await SendMessageAsync(ssl, "auth_ok", null);
                    _logger?.Log(LogLevel.Info, $"Client connected: {clientIp}");
                    lock (_clientLock)
                    {
                        if (!_cts.Token.IsCancellationRequested)
                        {
                            _clients.Add(ssl);
                        }
                        else
                        {
                            _writeLocks.TryRemove(ssl, out _);
                        }
                    }

                    while (client.Connected && !_cts.Token.IsCancellationRequested)
                    {
                        NetworkMessage msg = await ReceiveMessageAsync(ssl);
                        if (msg == null)
                        {
                            break;
                        }
                        MessageReceived?.Invoke(ssl, msg.Type, msg.Data);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(LogLevel.Warning, $"Client {clientIp} disconnected (error)", ex);
            }
            finally
            {
                if (ssl != null)
                {
                    lock (_clientLock)
                    {
                        _clients.Remove(ssl);
                    }
                    _writeLocks.TryRemove(ssl, out _);
                    _logger?.Log(LogLevel.Info, $"Client {clientIp} disconnected.");
                }
            }
        }

        private bool SecureTokenEquals(string a, string b)
        {
            if (a == null || b == null) return a == b;

            int diff = a.Length ^ b.Length;
            for (int i = 0; i < a.Length && i < b.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
        }

        public async Task SendMessageAsync(SslStream ssl, string type, object data)
        {
            if (!_writeLocks.TryGetValue(ssl, out SemaphoreSlim writeLock))
            {
                return;
            }

            await writeLock.WaitAsync();
            try
            {
                string jsonData;

                if (data is string s)
                    jsonData = s;
                else
                    jsonData = data == null ? null : JsonConvert.SerializeObject(data);


                string json = JsonConvert.SerializeObject(new NetworkMessage
                {
                    Type = type,
                    Data = jsonData
                });

                byte[] uncompressed = Encoding.UTF8.GetBytes(json);
                byte[] payload = Compress(uncompressed);
                byte[] length = BitConverter.GetBytes(payload.Length);

                await ssl.WriteAsync(length, 0, length.Length);
                await ssl.WriteAsync(payload, 0, payload.Length);
                await ssl.FlushAsync();
            }
            catch (Exception ex)
            {
                lock (_clientLock)
                {
                    _clients.Remove(ssl);
                }
                _writeLocks.TryRemove(ssl, out _);
            }
            finally
            {
                writeLock.Release();
            }
        }


        private async Task<NetworkMessage> ReceiveMessageAsync(SslStream ssl)
        {
            byte[] lenBuf = new byte[4];
            int read = await ssl.ReadAsync(lenBuf, 0, 4);
            if (read < 4) return null;

            int len = BitConverter.ToInt32(lenBuf, 0);
            if (len <= 0 || len > 10 * 1024 * 1024)
            {
                return null;
            }

            byte[] compressed = new byte[len];
            int totalRead = 0;
            while (totalRead < len)
            {
                read = await ssl.ReadAsync(compressed, totalRead, len - totalRead);
                if (read == 0) return null;
                totalRead += read;
            }

            byte[] uncompressed = Decompress(compressed);
            string json = Encoding.UTF8.GetString(uncompressed);
            return JsonConvert.DeserializeObject<NetworkMessage>(json);
        }

        public async Task BroadcastAsync(string type, object data)
        {
            if (_cts.Token.IsCancellationRequested) return;

            List<SslStream> clientsCopy;
            lock (_clientLock)
            {
                clientsCopy = new List<SslStream>(_clients);
            }

            foreach (SslStream client in clientsCopy)
            {
                await SendMessageAsync(client, type, data);
            }
        }

        private byte[] Compress(byte[] data)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (DeflateStream ds = new DeflateStream(ms, CompressionLevel.Fastest, true))
                {
                    ds.Write(data, 0, data.Length);
                }
                return ms.ToArray();
            }
        }

        private byte[] Decompress(byte[] data)
        {
            using (MemoryStream output = new MemoryStream())
            {
                using (MemoryStream input = new MemoryStream(data))
                using (DeflateStream ds = new DeflateStream(input, CompressionMode.Decompress))
                {
                    ds.CopyTo(output);
                }
                return output.ToArray();
            }
        }
    }
}