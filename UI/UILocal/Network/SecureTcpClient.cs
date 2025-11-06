using Newtonsoft.Json;
using System;
using System.IO;
using System.IO.Compression;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace NativeProcesses.Network
{
    public class SecureTcpClient
    {
        private readonly string _host;
        private readonly int _port;
        private readonly string _token;
        private TcpClient _client;
        private SslStream _ssl;

        public event Action<string, string> MessageReceived;
        public event Action Disconnected;
        public bool IsConnected { get { return _client != null && _client.Connected; } }

        public SecureTcpClient(string host, int port, string token)
        {
            _host = host;
            _port = port;
            _token = token;
        }

        public async Task<bool> ConnectAsync()
        {
            try
            {
                _client = new TcpClient();
                await _client.ConnectAsync(_host, _port);

                _ssl = new SslStream(_client.GetStream(), false, (s, c, ch, e) => true);
                await _ssl.AuthenticateAsClientAsync(_host);

                await SendMessageAsync("auth", _token);

                NetworkMessage authResponse = await ReceiveMessageAsync();
                if (authResponse != null && authResponse.Type == "auth_ok")
                {
                    _ = Task.Run(ReceiveLoop);
                    return true;
                }
                else
                {
                    Disconnect();
                    return false;
                }
            }
            catch
            {
                Disconnect();
                return false;
            }
        }

        public void Disconnect()
        {
            try
            {
                _ssl?.Close();
                _client?.Close();
            }
            catch { }
            finally
            {
                _ssl = null;
                _client = null;
            }
        }

        public async Task SendMessageAsync(string type, object data)
        {
            if (!IsConnected) return;

            string jsonData = data == null ? null : JsonConvert.SerializeObject(data);
            string json = JsonConvert.SerializeObject(new NetworkMessage { Type = type, Data = jsonData });

            byte[] uncompressed = Encoding.UTF8.GetBytes(json);
            byte[] payload = Compress(uncompressed);
            byte[] length = BitConverter.GetBytes(payload.Length);

            await _ssl.WriteAsync(length, 0, length.Length);
            await _ssl.WriteAsync(payload, 0, payload.Length);
            await _ssl.FlushAsync();
        }

        private async Task ReceiveLoop()
        {
            try
            {
                while (IsConnected)
                {
                    NetworkMessage msg = await ReceiveMessageAsync();
                    if (msg == null)
                    {
                        break;
                    }

                    if (msg.Type == "server_shutdown")
                    {
                        break;
                    }

                    MessageReceived?.Invoke(msg.Type, msg.Data);
                }
            }
            catch
            {
            }
            finally
            {
                Disconnect();
                Disconnected?.Invoke();
            }
        }

        private async Task<NetworkMessage> ReceiveMessageAsync()
        {
            byte[] lenBuf = new byte[4];
            int read = await _ssl.ReadAsync(lenBuf, 0, 4);
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
                read = await _ssl.ReadAsync(compressed, totalRead, len - totalRead);
                if (read == 0) return null;
                totalRead += read;
            }

            byte[] uncompressed = Decompress(compressed);
            string json = Encoding.UTF8.GetString(uncompressed);
            return JsonConvert.DeserializeObject<NetworkMessage>(json);
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