using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using YASS.AlgorithmProvider;

namespace YASS
{
    public class UdpRelayServer
    {
        public IAlgorithmProvider AlgorithmProvider { get; set; }
        private IPEndPoint _localEndPoint;
        private ConcurrentLRUCache<IPEndPoint, UdpClient> _portMap;
        private string _cipherName;
        private readonly log4net.ILog logger;
        private byte[] _passwordBytes;
        private SymmetricAlgorithm _algorithm;
        private int _ivlen;
        private byte[] _key;
        private bool _disposed;
        private UdpClient _listener;

        public UdpRelayServer(IPAddress localAddress, int port, string cipherName, byte[] passwordBytes, int lruCapacity = 200)
        {
            _localEndPoint = new IPEndPoint(localAddress, port);
            _cipherName = cipherName;
            _passwordBytes = passwordBytes;
            logger = log4net.LogManager.GetLogger($"{GetType().Name}@{localAddress}:{port}");
            _algorithm = AlgorithmProvider.GetAlgorithm(_cipherName);
            _key = Util.GetKeyFromBytes(_passwordBytes, _algorithm.KeySize / 8);
            //_algorithm.Key = _key;
            _ivlen = _algorithm.BlockSize / 8;
            logger.InfoFormat("cipher {0} initialized", _cipherName);
            _portMap = new ConcurrentLRUCache<IPEndPoint, UdpClient>(lruCapacity);
        }

        public async Task StartServerAsync()
        {

            _listener = new UdpClient(_localEndPoint);
            while (!_disposed)
            {
                try
                {
                    var result = await _listener.ReceiveAsync();
                    HandlePacketAsync(result).ConfigureAwait(false);
                }
                catch (ObjectDisposedException) { }
                catch (InvalidDataException) { }
                catch (ProtocolViolationException) { }
            }

        }

        public void StopServer()
        {
            _disposed = true;
            _listener?.Close();
        }

        private async Task HandlePacketAsync(UdpReceiveResult packet)
        {

            var buf = packet.Buffer;
            var len = buf.Length;
            var bytesParsed = 0;
            var iv = packet.Buffer.Take(_ivlen).ToArray();
            bytesParsed += _ivlen;
            var decryptor = _algorithm.CreateDecryptor(_key, iv);
            decryptor.TransformBlock(buf, bytesParsed, len - bytesParsed, buf, bytesParsed);

            /*
              +----+------   +------+----------+----------+----------+
              |RSV | FRAG    | ATYP | DST.ADDR | DST.PORT |   DATA   |
              +----+------   +------+----------+----------+----------+
              | 2  |  1      |  1   | Variable |    2     | Variable |
              +----+------   +------+----------+----------+----------+
              ^^-REMOVED-^
            */
            var atyp = buf[bytesParsed];
            bytesParsed++;
            var hmacClient = (atyp & 0x10) == 0x10;
            var addressType = (AddressType)(atyp & 0x0F);
            int addressLength;
            switch (addressType)
            {
                case AddressType.IPv4:
                    addressLength = 4;
                    break;
                case AddressType.IPv6:
                    addressLength = 16;
                    break;
                case AddressType.Hostname:
                    addressLength = buf[bytesParsed];
                    bytesParsed++;
                    break;
                default:
                    throw new ProtocolViolationException("invalid address type");
            }
            //var address = buf.Skip(bytesParsed).Take(addressLength).ToArray();
            var addressBytes = new ArraySegment<byte>(buf, bytesParsed, addressLength).ToArray();
            bytesParsed += addressLength;
            var port = Util.UInt16FromNetworkOrder(buf, bytesParsed);
            bytesParsed += 2;
            var datalen = len - bytesParsed;
            if (hmacClient)
            {
                datalen -= 10;
                var clientHash = buf.Skip(len - 10).Take(10);
                var hmacKey = iv.Concat(_key).ToArray();
                var localHash = Util.ComputeHMACSHA1Hash(hmacKey, buf, 0, len - 10);
                if (!clientHash.SequenceEqual(localHash))
                {
                    throw new InvalidDataException("HMAC mismatch");
                }
            }
            var address = addressType == AddressType.Hostname
                                ? (await Dns.GetHostAddressesAsync(Encoding.UTF8.GetString(addressBytes)).ConfigureAwait(false))[0]
                                : new IPAddress(addressBytes);
            var endpoint = new IPEndPoint(address, port);
            UdpClient socket;
            if ((socket = _portMap.GetValue(packet.RemoteEndPoint)) == null)
            {
                socket = new UdpClient(endpoint);
                _portMap.Add(packet.RemoteEndPoint, socket);
                StartReverseRelayAsync(socket, packet.RemoteEndPoint, hmacClient).ConfigureAwait(false);
            }
            var data = new ArraySegment<byte>(buf, bytesParsed, datalen);
            socket.SendAsync(data.ToArray(), datalen, endpoint).ConfigureAwait(false);
        }

        private async Task StartReverseRelayAsync(UdpClient socket, IPEndPoint origin, bool hmacEnabled)
        {
            try
            {
                var rng = RandomNumberGenerator.Create();
                byte atyp;
                int addressLength;
                switch (origin.AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                        atyp = (byte)AddressType.IPv4;
                        addressLength = 4;
                        break;
                    case AddressFamily.InterNetworkV6:
                        atyp = (byte)AddressType.IPv6;
                        addressLength = 16;
                        break;
                    default:
                        return;
                }
                if (hmacEnabled) atyp |= 0x10;

                var header = new byte[addressLength + 3];
                header[0] = atyp;
                origin.Address.GetAddressBytes().CopyTo(header, 1);
                header[addressLength + 1] = (byte)((origin.Port & 0xFF00) >> 8);
                header[addressLength + 2] = (byte)(origin.Port & 0xFF);
                while (!_disposed)
                {
                    var packet = await socket.ReceiveAsync();
                    var iv = new byte[_ivlen];
                    rng.GetBytes(iv);
                    var encryptor = _algorithm.CreateEncryptor(_key, iv);
                    var data = new byte[_ivlen + header.Length + packet.Buffer.Length + (hmacEnabled ? 10 : 0)];
                    var bytesFilled = 0;
                    iv.CopyTo(data, bytesFilled);
                    bytesFilled += _ivlen;
                    header.CopyTo(data, bytesFilled);
                    bytesFilled += header.Length;
                    packet.Buffer.CopyTo(data, bytesFilled);
                    bytesFilled += packet.Buffer.Length;
                    if (hmacEnabled)
                    {
                        var hmackey = iv.Concat(_key).ToArray();
                        var hash = Util.ComputeHMACSHA1Hash(hmackey, data, _ivlen, bytesFilled - _ivlen);
                        hash.CopyTo(data, bytesFilled);
                    }
                    encryptor.TransformBlock(data, _ivlen, bytesFilled - _ivlen, data, _ivlen);
                    _listener.SendAsync(data, data.Length, origin).ConfigureAwait(false);
                }
            }
            catch (ObjectDisposedException) { }
        }
    }
}
