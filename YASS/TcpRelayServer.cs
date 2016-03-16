// YASS - Yet another Shadowsocks
// Copyright (C) 2016 dantmnf
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using YASS.AlgorithmProvider;

namespace YASS
{
    

    public class TcpRelayServer
    {
        public enum ServerHmacPolicy
        {
            OptIn,
            Mandatory,
            Disabled
        }

        private enum ConnectionStage
        {
            New,
            IVReceived,
            AddressTypeReceived,
            AddressReceived,
            RemoteConnected,
            Streaming,
        }

        public enum AddressType
        {
            IPv4 = 1,
            IPv6 = 4,
            Hostname = 3,
        }
        public ServerHmacPolicy HmacPolicy = ServerHmacPolicy.OptIn;
        public IAlgorithmProvider AlgorithmProvider;
        public long BytesTransferred;

        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _serverCts;
        private CancellationToken _serverCt;
        private SymmetricAlgorithm _algorithm;
        private readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();
        private readonly log4net.ILog logger;
        private readonly int _timeout;
        private readonly string _cipherName;
        private readonly byte[] _passwordBytes;
        private readonly object _xferBytesLocker = new object();
        private readonly Dictionary<TcpClient, Task> _clientTasks = new Dictionary<TcpClient, Task>();
/*
        private bool _stopping = false;
*/

        public class ServerEventArgs : EventArgs
        {
            public IPEndPoint ClientEndPoint { get; internal set; }
            public bool IsHmacClient { get; internal set; }
            public AddressType RemoteAddressType { get; internal set; }

            /// <summary>
            /// Only when RemoteAddressType is AddressType.IPv4 or AddressType.IPv6
            /// </summary>
            public IPAddress RemoteAddress { get; internal set; }

            /// <summary>
            /// Only when RemoteAddressType is AddressType.Hostname
            /// </summary>
            public string RemoteHostname { get; internal set; }

            public int RemotePort { get; internal set; }

            /// <summary>
            /// Indicates whether server should drop the client
            /// </summary>
            public bool DropClient = false;
        }

        public event EventHandler ClientConnected;
        protected virtual void OnClientConnected(EventArgs e)
        {
            if (ClientConnected != null)
                ClientConnected(this, e);
        }

        public event EventHandler RemoteAddressReceived;
        protected virtual void OnRemoteAddressReceived(EventArgs e)
        {
            if (RemoteAddressReceived != null)
                RemoteAddressReceived(this, e);
        }

        public event EventHandler ClientDisconnected;
        protected virtual void OnClientDisconnected(EventArgs e)
        {
            if (ClientDisconnected != null)
                ClientDisconnected(this, e);
        }

        public event EventHandler ClientFailed;
        protected virtual void OnClientFailed(EventArgs e)
        {
            if (ClientFailed != null)
                ClientFailed(this, e);
        }


        public TcpRelayServer(IPAddress localAddress, int port, string cipherName, byte[] passwordBytes, int timeout)
        {
            logger = log4net.LogManager.GetLogger($"{GetType().Name}@{localAddress}:{port}");
            _serverCts = new CancellationTokenSource();
            _listener = new TcpListener(localAddress, port);
            _serverCt = _serverCts.Token;
            _timeout = timeout * 1000;
            _cipherName = cipherName;
            _passwordBytes = passwordBytes;
        }

        public async Task StartListeningAsync()
        {
            try
            {

                _algorithm = AlgorithmProvider.GetAlgorithm(_cipherName);
                _algorithm.Key = Util.GetKeyFromBytes(_passwordBytes, _algorithm.KeySize / 8);
                logger.InfoFormat("cipher {0} initialized", _cipherName);
                _listener.Start();
                logger.Info("start listening");
                await AcceptClientsAsync();
            }
            catch
            {
                StopListening();
                throw;
            }
        }

        public void StopListening()
        {
            try
            {
                _listener.Stop();
            }
            catch (ObjectDisposedException) { }
            catch (AggregateException) { }
        }

        public async Task WaitForAllClients()
        {
            Task[] tasks;
            lock (_clientTasks) tasks = _clientTasks.Values.ToArray();
            logger.Info("waiting for clients");
            await Task.WhenAll(tasks);
        }

        public void KillAllClients()
        {
            _serverCts.Cancel();
        }

        private async Task AcceptClientsAsync()
        {
            var clientCounter = 0;
            try
            {
                while (!_serverCt.IsCancellationRequested)
                {
                    var client = await _listener.AcceptTcpClientAsync().ConfigureAwait(false);
                    client.ReceiveTimeout = client.SendTimeout = _timeout;
                    client.NoDelay = true;
                    clientCounter++;
                    var task = HandleClientAsync(client, clientCounter);
                    lock (_clientTasks) _clientTasks.Add(client, task);
                }
            }
            catch (ObjectDisposedException) { /* caused by _listener.Stop() */ }

        }
        private async Task HandleClientAsync(TcpClient client, int clientIndex)
        {
            var clientEndPoint = (IPEndPoint)client.Client.RemoteEndPoint;
            var ev = new ServerEventArgs() { ClientEndPoint = clientEndPoint };
            logger.DebugFormat("client{0}<{1}:{2}> connected", clientIndex, clientEndPoint.Address, clientEndPoint.Port);

            var stage = ConnectionStage.New;
            using (var stream = client.GetStream())
            {
                try
                {
                    OnClientConnected(ev);
                    if (ev.DropClient) throw new SystemException("an OnClientConnected event handler requires dropping client");

                    var bytesRead = 0;
                    var bytesParsed = 0;
                    var ivlen = _algorithm.IV.Length;
                    var iv = new byte[ivlen];
                    var clientBuffer = new byte[ivlen + 280]; // IV + AddressType(1) + Address(<=256) + Port(2) + HMAC(10)
                    var invalidClientStage = stage;
                    Exception invalidClientException = null;

                    try { bytesRead += await PromisedReadAsync(stream, clientBuffer, bytesRead, ivlen - bytesRead, _serverCt).ConfigureAwait(false); }
                    catch(IOException) { throw new InvalidDataException("Can't read entire IV."); }
                    Buffer.BlockCopy(clientBuffer, 0, iv, 0, ivlen);
                    bytesParsed += ivlen;

                    var iv2 = new byte[ivlen];
                    _rng.GetBytes(iv2);
                    stage = ConnectionStage.IVReceived;

                    using (var decryptor = _algorithm.CreateDecryptor(_algorithm.Key, iv)) // we don't use CryptoStream because it won't return until it get full-length data
                    using (var encryptor = _algorithm.CreateEncryptor(_algorithm.Key, iv2))
                    {
                        bytesRead += await PromisedReadAsync(stream, clientBuffer, bytesRead, 1, _serverCt).ConfigureAwait(false);
                        decryptor.TransformBlock(clientBuffer, bytesParsed, 1, clientBuffer, bytesParsed);
                        var atyp = clientBuffer[bytesParsed];
                        bytesParsed++;
                        if ((atyp & 0xE0) != 0) // 0b11100000
                            invalidClientException = new ProtocolViolationException("Invalid ATYP value.");
                        var hmacClient = (atyp & 0x10) == 0x10; // 0b00010000
                        var clientAddressType = (AddressType)(atyp & 0x0F);

                        stage = ConnectionStage.AddressTypeReceived;
                        if (hmacClient && HmacPolicy == ServerHmacPolicy.Disabled && invalidClientException == null)
                            invalidClientException = new ProtocolViolationException("Received an HMAC-enabled request but HMAC is disabled.");
                        if (!hmacClient && HmacPolicy == ServerHmacPolicy.Mandatory && invalidClientException == null)
                            invalidClientException = new ProtocolViolationException("Received a non-HMAC-enabled request but HMAC is mandatory.");

                        int addressLength;
                        switch (clientAddressType)
                        {
                            case AddressType.IPv4:
                                addressLength = 4;
                                break;
                            case AddressType.IPv6:
                                addressLength = 16;
                                break;
                            case AddressType.Hostname:
                                await PromisedReadAsync(stream, clientBuffer, bytesRead, 1, _serverCt).ConfigureAwait(false);
                                bytesRead++;
                                decryptor.TransformBlock(clientBuffer, bytesParsed, 1, clientBuffer, bytesParsed);
                                addressLength = clientBuffer[bytesParsed];
                                bytesParsed++;
                                break;
                            default:
                                if (invalidClientException == null)
                                    invalidClientException = new ProtocolViolationException("Invalid address type");
                                var fakeAddressLength = new byte[1];
                                _rng.GetNonZeroBytes(fakeAddressLength);
                                addressLength = fakeAddressLength[0];
                                break;
                        }

                        if (invalidClientException != null)
                            invalidClientStage = stage;
                        
                        bytesRead += await PromisedReadAsync(stream, clientBuffer, bytesRead, addressLength + 2, _serverCt).ConfigureAwait(false);
                        decryptor.TransformBlock(clientBuffer, bytesParsed, addressLength + 2, clientBuffer, bytesParsed);

                        var remoteAddress = new ArraySegment<byte>(clientBuffer, bytesParsed, addressLength);
                        var port = Util.UInt16FromNetworkOrder(clientBuffer, bytesParsed + addressLength);
                        bytesParsed += addressLength + 2;

                        stage = ConnectionStage.AddressReceived;
                        
                        if (hmacClient)
                        {
                            var headerHmacKey = new byte[_algorithm.KeySize / 8 + ivlen];
                            iv.CopyTo(headerHmacKey, 0);
                            _algorithm.Key.CopyTo(headerHmacKey, ivlen);

                            var localHash = Util.ComputeHMACSHA1Hash(headerHmacKey, clientBuffer, ivlen, bytesParsed-ivlen);

                            bytesRead += await PromisedReadAsync(stream, clientBuffer, bytesRead, 10, _serverCt).ConfigureAwait(false);
                            decryptor.TransformBlock(clientBuffer, bytesParsed, 10, clientBuffer, bytesParsed);

                            var clientHash = new ArraySegment<byte>(clientBuffer, bytesParsed, 10);
                            bytesParsed += 10;

                            if (!localHash.Take(10).SequenceEqual(clientHash) && invalidClientException == null)
                            {
                                invalidClientException = new InvalidDataException("HMAC mismatch.");
                                invalidClientStage = stage;
                            }
                        }

                        if (invalidClientException != null)
                        {
                            stage = invalidClientStage;
                            throw invalidClientException;
                        }

                        ev.IsHmacClient = hmacClient;
                        ev.RemoteAddressType = clientAddressType;
                        if (clientAddressType == AddressType.Hostname)
                            ev.RemoteHostname = Encoding.UTF8.GetString(remoteAddress.ToArray());
                        else
                            ev.RemoteAddress = new IPAddress(remoteAddress.Take(addressLength).ToArray());
                        ev.RemotePort = port;
                        OnRemoteAddressReceived(ev);
                        if (ev.DropClient) throw new SystemException("an OnRemoteAddressReceived event handler requires dropping client");


                        using (var remote = new TcpClient())
                        {
                            var address = clientAddressType == AddressType.Hostname
                                ? (await Dns.GetHostAddressesAsync(ev.RemoteHostname).ConfigureAwait(false))[0]
                                : ev.RemoteAddress;
                            var logAddress = clientAddressType == AddressType.Hostname
                                ? Encoding.UTF8.GetString(remoteAddress.ToArray())
                                : address.ToString();
                            logger.InfoFormat("client{0}<{1}:{2}> connecting to {3}:{4}", clientIndex, clientEndPoint.Address, clientEndPoint.Port, logAddress, port);

                            remote.ReceiveTimeout = remote.SendTimeout = _timeout;
                            remote.Client.NoDelay = true;
                            await remote.ConnectAsync(address, port).ConfigureAwait(false);

                            stage = ConnectionStage.RemoteConnected;

                            await stream.WriteAsync(iv2, 0, ivlen, _serverCt).ConfigureAwait(false);

                            using (var remoteStream = remote.GetStream())
                            using (var clientCts = new CancellationTokenSource())
                            using (var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(_serverCt, clientCts.Token))
                            {

                                var ct = linkedCts.Token;
                                var clientTask = hmacClient
                                    ? StartHmacEnabledClientRelayAsync(stream, remoteStream, iv, decryptor, ct)
                                    : StartRelayAsync(stream, remoteStream, decryptor, ct);

                                var remoteTask = StartRelayAsync(remoteStream, stream, encryptor, ct);
                                stage = ConnectionStage.Streaming;

                                await Task.WhenAny(clientTask, remoteTask);
                                clientCts.Cancel();
                                client.Close();
                                remote.Close();
                                //await Task.WhenAll(clientTask, remoteTask); 
                            }
                            OnClientDisconnected(ev);
                        }
                    }

                }
                catch (Exception e)
                {
                    logger.ErrorFormat("client{0}<{1}:{2}> failed in stage {3}: {4} - {5}", clientIndex, clientEndPoint.Address, clientEndPoint.Port, stage, e.GetType().Name, e.Message);
                    OnClientFailed(ev);
                    // reset the connection
                    client.Client.LingerState = new LingerOption(true, 0);
                    client.Client.Dispose();
                }
            }
            lock(_clientTasks) _clientTasks.Remove(client);
            logger.DebugFormat("client{0}<{1}:{2}> disconnected", clientIndex, clientEndPoint.Address, clientEndPoint.Port);
        }

        private async Task StartRelayAsync(Stream srcStream, Stream dstStream, ICryptoTransform transformer, /* useless */ CancellationToken ct)
        {
            var buffer = new byte[8192];
            try
            {
                while (!ct.IsCancellationRequested && srcStream.CanRead && dstStream.CanWrite)
                {
                    var len = await srcStream.ReadAsync(buffer, 0, buffer.Length, ct).ConfigureAwait(false);
                    if (len == 0) throw new SocketException();
                    transformer.TransformBlock(buffer, 0, len, buffer, 0);
                    await dstStream.WriteAsync(buffer, 0, len, ct).ConfigureAwait(false);
                    lock (_xferBytesLocker) BytesTransferred += len;
                }
            }
            catch (ObjectDisposedException) { }
            catch (AggregateException) { }
            catch (SocketException) { }

        }



        private async Task StartHmacEnabledClientRelayAsync(Stream clientStream, Stream remoteStream, byte[] iv, ICryptoTransform decryptor, /* useless */ CancellationToken ct)
        {
            var clientBuffer = new byte[65535];
            var clientHash = new byte[10];
            var ivlen = iv.Length;
            int readlen;
            int datalen;
            uint chunkId = 0;
            var hmacKey = new byte[iv.Length + 4];
            iv.CopyTo(hmacKey, 0);
            try
            {
                while (!ct.IsCancellationRequested && clientStream.CanRead && remoteStream.CanWrite)
                {
                    // data length
                    readlen = await PromisedReadAsync(clientStream, clientBuffer, 0, 2, ct).ConfigureAwait(false);
                    decryptor.TransformBlock(clientBuffer, 0, readlen, clientBuffer, 0);
                    datalen = Util.UInt16FromNetworkOrder(clientBuffer, 0);

                    // client hash
                    readlen = await PromisedReadAsync(clientStream, clientHash, 0, 10, ct).ConfigureAwait(false);
                    decryptor.TransformBlock(clientHash, 0, readlen, clientHash, 0);

                    // data
                    readlen = await PromisedReadAsync(clientStream, clientBuffer, 0, datalen, ct).ConfigureAwait(false);
                    lock (_xferBytesLocker) BytesTransferred += datalen + 12;
                    decryptor.TransformBlock(clientBuffer, 0, readlen, clientBuffer, 0);
                    BitConverter.GetBytes((uint)IPAddress.HostToNetworkOrder((int)chunkId)).CopyTo(hmacKey, ivlen);
                    if (!Util.ComputeHMACSHA1Hash(hmacKey, clientBuffer, 0, datalen).Take(10).SequenceEqual(clientHash))
                        throw new InvalidDataException("HMAC mismatch.");

                    chunkId++;
                    await remoteStream.WriteAsync(clientBuffer, 0, datalen, ct).ConfigureAwait(false);
                }
            }
            catch (ObjectDisposedException) { }
            catch (AggregateException) { }
            catch (SocketException) { }
            catch (IOException) { }
        }

        private static async Task<int> PromisedReadAsync(Stream stream, byte[] buf, int offset, int count, CancellationToken ct)
        {
            var totallen = 0;
            var readlen = 0;
            while (totallen < count)
            {
                readlen = await stream.ReadAsync(buf, offset + readlen, count - readlen, ct);
                if(readlen == 0)
                    throw new IOException("stream closed");
                totallen += readlen;
            }
            return totallen;
        }

    }
}
