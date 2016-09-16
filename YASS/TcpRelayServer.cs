﻿// YASS - Yet another Shadowsocks
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
#define YASS_ENABLE_EXTENSIONS

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
using YASS.Extensions;


namespace YASS
{
    public enum AddressType
    {
        IPv4 = 1,
        IPv6 = 4,
        Hostname = 3,
    }

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

        [Flags]
        private enum AtypFlags
        {
            HMACEnabled = 0x10,
#if (YASS_ENABLE_EXTENSIONS)
            TimestampEnabled = 0x20,
#endif
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
            using (var netStream = client.GetStream())
            using (var shadowStream = new ShadowStream(netStream, _algorithm, ShadowStreamMode.Read))
            {
                try
                {
                    OnClientConnected(ev);
                    if (ev.DropClient) throw new SystemException("an OnClientConnected event handler requires dropping client");

                    var bytesRead = 0;
                    var bytesParsed = 0;

                    var clientBuffer = new byte[280]; // AddressType(1) + Address(<=256) + Port(2) + HMAC(10)
                    var invalidClientStage = stage;
                    Exception invalidClientException = null;




                    bytesRead += await shadowStream.PromisedReadAsync(clientBuffer, bytesRead, 1, _serverCt).ConfigureAwait(false);
                    stage = ConnectionStage.IVReceived;
                    var atyp = clientBuffer[bytesParsed];
                    bytesParsed++;

#if (YASS_ENABLE_EXTENSIONS)
                    const byte atypMask = 0xC0; // 0b11000000
#else
                        const byte atypMask = 0xE0; // 0b11100000
#endif
                    if ((atyp & atypMask) != 0)
                        invalidClientException = new ProtocolViolationException("Invalid ATYP value.");

                    var flaggedAtyp = (AtypFlags)atyp;
                    var hmacClient = flaggedAtyp.HasFlag(AtypFlags.HMACEnabled);
#if (YASS_ENABLE_EXTENSIONS)
                    var timestampEnabled = flaggedAtyp.HasFlag(AtypFlags.TimestampEnabled);
#endif
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
                            await shadowStream.PromisedReadAsync(clientBuffer, bytesRead, 1, _serverCt).ConfigureAwait(false);
                            bytesRead++;
                            addressLength = clientBuffer[bytesParsed];
                            bytesParsed++;
                            break;
                        default:
                            if (invalidClientException == null)
                                invalidClientException = new ProtocolViolationException("Invalid address type.");
                            var fakeAddressLength = new byte[1];
                            _rng.GetNonZeroBytes(fakeAddressLength);
                            addressLength = fakeAddressLength[0];
                            break;
                    }

                    if (invalidClientException != null)
                        invalidClientStage = stage;

                    bytesRead += await shadowStream.PromisedReadAsync(clientBuffer, bytesRead, addressLength + 2, _serverCt).ConfigureAwait(false);

                    var remoteAddress = new ArraySegment<byte>(clientBuffer, bytesParsed, addressLength);
                    var port = Util.UInt16FromNetworkOrder(clientBuffer, bytesParsed + addressLength);
                    bytesParsed += addressLength + 2;

                    stage = ConnectionStage.AddressReceived;

                    if (hmacClient)
                    {
                        var iv = shadowStream.IV;
                        var ivlen = iv.Length;
                        var headerHmacKey = new byte[_algorithm.KeySize / 8 + ivlen];
                        iv.CopyTo(headerHmacKey, 0);
                        _algorithm.Key.CopyTo(headerHmacKey, ivlen);

                        var localHash = Util.ComputeHMACSHA1Hash(headerHmacKey, clientBuffer, 0, bytesParsed);

                        bytesRead += await shadowStream.PromisedReadAsync(clientBuffer, bytesRead, 10, _serverCt).ConfigureAwait(false);

                        var clientHash = new ArraySegment<byte>(clientBuffer, bytesParsed, 10);
                        bytesParsed += 10;

                        if (!localHash.Take(10).SequenceEqual(clientHash) && invalidClientException == null)
                        {
                            invalidClientException = new InvalidDataException("HMAC mismatch.");
                            invalidClientStage = stage;
                        }
                    }

#if (YASS_ENABLE_EXTENSIONS)
                    if (timestampEnabled)
                    {
                        bytesRead += await shadowStream.PromisedReadAsync(clientBuffer, bytesRead, 8, _serverCt).ConfigureAwait(false);
                        var timestamp = new ArraySegment<byte>(clientBuffer, bytesParsed, 8);
                        bytesParsed += 8;
                        var clientTime = Util.UInt64FromNetworkOrder(timestamp.ToArray(), 0);
                        var localTime = Util.GetUtcTimeEpoch();
                        if (Math.Abs((double)(clientTime - localTime)) > 120)
                        {
                            invalidClientException = new InvalidDataException("Timestamp error.");
                            invalidClientStage = stage;
                        }
                    }
#endif

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
                    if (ev.DropClient) throw new SystemException("An OnRemoteAddressReceived event handler requires dropping client.");


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

                        using (var remoteStream = remote.GetStream())
                        using (var clientCts = new CancellationTokenSource())
                        using (var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(_serverCt, clientCts.Token))
                        using (var writeStream = new ShadowStream(netStream, _algorithm, ShadowStreamMode.Write))
                        {
                            var ct = linkedCts.Token;
                            var readStream = hmacClient
                                ? (Stream)new HmacChunkedStream(shadowStream, shadowStream.IV, ShadowStreamMode.Read)
                                : shadowStream;
                            
                            var clientToRemoteTask = readStream.CopyToAsync(remoteStream, 4096, ct);
                            var remoteToClientTask = remoteStream.CopyToAsync(writeStream, 4096, ct);
                            stage = ConnectionStage.Streaming;

                            await Task.WhenAny(clientToRemoteTask, remoteToClientTask);
                            clientCts.Cancel();
                            client.Close();
                            remote.Close();
                            //await Task.WhenAll(clientTask, remoteTask); 
                        }
                        OnClientDisconnected(ev);
                    }


                }
                catch (Exception e)
                {
                    logger.ErrorFormat("Client{0}<{1}:{2}> failed in stage {3}: {4} - {5}", clientIndex, clientEndPoint.Address, clientEndPoint.Port, stage, e.GetType().Name, e.Message);
                    OnClientFailed(ev);
                    // reset the connection
                    client.Client.LingerState = new LingerOption(true, 0);
                    client.Client.Dispose();
                }
            }
            lock (_clientTasks) _clientTasks.Remove(client);
            logger.DebugFormat("Client{0}<{1}:{2}> disconnected", clientIndex, clientEndPoint.Address, clientEndPoint.Port);
        }


    }
}
