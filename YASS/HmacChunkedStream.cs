using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using YASS.Extensions;

namespace YASS
{

    class HmacChunkedStream : Stream, IDisposable
    {
        private readonly Stream _stream;
        private readonly ShadowStreamMode _mode;
        private readonly bool _canRead;
        private readonly bool _canWrite;
        private byte[] _iv;
        private int _ivlen;
        private bool _initialized;
        private SemaphoreSlim _lazyAsyncActiveSemaphore;
        private int _chunkID;
        private byte[] _lastChunk;
        private int _lastChunkOffset;

        public HmacChunkedStream(Stream underlyingStream, byte[] iv, ShadowStreamMode mode)
        {
            _stream = underlyingStream;
            _iv = iv;
            _ivlen = iv.Length;
            //_transformer = transform;
            _mode = mode;
            _chunkID = 0;
            switch (mode)
            {
                case ShadowStreamMode.Read:
                    if (!(_stream.CanRead)) throw new ArgumentException("stream not readable");
                    _canRead = true;
                    break;
                case ShadowStreamMode.Write:
                    if (!(_stream.CanWrite)) throw new ArgumentException("stream not writable");
                    _canWrite = true;
                    
                    break;
                default:
                    throw new ArgumentException("invalid mdoe value");
            }
            _initialized = false;

        }
        public override bool CanRead
        {
            [Pure]
            get { return _canRead; }
        }
        public override bool CanSeek
        {
            [Pure]
            get { return false; }
        }

        public override bool CanWrite
        {
            [Pure]
            get { return _canWrite; }
        }
        public override long Length
        {
            get { throw new NotSupportedException("stream unseekable"); }
        }

        public override long Position
        {
            get { throw new NotSupportedException("stream unseekable"); }
            set { throw new NotSupportedException("stream unseekable"); }
        }

        public override void Flush()
        {
            _stream.Flush();
        }

        public override async Task FlushAsync(CancellationToken cancellationToken)
        {
            await _stream.FlushAsync(cancellationToken);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException("stream unseekable");
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException("stream unseekable");
        }

        #region read
        public override int Read(byte[] buffer, int offset, int count)
        {
            CheckReadArguments(buffer, offset, count);
            return
                ReadAsyncCore(buffer, offset, count, default(CancellationToken), false).ConfigureAwait(false).GetAwaiter().GetResult();
        }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            CheckReadArguments(buffer, offset, count);
            return ReadAsyncInternal(buffer, offset, count, cancellationToken);
        }

        private async Task<int> ReadAsyncInternal(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            // To avoid a race with a stream's position pointer & generating race 
            // conditions with internal buffer indexes in our own streams that 
            // don't natively support async IO operations when there are multiple 
            // async requests outstanding, we will block the application's main
            // thread if it does a second IO request until the first one completes.

            SemaphoreSlim semaphore = AsyncActiveSemaphore;
            await semaphore.WaitAsync(cancellationToken);
            if (cancellationToken.IsCancellationRequested) return 0;
            try
            {
                return await ReadAsyncCore(buffer, offset, count, cancellationToken, true);
            }
            finally
            {
                semaphore.Release();
            }
        }

        private async Task<byte[]> ReadChunkAsync(CancellationToken cancellationToken)
        {
            var buffer1 = new byte[10];
            await _stream.PromisedReadAsync(buffer1, 0, 2, cancellationToken);
            var datalen = (int)Util.UInt16FromNetworkOrder(buffer1, 0);
            await _stream.PromisedReadAsync(buffer1, 0, 10, cancellationToken);
            var chunkData = new byte[datalen];
            await _stream.PromisedReadAsync(chunkData, 0, datalen, cancellationToken);

            var key = new byte[_ivlen + 4];
            _iv.CopyTo(key, 0);
            Util.Int32ToNetworkOrder(_chunkID).CopyTo(key, _ivlen);

            var remoteHash = buffer1;
            var localHash = Util.ComputeHMACSHA1Hash(key, chunkData, 0, datalen);
            _chunkID += 1;
            if (localHash.Take(10).SequenceEqual(remoteHash))
                return chunkData;
            else
                throw new InvalidDataException("HMAC mismatch");
        }

        private async Task<int> ReadAsyncCore(byte[] buffer, int offset, int count, CancellationToken cancellationToken, bool useAsync)
        {
            var bytesRead = 0;
            while (count > 0)
            {
                if (_lastChunk == null || _lastChunkOffset == _lastChunk.Length) // last chunk run out
                {
                    var task = ReadChunkAsync(cancellationToken);
                    _lastChunk = useAsync ? (await task) : task.Result;
                    _lastChunkOffset = 0;
                }
                var bytesLastChunkcanProvide = _lastChunk.Length - _lastChunkOffset;
                var bytesToCopy = Math.Min(count, bytesLastChunkcanProvide);
                Buffer.BlockCopy(_lastChunk, _lastChunkOffset, buffer, offset, bytesToCopy);
                offset += bytesToCopy;
                count -= bytesToCopy;
                bytesRead += bytesToCopy;
            }
            return bytesRead;
        }
        private void CheckReadArguments(byte[] buffer, int offset, int count)
        {
            if (!CanRead)
                throw new NotSupportedException("SR.NotSupported_UnreadableStream");
            if (offset < 0)
                throw new ArgumentOutOfRangeException(nameof(offset), "SR.ArgumentOutOfRange_NeedNonNegNum");
            if (count < 0)
                throw new ArgumentOutOfRangeException(nameof(count), "SR.ArgumentOutOfRange_NeedNonNegNum");
            if (buffer.Length - offset < count)
                throw new ArgumentException("SR.Argument_InvalidOffLen");
        }
        #endregion

        #region write
        private void CheckWriteArguments(byte[] buffer, int offset, int count)
        {
            if (!CanWrite)
                throw new NotSupportedException("SR.NotSupported_UnwritableStream");
            if (offset < 0)
                throw new ArgumentOutOfRangeException(nameof(offset), "SR.ArgumentOutOfRange_NeedNonNegNum");
            if (count < 0)
                throw new ArgumentOutOfRangeException(nameof(count), "SR.ArgumentOutOfRange_NeedNonNegNum");
            if (buffer.Length - offset < count)
                throw new ArgumentException("SR.Argument_InvalidOffLen");
        }



        private async Task WriteAsyncCore(byte[] buffer, int offset, int count, CancellationToken cancellationToken,
            bool useAsync)
        {
            while (count > 65535)
            {
                var task = WriteAsyncCore(buffer, offset, 65535, cancellationToken, useAsync);
                if (useAsync)
                    await task;
                else
                    task.Wait();
                offset += 65535;
                count -= 65535;
            }
            if (count == 0) return;
            var realBuffer = new byte[count+12];

            var key = new byte[_ivlen + 4];
            _iv.CopyTo(key, 0);
            Util.Int32ToNetworkOrder(_chunkID).CopyTo(key, _ivlen);
            var hash = Util.ComputeHMACSHA1Hash(key, buffer, offset, count);

            Util.UInt16ToNetworkOrder((ushort)count).CopyTo(realBuffer, 0);
            hash.Take(10).ToArray().CopyTo(realBuffer, 2);
            Buffer.BlockCopy(buffer, offset, realBuffer, 12, count);

            if (useAsync)
                await _stream.WriteAsync(realBuffer, 0, realBuffer.Length, cancellationToken);
            else
                _stream.Write(realBuffer, 0, realBuffer.Length);

            _chunkID += 1;
        }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            CheckWriteArguments(buffer, offset, count);
            return WriteAsyncInternal(buffer, offset, count, cancellationToken);
        }

        private async Task WriteAsyncInternal(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            // To avoid a race with a stream's position pointer & generating race 
            // conditions with internal buffer indexes in our own streams that 
            // don't natively support async IO operations when there are multiple 
            // async requests outstanding, we will block the application's main
            // thread if it does a second IO request until the first one completes.

            SemaphoreSlim semaphore = AsyncActiveSemaphore;
            await semaphore.WaitAsync(cancellationToken);
            if (cancellationToken.IsCancellationRequested) return;
            try
            {
                await WriteAsyncCore(buffer, offset, count, cancellationToken, useAsync: true);
            }
            finally
            {
                semaphore.Release();
            }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            CheckWriteArguments(buffer, offset, count);
            WriteAsyncCore(buffer, offset, count, default(CancellationToken), useAsync: false).GetAwaiter().GetResult();
        }
        #endregion


        private SemaphoreSlim AsyncActiveSemaphore
        {
            get
            {
                // Lazily-initialize _lazyAsyncActiveSemaphore.  As we're never accessing the SemaphoreSlim's
                // WaitHandle, we don't need to worry about Disposing it.
                return LazyInitializer.EnsureInitialized(ref _lazyAsyncActiveSemaphore, () => new SemaphoreSlim(1, 1));
            }
        }
    }
}
