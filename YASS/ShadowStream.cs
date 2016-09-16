using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace YASS
{
    public enum ShadowStreamMode
    {
        Read,
        Write
    }

    class ShadowStream : Stream, IDisposable
    {
        private readonly Stream _stream;
        private readonly SymmetricAlgorithm _algo;
        private ICryptoTransform _transformer;
        private readonly ShadowStreamMode _mode;
        private readonly bool _canRead;
        private readonly bool _canWrite;
        private readonly RandomNumberGenerator _rng;
        public byte[] IV { get; private set; }
        private int _ivlen;
        private bool _initialized;
        private SemaphoreSlim _lazyAsyncActiveSemaphore;

        public ShadowStream(Stream underlyingStream, SymmetricAlgorithm algorithm, ShadowStreamMode mode)
        {
            _stream = underlyingStream;
            _algo = algorithm;
            _ivlen = algorithm.BlockSize/8;
            //_transformer = transform;
            _mode = mode;
            _rng = RandomNumberGenerator.Create();
            switch (mode)
            {
                case ShadowStreamMode.Read:
                    if (!(_stream.CanRead)) throw new ArgumentException("stream not readable");
                    if (_algo.CreateDecryptor().InputBlockSize != 1)
                        throw new ArgumentException("algorithm block size is not 1");
                    _canRead = true;
                    break;
                case ShadowStreamMode.Write:
                    if (!(_stream.CanWrite)) throw new ArgumentException("stream not writable");
                    if (_algo.CreateEncryptor().InputBlockSize != 1)
                        throw new ArgumentException("algorithm block size is not 1");
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
                ReadAsyncCore(buffer, offset, count, default(CancellationToken), false, true).ConfigureAwait(false).GetAwaiter().GetResult();
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
                return await ReadAsyncCore(buffer, offset, count, cancellationToken, true, true);
            }
            finally
            {
                semaphore.Release();
            }
        }
        private async Task<int> ReadAsyncCore(byte[] buffer, int offset, int count, CancellationToken cancellationToken, bool useAsync, bool inplace)
        {
            if (!_initialized)
            {
                IV = new byte[_algo.BlockSize/8];
                if (useAsync)
                    await _stream.ReadAsync(IV, 0, IV.Length, cancellationToken);
                else
                    _stream.Read(IV, 0, IV.Length);
                _transformer = _algo.CreateDecryptor(_algo.Key, IV);
                _initialized = true;
            }
            var realBuffer = inplace ? buffer : new byte[count];
            var realOffset = inplace ? offset : 0;
            var bytesRead = useAsync ? await _stream.ReadAsync(realBuffer, realOffset , count, cancellationToken).ConfigureAwait(false)
                                     : _stream.Read(realBuffer, realOffset, count);
            _transformer.TransformBlock(realBuffer, realOffset, count, realBuffer, realOffset);
            if (!inplace) Buffer.BlockCopy(realBuffer, 0, buffer, offset, count);
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
            var realBuffer = new byte[_initialized ? count : count + _ivlen];
            if (!_initialized)
            {
                IV = new byte[_ivlen];
                _rng.GetBytes(IV);
                _transformer = _algo.CreateEncryptor(_algo.Key, IV);
                IV.CopyTo(realBuffer, 0);
            }
            
            _transformer.TransformBlock(buffer, offset, count, realBuffer, _initialized ? 0 : _ivlen);
            if (useAsync)
                await _stream.WriteAsync(realBuffer, 0, realBuffer.Length, cancellationToken);
            else
                _stream.Write(realBuffer, 0, realBuffer.Length);
            if (!_initialized) _initialized = true;
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
