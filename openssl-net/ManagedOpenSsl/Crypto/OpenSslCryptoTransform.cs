// Copyright (c) 2006-2007 Frank Laub
// All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

using OpenSSL.Core;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace OpenSSL.Crypto
{

	/// <summary>
	/// Wraps the EVP_CIPHER_CTX object.
	/// </summary>
	public class OpenSslCryptoTransform : Base, ICryptoTransform
	{
		#region EVP_CIPHER_CTX
		[StructLayout(LayoutKind.Sequential)]
		struct EVP_CIPHER_CTX
		{
			public IntPtr cipher;
			public IntPtr engine;	/* functional reference if 'cipher' is ENGINE-provided */
			public int encrypt;		/* encrypt or decrypt */
			public int buf_len;		/* number we have left */

			[MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_IV_LENGTH)]
			public byte[] oiv;	/* original iv */
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_IV_LENGTH)]
			public byte[] iv;	/* working iv */
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_BLOCK_LENGTH)]
			public byte[] buf;/* saved partial block */
			public int num;				/* used by cfb/ofb mode */

			public IntPtr app_data;		/* application stuff */
			public int key_len;		/* May change for variable length cipher */
			public uint flags;	/* Various flags */
			public IntPtr cipher_data; /* per EVP data */
			public int final_used;
			public int block_mask;

			[MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_BLOCK_LENGTH)]
			public byte[] final;/* possible final block */
		}
		#endregion

	    /// <summary>
        /// Calls OPENSSL_malloc() and initializes the buffer using EVP_CIPHER_CTX_init()
        /// </summary>

        public  OpenSslCryptoTransform(Cipher cipher, byte[] rgbKey, byte[] rgbIV, bool isEncrypt, int pkcsPadding)
			: base(Native.OPENSSL_malloc(Marshal.SizeOf(typeof(EVP_CIPHER_CTX))), true)
        {
            var enc = isEncrypt ? 1 : 0;
            Native.EVP_CIPHER_CTX_init(ptr);
			Cipher = cipher;
            var key = SetupKey(rgbKey);
            var iv = SetupIV(rgbIV);
            Native.ExpectSuccess(Native.EVP_CipherInit_ex(ptr, cipher.Handle, IntPtr.Zero, null, null, enc));

            Native.ExpectSuccess(Native.EVP_CIPHER_CTX_set_key_length(ptr, key.Length));

            if (IsStream)
            {
                for (int i = 0; i < Math.Min(key.Length, iv.Length); i++)
                {
                    key[i] ^= iv[i];
                }

                Native.ExpectSuccess(Native.EVP_CipherInit_ex(ptr, cipher.Handle, IntPtr.Zero, key, null, enc));
            }
            else
            {
                Native.ExpectSuccess(Native.EVP_CipherInit_ex(ptr, cipher.Handle, IntPtr.Zero, key, iv, enc));
            }

            if (pkcsPadding >= 0)
                Native.ExpectSuccess(Native.EVP_CIPHER_CTX_set_padding(ptr, pkcsPadding));
            }


		#region Methods

		private byte[] SetupKey(byte[] key)
		{
			if (key == null)
			{
				key = new byte[Cipher.KeyLength];
				key.Initialize();
				return key;
			}

			if (Cipher.KeyLength == key.Length)
			{
				return key;
			}

			byte[] real_key = new byte[Cipher.KeyLength];
			real_key.Initialize();
			Buffer.BlockCopy(key, 0, real_key, 0, Math.Min(key.Length, real_key.Length));

			return real_key;
		}

		private byte[] SetupIV(byte[] iv)
		{
			if (Cipher.IVLength > iv.Length)
			{
				var ret = new byte[Cipher.IVLength];
				ret.Initialize();
				Buffer.BlockCopy(iv, 0, ret, 0, iv.Length);

				return ret;
			}

			return iv;
		}

        public int TransformBlock(byte[] buffer, int offset, int count, byte[] outbuf, int outoffset)
        {
            // 1. passing a managed array to P/Invoke will cause a memory copy,
            //    and we need another copy to implement offset.
            // 2. getting pointer of a managed array is expensive, making it has no advantage in performance
            // 3. so we allocate a block of unmanaged memory and copy the memory once

            var len = 0;
            var realIn = Marshal.AllocHGlobal(count);
            Marshal.Copy(buffer, offset, realIn, count);
            var realOut = Marshal.AllocHGlobal(count);
            try
            {
                Native.ExpectSuccess(Native.EVP_CipherUpdate(ptr, realOut, out len, realIn, count));
                Marshal.Copy(realOut, outbuf, outoffset, len);
            }
            finally
            {
                Marshal.FreeHGlobal(realIn);
                Marshal.FreeHGlobal(realOut);
            }
            return len;
        }

        /// <summary>
        /// passing fixed pointer to EVP_CipherUpdate
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <param name="outbuf"></param>
        /// <param name="outoffset"></param>
        /// <returns>number of bytes transformed</returns>
        public unsafe int TransformBlockUnsafe(byte[] buffer, int offset, int count, byte[] outbuf, int outoffset)
        {
            var len = 0;
            fixed (byte* pBuffer = buffer)
            fixed (byte* pOutput = outbuf)
            {
                Native.ExpectSuccess(Native.EVP_CipherUpdate(ptr, pOutput + outoffset, out len, pBuffer + offset, count));
            }
            return len;
        }

        /// <summary>
        /// calls TransformBlock and EVP_CipherFinal_ex
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <returns>the last transformed block</returns>
        public byte[] TransformFinalBlock(byte[] buffer, int offset, int count)
        {
            var ms = new MemoryStream();
            var outbuf = new byte[Math.Max(count, Cipher.BlockSize)];
            var len = TransformBlock(buffer, offset, count, outbuf, 0);
            ms.Write(outbuf, 0, len);
            len = outbuf.Length;
            Native.ExpectSuccess(Native.EVP_CipherFinal_ex(ptr, outbuf, ref len));
            ms.Write(outbuf, 0, len);
            return ms.ToArray();
        }

        #endregion

        #region Properties
        /// <summary>
        /// Returns the EVP_CIPHER for this context.
        /// </summary>
        public Cipher Cipher { get; }

	    /// <summary>
		/// Returns if EVP_CIPH_STREAM_CIPHER is set in flags
		/// </summary>
		public bool IsStream
		{
			get { return (Cipher.Flags & Native.EVP_CIPH_MODE) == Native.EVP_CIPH_STREAM_CIPHER; }
		}


        public bool CanReuseTransform { get { return false; } }
        public bool CanTransformMultipleBlocks { get { return true; } }

        public int InputBlockSize { get { return Cipher.BlockSize; } }
        public int OutputBlockSize { get { return Cipher.BlockSize; } }

        #endregion

        #region IDisposable Members

        /// <summary>
        /// Calls EVP_CIPHER_CTX_clean() and then OPENSSL_free()
        /// </summary>
        protected override void OnDispose()
		{
			Native.EVP_CIPHER_CTX_cleanup(ptr);
			Native.OPENSSL_free(ptr);
		}

		#endregion
	}
}
