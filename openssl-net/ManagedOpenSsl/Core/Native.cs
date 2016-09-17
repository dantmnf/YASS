// Copyright (c) 2006-2012 Frank Laub
// All rights reserved.
//
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

using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace OpenSSL.Core
{
	/// <summary>
	/// 
	/// </summary>
	public static class FIPS
	{
		/// <summary>
		/// 
		/// </summary>
		public static bool Enabled { get; set; }
	}

	internal enum CryptoLockTypes
	{
		CRYPTO_LOCK_ERR = 1,
		CRYPTO_LOCK_EX_DATA = 2,
		CRYPTO_LOCK_X509 = 3,
		CRYPTO_LOCK_X509_INFO = 4,
		CRYPTO_LOCK_X509_PKEY = 5,
		CRYPTO_LOCK_X509_CRL = 6,
		CRYPTO_LOCK_X509_REQ = 7,
		CRYPTO_LOCK_DSA = 8,
		CRYPTO_LOCK_RSA = 9,
		CRYPTO_LOCK_EVP_PKEY = 10,
		CRYPTO_LOCK_X509_STORE = 11,
		CRYPTO_LOCK_SSL_CTX = 12,
		CRYPTO_LOCK_SSL_CERT = 13,
		CRYPTO_LOCK_SSL_SESSION = 14,
		CRYPTO_LOCK_SSL_SESS_CERT = 15,
		CRYPTO_LOCK_SSL = 16,
		CRYPTO_LOCK_SSL_METHOD = 17,
		CRYPTO_LOCK_RAND = 18,
		CRYPTO_LOCK_RAND2 = 19,
		CRYPTO_LOCK_MALLOC = 20,
		CRYPTO_LOCK_BIO = 21,
		CRYPTO_LOCK_GETHOSTBYNAME = 22,
		CRYPTO_LOCK_GETSERVBYNAME = 23,
		CRYPTO_LOCK_READDIR = 24,
		CRYPTO_LOCK_RSA_BLINDING = 25,
		CRYPTO_LOCK_DH = 26,
		CRYPTO_LOCK_MALLOC2 = 27,
		CRYPTO_LOCK_DSO = 28,
		CRYPTO_LOCK_DYNLOCK = 29,
		CRYPTO_LOCK_ENGINE = 30,
		CRYPTO_LOCK_UI = 31,
		CRYPTO_LOCK_ECDSA = 32,
		CRYPTO_LOCK_EC = 33,
		CRYPTO_LOCK_ECDH = 34,
		CRYPTO_LOCK_BN = 35,
		CRYPTO_LOCK_EC_PRE_COMP = 36,
		CRYPTO_LOCK_STORE = 37,
		CRYPTO_LOCK_COMP = 38,
		CRYPTO_LOCK_FIPS = 39,
		CRYPTO_LOCK_FIPS2 = 40,
		CRYPTO_NUM_LOCKS = 41,
	}

	/// <summary>
	/// This is the low-level C-style interface to the crypto API.
	/// Use this interface with caution.
	/// </summary>
	internal class Native
	{
		/// <summary>
		/// This is the name of the DLL that P/Invoke loads and tries to bind all of
		/// these native functions to.
		/// </summary>
		const string DLLNAME = "libeay32";

		#region Delegates

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int err_cb(IntPtr str, uint len, IntPtr u);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int pem_password_cb(IntPtr buf, int size, int rwflag, IntPtr userdata);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int GeneratorHandler(int p, int n, IntPtr arg);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate void ObjectNameHandler(IntPtr name, IntPtr arg);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate void CRYPTO_locking_callback(int mode, int type, string file, int line);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate void CRYPTO_id_callback(IntPtr tid);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int VerifyCertCallback(int ok, IntPtr x509_store_ctx);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int client_cert_cb(IntPtr ssl, out IntPtr x509, out IntPtr pkey);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int alpn_cb(
			IntPtr ssl, 
			out string selProto, 
			out byte selProtoLen,
			IntPtr inProtos, 
			int inProtosLen, 
			IntPtr arg
		);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate IntPtr MallocFunctionPtr(uint num, IntPtr file, int line);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate IntPtr ReallocFunctionPtr(IntPtr addr, uint num, IntPtr file, int line);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate void FreeFunctionPtr(IntPtr addr);

		#endregion

		#region Initialization

		static Native()
		{
			var lib = Version.Library;
			var wrapper = Version.Wrapper;
			if (lib.Raw < wrapper.Raw)
				throw new Exception(string.Format("Invalid version of {0}, expecting {1}, got: {2}",
					DLLNAME, wrapper, lib));
            
			// Enable FIPS mode
			if (FIPS.Enabled)
			{
				if (FIPS_mode_set(1) == 0)
				{
					throw new Exception("Failed to initialize FIPS mode");
				}
			}

			ERR_load_crypto_strings();

			OPENSSL_add_all_algorithms_noconf();
            
			var seed = new byte[128];
			var rng = RandomNumberGenerator.Create();
			rng.GetBytes(seed);
			RAND_seed(seed, seed.Length);
		}

		#endregion

		#region Version

		// 1.0.2a Release
		public const uint Wrapper = 0x1000201F;

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr SSLeay_version(int type);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static uint SSLeay();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr BN_options();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr MD2_options();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr RC4_options();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr DES_options();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr BF_options();

		#endregion

		#region Threading

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int CRYPTO_THREADID_set_callback(CRYPTO_id_callback cb);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void CRYPTO_THREADID_set_numeric(IntPtr id, uint val);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void CRYPTO_set_locking_callback(CRYPTO_locking_callback cb);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int CRYPTO_num_locks();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int CRYPTO_add_lock(IntPtr ptr, int amount, CryptoLockTypes type, string file, int line);

		#endregion

		#region CRYPTO

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void OPENSSL_add_all_algorithms_noconf();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void OPENSSL_add_all_algorithms_conf();

		/// <summary>
		/// #define OPENSSL_malloc(num)	CRYPTO_malloc((int)num,__FILE__,__LINE__)
		/// </summary>
		/// <param name="cbSize"></param>
		/// <returns></returns>
		public static IntPtr OPENSSL_malloc(int cbSize)
		{
			return CRYPTO_malloc(cbSize, Assembly.GetExecutingAssembly().FullName, 0);
		}

		/// <summary>
		/// #define OPENSSL_free(addr) CRYPTO_free(addr)
		/// </summary>
		/// <param name="p"></param>
		public static void OPENSSL_free(IntPtr p)
		{
			CRYPTO_free(p);
		}

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void CRYPTO_free(IntPtr p);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr CRYPTO_malloc(int num, string file, int line);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int CRYPTO_set_mem_ex_functions(
			MallocFunctionPtr m, 
			ReallocFunctionPtr r, 
			FreeFunctionPtr f
		);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void CRYPTO_cleanup_all_ex_data();

		#endregion

		#region OBJ

		public const int NID_undef = 0;

		public const int OBJ_undef = 0;

		public const int OBJ_NAME_TYPE_UNDEF = 0x00;
		public const int OBJ_NAME_TYPE_MD_METH = 0x01;
		public const int OBJ_NAME_TYPE_CIPHER_METH = 0x02;
		public const int OBJ_NAME_TYPE_PKEY_METH = 0x03;
		public const int OBJ_NAME_TYPE_COMP_METH = 0x04;
		public const int OBJ_NAME_TYPE_NUM = 0x05;

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void OBJ_NAME_do_all(int type, ObjectNameHandler fn, IntPtr arg);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void OBJ_NAME_do_all_sorted(int type, ObjectNameHandler fn, IntPtr arg);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int OBJ_txt2nid(string s);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr OBJ_nid2obj(int n);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr OBJ_nid2ln(int n);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr OBJ_nid2sn(int n);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int OBJ_obj2nid(IntPtr o);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr OBJ_txt2obj(string s, int no_name);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int OBJ_ln2nid(string s);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int OBJ_sn2nid(string s);

		#endregion

		#region stack

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr sk_new_null();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int sk_num(IntPtr stack);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int sk_find(IntPtr stack, IntPtr data);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int sk_insert(IntPtr stack, IntPtr data, int where);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr sk_shift(IntPtr stack);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int sk_unshift(IntPtr stack, IntPtr data);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int sk_push(IntPtr stack, IntPtr data);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr sk_pop(IntPtr stack);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr sk_delete(IntPtr stack, int loc);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr sk_delete_ptr(IntPtr stack, IntPtr p);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr sk_value(IntPtr stack, int index);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr sk_set(IntPtr stack, int index, IntPtr data);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr sk_dup(IntPtr stack);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void sk_zero(IntPtr stack);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void sk_free(IntPtr stack);

		#endregion
        
		#region RAND

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int RAND_set_rand_method(IntPtr meth);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr RAND_get_rand_method();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void RAND_cleanup();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void RAND_seed(byte[] buf, int len);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int RAND_pseudo_bytes(byte[] buf, int len);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int RAND_bytes(byte[] buf, int num);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void RAND_add(byte[] buf, int num, double entropy);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int RAND_load_file(string file, int max_bytes);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int RAND_write_file(string file);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static string RAND_file_name(byte[] buf, uint num);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int RAND_status();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int RAND_query_egd_bytes(string path, byte[] buf, int bytes);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int RAND_egd(string path);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int RAND_egd_bytes(string path, int bytes);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int RAND_poll();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int BN_rand(IntPtr rnd, int bits, int top, int bottom);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int BN_pseudo_rand(IntPtr rnd, int bits, int top, int bottom);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int BN_rand_range(IntPtr rnd, IntPtr range);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int BN_pseudo_rand_range(IntPtr rnd, IntPtr range);

		#endregion
        
        #region DER

		//#define d2i_DHparams_bio(bp,x) ASN1_d2i_bio_of(DH,DH_new,d2i_DHparams,bp,x)
		//#define i2d_DHparams_bio(bp,x) ASN1_i2d_bio_of_const(DH,i2d_DHparams,bp,x)
		//
		//#define ASN1_d2i_bio_of(type,xnew,d2i,in,x) \
		//    ((type*)ASN1_d2i_bio( CHECKED_NEW_OF(type, xnew), \
		//              CHECKED_D2I_OF(type, d2i), \
		//              in, \
		//              CHECKED_PPTR_OF(type, x)))
		//
		//#define ASN1_i2d_bio_of_const(type,i2d,out,x) \
		//    (ASN1_i2d_bio(CHECKED_I2D_OF(const type, i2d), \
		//          out, \
		//          CHECKED_PTR_OF(const type, x)))
		//
		//#define CHECKED_I2D_OF(type, i2d) \
		//    ((i2d_of_void*) (1 ? i2d : ((I2D_OF(type))0)))
		//
		//#define I2D_OF(type) int (*)(type *,byte[] *)
		//
		//#define CHECKED_PTR_OF(type, p) \
		//    ((void*) (1 ? p : (type*)0))

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public static extern IntPtr d2i_DHparams(out IntPtr a, IntPtr pp, int length);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int i2d_DHparams(IntPtr a, IntPtr pp);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr ASN1_d2i_bio(IntPtr xnew, IntPtr d2i, IntPtr bp, IntPtr x);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int ASN1_i2d_bio(IntPtr i2d, IntPtr bp, IntPtr x);

		#endregion
        
		#region EVP

		#region Constants

		public const int EVP_MAX_MD_SIZE = 64;
		//!!(16+20);
		public const int EVP_MAX_KEY_LENGTH = 32;
		public const int EVP_MAX_IV_LENGTH = 16;
		public const int EVP_MAX_BLOCK_LENGTH = 32;

		public const int EVP_CIPH_STREAM_CIPHER = 0x0;
		public const int EVP_CIPH_ECB_MODE = 0x1;
		public const int EVP_CIPH_CBC_MODE = 0x2;
		public const int EVP_CIPH_CFB_MODE = 0x3;
		public const int EVP_CIPH_OFB_MODE = 0x4;
		public const int EVP_CIPH_MODE = 0x7;
		public const int EVP_CIPH_VARIABLE_LENGTH = 0x8;
		public const int EVP_CIPH_CUSTOM_IV = 0x10;
		public const int EVP_CIPH_ALWAYS_CALL_INIT = 0x20;
		public const int EVP_CIPH_CTRL_INIT = 0x40;
		public const int EVP_CIPH_CUSTOM_KEY_LENGTH = 0x80;
		public const int EVP_CIPH_NO_PADDING = 0x100;
		public const int EVP_CIPH_FLAG_FIPS = 0x400;
		public const int EVP_CIPH_FLAG_NON_FIPS_ALLOW = 0x800;

		#endregion

		#region Message Digests

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_md_null();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_md2();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_md4();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_md5();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_sha();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_sha1();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_sha224();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_sha256();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_sha384();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_sha512();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_dss();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_dss1();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_mdc2();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_ripemd160();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_ecdsa();

		#endregion

		#region HMAC

		public const int HMAC_MAX_MD_CBLOCK = 128;

		//!!void HMAC_CTX_init(HMAC_CTX *ctx);
		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void HMAC_CTX_init(IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void HMAC_CTX_set_flags(IntPtr ctx, uint flags);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void HMAC_CTX_cleanup(IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void HMAC_Init(IntPtr ctx, byte[] key, int len, IntPtr md);
		/* deprecated */
		
		//!!public extern static void HMAC_Init_ex(IntPtr ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl);
		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void HMAC_Init_ex(IntPtr ctx, byte[] key, int len, IntPtr md, IntPtr engine_impl);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void HMAC_Update(IntPtr ctx, byte[] data, int len);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void HMAC_Final(IntPtr ctx, byte[] md, ref uint len);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr HMAC(IntPtr evp_md, byte[] key, int key_len, byte[] d, int n, byte[] md, ref uint md_len);

		#endregion

		#region Ciphers

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_get_cipherbyname(byte[] name);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_enc_null();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ecb();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede3();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede_ecb();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede3_ecb();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_cfb64();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_cfb1();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_cfb8();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede_cfb64();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede3_cfb64();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede3_cfb1();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede3_cfb8();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ofb();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede_ofb();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede3_ofb();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_cbc();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede_cbc();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_des_ede3_cbc();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_desx_cbc();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc4();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc4_40();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc2_ecb();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc2_cbc();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc2_40_cbc();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc2_64_cbc();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc2_cfb64();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc2_ofb();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_bf_ecb();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_bf_cbc();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_bf_cfb64();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_bf_ofb();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_cast5_ecb();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_cast5_cbc();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_cast5_cfb64();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_cast5_ofb();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc5_32_12_16_cbc();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc5_32_12_16_ecb();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc5_32_12_16_cfb64();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_rc5_32_12_16_ofb();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_128_ecb();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_128_cbc();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_128_cfb1();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_128_cfb8();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_128_cfb128();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_128_ofb();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_192_ecb();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_192_cbc();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_192_cfb1();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_192_cfb8();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_192_cfb128();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_192_ofb();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_256_ecb();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_256_cbc();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_256_cfb1();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_256_cfb8();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_256_cfb128();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_aes_256_ofb();

		#endregion

		#region EVP_PKEY

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_PKEY_new();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void EVP_PKEY_free(IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_cmp(IntPtr a, IntPtr b);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_decrypt(byte[] dec_key, byte[] enc_key, int enc_key_len, IntPtr private_key);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_encrypt(byte[] enc_key, byte[] key, int key_len, IntPtr pub_key);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_encrypt_old(byte[] enc_key, byte[] key, int key_len, IntPtr pub_key);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_type(int type);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_bits(IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_size(IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_assign(IntPtr pkey, int type, IntPtr key);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_set1_DSA(IntPtr pkey, IntPtr key);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_PKEY_get1_DSA(IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_set1_RSA(IntPtr pkey, IntPtr key);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_PKEY_get1_RSA(IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_set1_EC_KEY(IntPtr pkey, IntPtr key);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_PKEY_get1_EC_KEY(IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_set1_DH(IntPtr pkey, IntPtr key);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_PKEY_get1_DH(IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_copy_parameters(IntPtr to, IntPtr from);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_missing_parameters(IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_save_parameters(IntPtr pkey, int mode);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_PKEY_cmp_parameters(IntPtr a, IntPtr b);

		#endregion

		#region EVP_CIPHER

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void EVP_CIPHER_CTX_init(IntPtr a);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_CIPHER_CTX_rand_key(IntPtr ctx, byte[] key);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_CIPHER_CTX_set_padding(IntPtr x, int padding);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_CIPHER_CTX_set_key_length(IntPtr x, int keylen);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_CIPHER_CTX_ctrl(IntPtr ctx, int type, int arg, IntPtr ptr);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_CIPHER_CTX_cleanup(IntPtr a);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_CIPHER_type(IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_CipherInit_ex(IntPtr ctx, IntPtr type, IntPtr impl, byte[] key, byte[] iv, int enc);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_CipherUpdate(IntPtr ctx, byte[] outb, out int outl, byte[] inb, int inl);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_CipherUpdate(IntPtr ctx, IntPtr outb, out int outl, IntPtr inb, int inl);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern unsafe static int EVP_CipherUpdate(IntPtr ctx, void* outb, out int outl, void* inb, int inl);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_CipherFinal_ex(IntPtr ctx, byte[] outm, ref int outl);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_OpenInit(IntPtr ctx, IntPtr type, byte[] ek, int ekl, byte[] iv, IntPtr priv);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_OpenFinal(IntPtr ctx, byte[] outb, out int outl);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_SealInit(
			IntPtr ctx,
			IntPtr type,
			IntPtr[] ek,
			int[] ekl,
			byte[] iv,
			IntPtr[] pubk,
			int npubk);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_SealFinal(IntPtr ctx, byte[] outb, out int outl);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_DecryptUpdate(IntPtr ctx, byte[] output, out int outl, byte[] input, int inl);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_EncryptInit_ex(IntPtr ctx, IntPtr cipher, IntPtr impl, byte[] key, byte[] iv);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_EncryptUpdate(IntPtr ctx, byte[] output, out int outl, byte[] input, int inl);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_BytesToKey(
			IntPtr type,
			IntPtr md,
			byte[] salt,
			byte[] data,
			int datal,
			int count,
			byte[] key,
			byte[] iv);

		#endregion

		#region EVP_MD

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_MD_type(IntPtr md);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_MD_pkey_type(IntPtr md);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_MD_size(IntPtr md);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_MD_block_size(IntPtr md);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static uint EVP_MD_flags(IntPtr md);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_get_digestbyname(byte[] name);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void EVP_MD_CTX_init(IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_MD_CTX_cleanup(IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr EVP_MD_CTX_create();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void EVP_MD_CTX_destroy(IntPtr ctx);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_DigestInit_ex(IntPtr ctx, IntPtr type, IntPtr impl);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_DigestUpdate(IntPtr ctx, byte[] d, uint cnt);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_DigestFinal_ex(IntPtr ctx, byte[] md, ref uint s);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_Digest(byte[] data, uint count, byte[] md, ref uint size, IntPtr type, IntPtr impl);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_SignFinal(IntPtr ctx, byte[] md, ref uint s, IntPtr pkey);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int EVP_VerifyFinal(IntPtr ctx, byte[] sigbuf, uint siglen, IntPtr pkey);

		#endregion

		#endregion
        
		#region ERR

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void ERR_load_crypto_strings();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static uint ERR_get_error();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void ERR_error_string_n(uint e, byte[] buf, int len);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr ERR_lib_error_string(uint e);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr ERR_func_error_string(uint e);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr ERR_reason_error_string(uint e);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void ERR_remove_thread_state(IntPtr tid);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void ERR_clear_error();

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void ERR_print_errors_cb(err_cb cb, IntPtr u);

		#endregion

		#region NCONF

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr NCONF_new(IntPtr meth);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void NCONF_free(IntPtr conf);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		//!!public extern static int NCONF_load(IntPtr conf, byte[] file, ref int eline);
		public extern static int NCONF_load(IntPtr conf, string file, ref int eline);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static IntPtr NCONF_get_string(IntPtr conf, byte[] group, byte[] name);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void X509V3_set_ctx(
			IntPtr ctx,
			IntPtr issuer,
			IntPtr subject,
			IntPtr req,
			IntPtr crl,
			int flags);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static void X509V3_set_nconf(IntPtr ctx, IntPtr conf);

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int X509V3_EXT_add_nconf(IntPtr conf, IntPtr ctx, byte[] section, IntPtr cert);

		#endregion

		#region FIPS

		[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
		public extern static int FIPS_mode_set(int onoff);

		#endregion
        
		#region Utilities

		public static string StaticString(IntPtr ptr)
		{
			return Marshal.PtrToStringAnsi(ptr);
		}

		public static string PtrToStringAnsi(IntPtr ptr, bool hasOwnership)
		{
			var len = 0;
			for (var i = 0; i < 1024; i++, len++)
			{
				var octet = Marshal.ReadByte(ptr, i);
				if (octet == 0)
					break;
			}

			if (len == 1024)
				return "Invalid string";

			var buf = new byte[len];
			Marshal.Copy(ptr, buf, 0, len);
			if (hasOwnership)
				Native.OPENSSL_free(ptr);
			
			return Encoding.ASCII.GetString(buf, 0, len);
		}

		public static IntPtr ExpectNonNull(IntPtr ptr)
		{
			if (ptr == IntPtr.Zero)
				throw new OpenSslException();

			return ptr;
		}

		public static int ExpectSuccess(int ret)
		{
			if (ret <= 0)
				throw new OpenSslException();

			return ret;
		}

		public static int TextToNID(string text)
		{
			var nid = Native.OBJ_txt2nid(text);

			if (nid == Native.NID_undef)
				throw new OpenSslException();

			return nid;
		}

		#endregion
	}

	class NameCollector
	{
		[StructLayout(LayoutKind.Sequential)]
		struct OBJ_NAME
		{
			public int type;
			public int alias;
			public IntPtr name;
			public IntPtr data;
		};

		private List<string> list = new List<string>();

		public List<string> Result { get { return list; } }

		public NameCollector(int type, bool isSorted)
		{
			if (isSorted)
				Native.OBJ_NAME_do_all_sorted(type, OnObjectName, IntPtr.Zero);
			else
				Native.OBJ_NAME_do_all(type, OnObjectName, IntPtr.Zero);
		}

		private void OnObjectName(IntPtr ptr, IntPtr arg)
		{
			var name = (OBJ_NAME)Marshal.PtrToStructure(ptr, typeof(OBJ_NAME));
			var str = Native.PtrToStringAnsi(name.name, false);
			list.Add(str);
		}
	}
}
