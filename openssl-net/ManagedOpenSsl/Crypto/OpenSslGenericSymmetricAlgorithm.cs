using System;
using System.Security.Cryptography;

namespace OpenSSL.Crypto
{
    /// <summary>
    /// Provides access to OpenSSL EVP via .NET cryptographic API
    /// There are some restrictions due to the API difference between OpenSSL EVP and .NET Cryptographic API
    /// If you are doing AES transform, consider using AesOpenSsl class
    /// </summary>
    public class OpenSslGenericSymmetricAlgorithm : SymmetricAlgorithm
    {
        private RandomNumberGenerator _rng = RandomNumberGenerator.Create();
        /// <summary>
        /// Only supports PKCS7 mode.
        /// </summary>
        public override PaddingMode Padding
        {
            get { return PaddingValue; }
            set
            {
                if(value != PaddingMode.PKCS7 && value != PaddingMode.None)
                    throw new NotSupportedException($"Padding mode {value} is not supported.");
                PaddingValue = value;
            }
        }

        /// <summary>
        /// THIS PROPERTY WILL NOT BE RESPECTED due to the API difference between OpenSSL EVP and .NET Cryptographic API
        /// </summary>
        [Obsolete("OpenSslGenericSymmetricAlgorithm.CipherMode will be ignored due to the API difference between OpenSSL EVP and .NET Cryptographic API")]
        public override CipherMode Mode { get; set; }

        /// <summary>
        /// THIS PROPERTY WILL NOT BE RESPECTED due to the API difference between OpenSSL EVP and .NET Cryptographic API
        /// </summary>
        [Obsolete("OpenSslGenericSymmetricAlgorithm.FeedbackSize will be ignored due to the API difference between OpenSSL EVP and .NET Cryptographic API")]
        public override int FeedbackSize { get; set; }

        public override int BlockSize => OpenSslCipher.BlockSize*8;
        public override int KeySize => OpenSslCipher.KeyLength*8;
        public override KeySizes[] LegalBlockSizes => new[] { new KeySizes(BlockSize, BlockSize, 0) };
        public override KeySizes[] LegalKeySizes => new[] { new KeySizes(KeySize, KeySize, 0) };

        public readonly Cipher OpenSslCipher;

        public OpenSslGenericSymmetricAlgorithm(Cipher cipher)
        {
            OpenSslCipher = cipher;
            KeySizeValue = cipher.KeyLength * 8;
            BlockSizeValue = cipher.BlockSize * 8;
        }

        public OpenSslGenericSymmetricAlgorithm(string cipherName)
            : this(Cipher.CreateByName(cipherName))
        {
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new OpenSslCryptoTransform(OpenSslCipher, rgbKey, rgbIV, true, PaddingValue != PaddingMode.None ? 1 : 0);
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new OpenSslCryptoTransform(OpenSslCipher, rgbKey, rgbIV, false, PaddingValue != PaddingMode.None ? 1 : 0);
        }

        public override void GenerateKey()
        {
            var key = new byte[OpenSslCipher.KeyLength];
            _rng.GetBytes(key);
            KeyValue = key;
        }

        public override void GenerateIV()
        {
            var iv = new byte[OpenSslCipher.IVLength];
            _rng.GetBytes(iv);
            IVValue = iv;
        }



    }
}
