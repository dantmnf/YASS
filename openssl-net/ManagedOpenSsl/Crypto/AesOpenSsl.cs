using System;
using System.Security.Cryptography;

namespace OpenSSL.Crypto
{
    /// <summary>
    /// Provides OpenSSL implementation of the Advanced Encryption Standard (AES) symmetric algorithm.
    /// </summary>
    public class AesOpenSsl : Aes
    {
        private readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();
        private readonly Cipher[,] _ciphers = {
            {Cipher.AES_128_CBC, Cipher.AES_128_ECB, Cipher.AES_128_OFB, Cipher.AES_128_CFB8, Cipher.AES_128_CFB128, Cipher.AES_128_CFB1, },
            {Cipher.AES_192_CBC, Cipher.AES_192_ECB, Cipher.AES_192_OFB, Cipher.AES_192_CFB8, Cipher.AES_192_CFB128, Cipher.AES_192_CFB1, },
            {Cipher.AES_256_CBC, Cipher.AES_256_ECB, Cipher.AES_256_OFB, Cipher.AES_256_CFB8, Cipher.AES_256_CFB128, Cipher.AES_256_CFB1, },
        };

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

        public override CipherMode Mode
        {
            get { return ModeValue; }
            set
            {
                if (value == CipherMode.CTS)
                    throw new NotSupportedException($"Cipher mode {value} is not supported.");
                ModeValue = value;
            }
        }

        /// <summary>
        /// Only applies to cipher feedback (CFB) mode. Supported values: 1, 8, 128
        /// </summary>
        public override int FeedbackSize
        {
            get { return FeedbackSizeValue; }
            set
            {
                if (value != 1 && value != 8 && value != 128)
                    throw new NotSupportedException($"Feedback size {value} is not supported.");
                FeedbackSizeValue = value;
            }
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            //Cipher.CreateByName()
            return new OpenSslCryptoTransform(GetOpenSslCipher(), rgbKey, rgbIV, true, PaddingValue != PaddingMode.None ? 1 : 0);
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new OpenSslCryptoTransform(GetOpenSslCipher(), rgbKey, rgbIV, false, PaddingValue != PaddingMode.None ? 1 : 0);
        }

        public override void GenerateKey()
        {
            var key = new byte[KeySizeValue / 8];
            _rng.GetBytes(key);
            KeyValue = key;
        }

        public override void GenerateIV()
        {
            var iv = new byte[BlockSizeValue / 8];
            _rng.GetBytes(iv);
            IVValue = iv;
        }

        private Cipher GetOpenSslCipher()
        {
            var i = (KeySizeValue - 128)/64;
            var j = 0;
            switch (ModeValue)
            {
                case CipherMode.CBC:
                    j = 0;
                    break;
                    case CipherMode.ECB:
                    j = 1;
                    break;
                    case CipherMode.OFB:
                    j = 2;
                    break;
                    case CipherMode.CFB:
                    switch (FeedbackSizeValue)
                    {
                        case 8:
                            j = 3;
                            break;
                        case 128:
                            j = 4;
                            break;
                        case 1:
                            j = 5;
                            break;
                    }
                    break;
                default:
                    j = 0;
                    break;
            }
            return _ciphers[i, j];
        }

    }
}
