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
using System.Linq;
using System.Security.Cryptography;
using OpenSSL.Crypto;

namespace YASS.AlgorithmProvider
{
    [AlgorithmProvider(Metric = 500)]
    public class OpenSslAlgorithmProvider : IAlgorithmProvider
    {
        private readonly Dictionary<string, int> _ciphers = new Dictionary<string, int>()
        {
            // name,         keysize
            { "aes-128-cfb", 128 },
            { "aes-192-cfb", 192 },
            { "aes-256-cfb", 256 },
        };

        public string[] GetSupportedCiphers() => _ciphers.Keys.ToArray();

        public SymmetricAlgorithm GetAlgorithm(string name)
        {
            var result = new AesOpenSsl()
            {
                Mode = CipherMode.CFB,
                FeedbackSize = 128,
                Padding = PaddingMode.None,
                KeySize = _ciphers[name],
            };
            return result;
        }

        public bool IsAvailable()
        {
            try
            {
                var algo = new AesOpenSsl()
                {
                    Mode = CipherMode.CFB,
                    FeedbackSize = 128,
                    Padding = PaddingMode.None,
                    KeySize = 128
                };
                var enc = algo.CreateEncryptor();
                var result = enc.TransformFinalBlock(
                    new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 0, 10);
                return result.Length == 10;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
