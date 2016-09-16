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
using System.Linq;
using System.Net;
using System.Security.Cryptography;

namespace YASS
{
    public static class Util
    {
        public static byte[] ComputeMD5Hash(byte[] buffer, int offset, int count)
        {
            var hasher = MD5.Create();
            return hasher.ComputeHash(buffer, offset, count);
        }

        public static byte[] ComputeMD5Hash(byte[] buffer)
        {
            var hasher = MD5.Create();
            return hasher.ComputeHash(buffer);
        }

        public static byte[] ComputeHMACSHA1Hash(byte[] key, byte[] buffer, int offset, int count)
        {
            var hasher = new HMACSHA1(key);
            return hasher.ComputeHash(buffer, offset, count);
        }

        public static byte[] GetKeyFromBytes(byte[] bytes, int desiredKeyBytes)
        {
            var hasher = MD5.Create();
            var hashlen = hasher.HashSize / 8;
            var result = new byte[bytes.Length + (desiredKeyBytes / hashlen + 1) * hashlen];
            bytes.CopyTo(result, 0);
            for (var currentKeyBytes = 0; currentKeyBytes < desiredKeyBytes; currentKeyBytes += hashlen)
            {
                hasher.ComputeHash(result, 0, currentKeyBytes == 0 ? bytes.Length : bytes.Length + hashlen)
                      .CopyTo(result, currentKeyBytes);
                bytes.CopyTo(result, currentKeyBytes + hashlen);
            }
            return result.Take(desiredKeyBytes).ToArray();
        }

        public static ushort UInt16FromNetworkOrder(byte[] data, int offset)
        {
            return (ushort)(data[offset] << 8 | data[offset + 1]);
        }

        public static byte[] UInt16ToNetworkOrder(ushort x)
        {
            return new []{(byte)((x & 0xFF00) >> 8), (byte)(x & 0xFF)};
        }
        public static byte[] Int32ToNetworkOrder(int x)
        {
            return BitConverter.GetBytes(IPAddress.HostToNetworkOrder(x));
        }

        public static ulong UInt64FromNetworkOrder(byte[] data, int offset)
        {
            return BitConverter.IsLittleEndian
                ? BitConverter.ToUInt64(data.Skip(offset).Take(8).Reverse().ToArray(), 0)
                : BitConverter.ToUInt64(data, offset);
        }

        public static ulong GetUtcTimeEpoch()
        {
            var t = DateTime.UtcNow - new DateTime(1970, 1, 1);
            return (ulong) t.TotalSeconds;
        }

    }
}
