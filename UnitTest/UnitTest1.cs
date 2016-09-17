using System;
using System.IO;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenSSL.Crypto;
using YASS.Extensions;
//using YASS.UnitTest.Extensions;

namespace YASS.UnitTest
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestShadowStream()
        {
            var rng = new Random();
            var originalData = new byte[52428800];
            rng.NextBytes(originalData);
            var ms1 = new MemoryStream();
            var algo = new OpenSslGenericSymmetricAlgoriothm("aes-128-cfb");
            algo.GenerateKey();
            algo.GenerateIV();

            var ss1 = new ShadowStream(ms1, algo, ShadowStreamMode.Write);
            ss1.Write(originalData, 0, 52428800);

            var ms2 = new MemoryStream(ms1.ToArray());

            var ss2 = new ShadowStream(ms2, algo, ShadowStreamMode.Read);
            var readData = new byte[52428800];
            var len = ss2.PromisedRead(readData, 0, 524288);
            Assert.AreEqual(len, 524288);
            Assert.IsTrue(originalData.SequenceEqual(readData));
        }

        [TestMethod]
        public void TestHmacChunkedStream()
        {
            var rng = new Random();
            var originalData = new byte[52428800];
            rng.NextBytes(originalData);
            var ms1 = new MemoryStream();
            var iv = new byte[16];
            rng.NextBytes(iv);
            var ss1 = new HmacChunkedStream(ms1, iv, ShadowStreamMode.Write);
            ss1.Write(originalData, 0, 52428800);

            var ms2 = new MemoryStream(ms1.ToArray());

            var ss2 = new HmacChunkedStream(ms2, iv, ShadowStreamMode.Read);
            var readData = new byte[52428800];
            var len = ss2.PromisedRead(readData, 0, 524288);
            Assert.AreEqual(len, 524288);
            Assert.IsTrue(originalData.SequenceEqual(readData));
        }
    }
}
