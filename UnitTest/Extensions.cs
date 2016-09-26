using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace YASS.UnitTest.Extensions
{
    static class ArrayExtensions
    {
        [DllImport("ntdll.dll")]
        static extern unsafe uint RtlCompareMemory(void* src1, void* src2, uint len);

        public static unsafe bool SequenceEqual(this ArraySegment<byte> src1, byte[] src2)
        {
            if (src1.Count != src2.Length) return false;
            var len = src1.Count;
            var array = src1.Array;
            fixed (byte* pSrcArray = array)
            fixed (byte* pSrc2 = src2)
            {
                var pSrc1 = pSrcArray + src1.Offset;
                return len == RtlCompareMemory(pSrc1, pSrc2, (uint)len);
            }

        }

        public static unsafe bool SequenceEqual(this byte[] src1, byte[] src2)
        {
            if (src1.Length != src2.Length)
                return false;
            var len = src1.Length;
            /*for (var i = 0; i < len; i++)
                if (src1[i] != src2[i])
                    return false;
            return true;*/
            fixed (byte* pSrc1 = src1)
            fixed (byte* pSrc2 = src2)
            {
                return len == RtlCompareMemory(pSrc1, pSrc2, (uint)len);
            }
        }
    }
}
