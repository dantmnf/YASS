using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace YASS.Extensions
{
    public static class StreamExtension
    {
        public static async Task<int> PromisedReadAsync(this Stream stream, byte[] buf, int offset, int count,
            CancellationToken ct)
        {
            var totalBytesRead = 0;
            while (totalBytesRead < count)
            {
                var readlen = await stream.ReadAsync(buf, offset + totalBytesRead, count - totalBytesRead, ct);
                if (readlen == 0)
                    throw new IOException("stream closed");
                totalBytesRead += readlen;
            }
            return totalBytesRead;
        }

        public static int PromisedRead(this Stream stream, byte[] buf, int offset, int count)
        {
            var totalBytesRead = 0;
            while (totalBytesRead < count)
            {
                var readlen = stream.Read(buf, offset + totalBytesRead, count - totalBytesRead);
                if (readlen == 0)
                    throw new IOException("stream closed");
                totalBytesRead += readlen;
            }
            return totalBytesRead;
        }
    }
}
