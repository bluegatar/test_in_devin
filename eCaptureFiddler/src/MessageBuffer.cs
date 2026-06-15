using System;
using System.IO;
using System.Text;

namespace ECaptureFiddler.Core
{
    /// <summary>
    /// Accumulates the bytes of one HTTP message and decides when it is
    /// complete (headers present + body satisfied per Content-Length or the
    /// chunked terminator).
    /// </summary>
    internal sealed class MessageBuffer
    {
        private static readonly Encoding Latin1 = Encoding.GetEncoding("ISO-8859-1");
        private readonly MemoryStream _buf = new MemoryStream();
        public bool Started;

        public void Append(byte[] b)
        {
            if (b != null && b.Length > 0) _buf.Write(b, 0, b.Length);
        }

        public bool IsEmpty => _buf.Length == 0;
        public byte[] ToBytes() => _buf.ToArray();

        public void Reset()
        {
            _buf.SetLength(0);
            Started = false;
        }

        public bool IsComplete()
        {
            byte[] data = _buf.ToArray();
            int headerEnd = IndexOf(data, new byte[] { (byte)'\r', (byte)'\n', (byte)'\r', (byte)'\n' });
            int sepLen = 4;
            if (headerEnd < 0)
            {
                headerEnd = IndexOf(data, new byte[] { (byte)'\n', (byte)'\n' });
                sepLen = 2;
            }
            if (headerEnd < 0) return false;

            string head = Latin1.GetString(data, 0, headerEnd);
            int bodyStart = headerEnd + sepLen;
            int bodyLen = data.Length - bodyStart;

            string te = HttpBodyCodec.HeaderValue(head, "Transfer-Encoding");
            if (!string.IsNullOrEmpty(te) && te.ToLowerInvariant().Contains("chunked"))
                return ChunkedComplete(data, bodyStart);

            string cl = HttpBodyCodec.HeaderValue(head, "Content-Length");
            if (!string.IsNullOrEmpty(cl))
            {
                if (long.TryParse(cl.Trim(), out long want)) return bodyLen >= want;
                return true;
            }

            string firstLine = head.Split('\n')[0].TrimEnd('\r');
            if (firstLine.StartsWith("HTTP/"))
            {
                string code = StatusOf(firstLine);
                if (code.StartsWith("1") || code == "204" || code == "304") return true;
                return true; // no length indicator: best-effort complete at headers
            }
            return true; // request line, no body expected
        }

        private static string StatusOf(string statusLine)
        {
            string[] parts = statusLine.Split(' ');
            return parts.Length >= 2 ? parts[1].Trim() : "";
        }

        private static bool ChunkedComplete(byte[] data, int bodyStart)
        {
            int pos = bodyStart, n = data.Length;
            while (pos < n && (data[pos] == '\r' || data[pos] == '\n')) pos++;
            while (pos < n)
            {
                int lineEnd = pos;
                while (lineEnd < n && data[lineEnd] != '\n') lineEnd++;
                if (lineEnd >= n) return false;
                string sizeLine = Latin1.GetString(data, pos, lineEnd - pos).Trim();
                int semi = sizeLine.IndexOf(';');
                if (semi >= 0) sizeLine = sizeLine.Substring(0, semi).Trim();
                if (sizeLine.Length == 0) { pos = lineEnd + 1; continue; }
                int chunkSize;
                try { chunkSize = Convert.ToInt32(sizeLine, 16); }
                catch { return true; }
                if (chunkSize == 0) return true;
                pos = lineEnd + 1 + chunkSize;
                while (pos < n && (data[pos] == '\r' || data[pos] == '\n')) pos++;
            }
            return false;
        }

        private static int IndexOf(byte[] data, byte[] pattern)
        {
            for (int i = 0; i <= data.Length - pattern.Length; i++)
            {
                bool ok = true;
                for (int j = 0; j < pattern.Length; j++)
                    if (data[i + j] != pattern[j]) { ok = false; break; }
                if (ok) return i;
            }
            return -1;
        }
    }
}
