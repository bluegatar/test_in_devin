using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Text;

namespace ECaptureFiddler.Core
{
    /// <summary>
    /// Decodes raw HTTP bytes captured by eCapture into plaintext: removes
    /// Transfer-Encoding: chunked framing and recursively decompresses common
    /// Content-Encodings (gzip / deflate(zlib) / br) until the body is no
    /// longer a recognised compression format.
    ///
    /// eCapture text mode forwards raw SSL_read bytes without any decoding, so
    /// gzipped/chunked bodies arrive verbatim and must be decoded here.
    /// </summary>
    public static class HttpBodyCodec
    {
        private static readonly Encoding Latin1 = Encoding.GetEncoding("ISO-8859-1");
        private static readonly byte[] CrlfCrlf = { (byte)'\r', (byte)'\n', (byte)'\r', (byte)'\n' };
        private static readonly byte[] LfLf = { (byte)'\n', (byte)'\n' };

        public static byte[] DecodeHttpMessage(byte[] rawHttp)
        {
            if (rawHttp == null || rawHttp.Length == 0) return rawHttp;
            try
            {
                int sep = IndexOf(rawHttp, CrlfCrlf, 0);
                int sepLen = 4;
                if (sep < 0) { sep = IndexOf(rawHttp, LfLf, 0); sepLen = 2; }
                if (sep < 0) return rawHttp;

                var head = new byte[sep];
                Array.Copy(rawHttp, 0, head, 0, sep);
                int bodyStart = sep + sepLen;
                var body = new byte[rawHttp.Length - bodyStart];
                Array.Copy(rawHttp, bodyStart, body, 0, body.Length);

                string headStr = Latin1.GetString(head);
                string te = HeaderValue(headStr, "Transfer-Encoding");
                string ce = HeaderValue(headStr, "Content-Encoding");

                if (string.IsNullOrEmpty(te) && string.IsNullOrEmpty(ce) && !LooksCompressed(body))
                    return rawHttp;

                byte[] decoded = DecodeBody(body, te, ce);
                string newHead = RewriteHeaders(headStr, decoded.Length);
                byte[] newHeadBytes = Latin1.GetBytes(newHead);

                using (var outMs = new MemoryStream(newHeadBytes.Length + 4 + decoded.Length))
                {
                    outMs.Write(newHeadBytes, 0, newHeadBytes.Length);
                    outMs.WriteByte((byte)'\r'); outMs.WriteByte((byte)'\n');
                    outMs.WriteByte((byte)'\r'); outMs.WriteByte((byte)'\n');
                    outMs.Write(decoded, 0, decoded.Length);
                    return outMs.ToArray();
                }
            }
            catch
            {
                return rawHttp;
            }
        }

        public static byte[] DecodeBody(byte[] body, string transferEncoding, string contentEncoding)
        {
            if (body == null) return Array.Empty<byte>();
            byte[] data = body;

            if (!string.IsNullOrEmpty(transferEncoding) &&
                transferEncoding.ToLowerInvariant().Contains("chunked"))
            {
                data = Dechunk(data);
            }

            if (!string.IsNullOrEmpty(contentEncoding))
            {
                var tokens = contentEncoding.Split(',')
                    .Select(t => t.Trim().ToLowerInvariant())
                    .Where(t => t.Length > 0)
                    .ToList();
                for (int i = tokens.Count - 1; i >= 0; i--)
                    data = ApplyDecode(data, tokens[i]);
            }

            // Magic-byte loop: undeclared / stacked compression.
            for (int round = 0; round < 8; round++)
            {
                if (IsGzip(data))
                {
                    byte[] r = Gunzip(data);
                    if (r.Length == 0 || ByteEquals(r, data)) break;
                    data = r;
                }
                else if (IsZlib(data))
                {
                    byte[] r = Inflate(data, false);
                    if (r.Length == 0 || ByteEquals(r, data)) break;
                    data = r;
                }
                else break;
            }
            return data;
        }

        private static byte[] ApplyDecode(byte[] data, string token)
        {
            switch (token)
            {
                case "gzip":
                case "x-gzip": return Gunzip(data);
                case "deflate": return Inflate(data, false);
                case "br": return Brotli(data);
                default: return data;
            }
        }

        internal static byte[] Dechunk(byte[] input)
        {
            try
            {
                using (var outMs = new MemoryStream())
                {
                    int pos = 0, n = input.Length;
                    while (pos < n && (input[pos] == '\r' || input[pos] == '\n')) pos++;
                    while (pos < n)
                    {
                        int lineEnd = pos;
                        while (lineEnd < n && input[lineEnd] != '\n') lineEnd++;
                        if (lineEnd >= n) break;
                        string sizeLine = Latin1.GetString(input, pos, lineEnd - pos).Trim();
                        int semi = sizeLine.IndexOf(';');
                        if (semi >= 0) sizeLine = sizeLine.Substring(0, semi).Trim();
                        if (sizeLine.Length == 0) { pos = lineEnd + 1; continue; }
                        int chunkSize;
                        try { chunkSize = Convert.ToInt32(sizeLine, 16); }
                        catch { outMs.Write(input, pos, n - pos); break; }
                        pos = lineEnd + 1;
                        if (chunkSize == 0) break;
                        if (pos + chunkSize > n) { outMs.Write(input, pos, n - pos); break; }
                        outMs.Write(input, pos, chunkSize);
                        pos += chunkSize;
                        while (pos < n && (input[pos] == '\r' || input[pos] == '\n')) pos++;
                    }
                    return outMs.ToArray();
                }
            }
            catch { return input; }
        }

        internal static bool IsGzip(byte[] d) =>
            d != null && d.Length >= 3 && d[0] == 0x1F && d[1] == 0x8B && d[2] == 0x08;

        internal static bool IsZlib(byte[] d)
        {
            if (d == null || d.Length < 2) return false;
            int b0 = d[0], b1 = d[1];
            return b0 == 0x78 && ((b0 << 8 | b1) % 31 == 0);
        }

        private static bool LooksCompressed(byte[] d) => IsGzip(d) || IsZlib(d);

        internal static byte[] Gunzip(byte[] input)
        {
            if (input == null || input.Length == 0) return Array.Empty<byte>();
            try
            {
                using (var inMs = new MemoryStream(input))
                using (var gz = new GZipStream(inMs, CompressionMode.Decompress))
                    return ReadAll(gz);
            }
            catch
            {
                // Lenient: eCapture may truncate. Skip 10-byte header, raw inflate.
                if (input.Length <= 10) return input;
                var deflated = new byte[input.Length - 10];
                Array.Copy(input, 10, deflated, 0, deflated.Length);
                byte[] partial = Inflate(deflated, true);
                return partial.Length > 0 ? partial : input;
            }
        }

        internal static byte[] Inflate(byte[] input, bool nowrap)
        {
            if (input == null || input.Length == 0) return Array.Empty<byte>();
            // .NET DeflateStream handles raw deflate (RFC1951). zlib (RFC1950)
            // has a 2-byte header we must skip when nowrap == false.
            byte[] data = input;
            if (!nowrap && input.Length >= 2 && input[0] == 0x78)
            {
                data = new byte[input.Length - 2];
                Array.Copy(input, 2, data, 0, data.Length);
            }
            try
            {
                using (var inMs = new MemoryStream(data))
                using (var df = new DeflateStream(inMs, CompressionMode.Decompress))
                {
                    byte[] r = ReadAll(df);
                    if (r.Length > 0) return r;
                }
            }
            catch { /* fall through */ }

            if (!nowrap && data != input)
            {
                // Retry treating the whole thing as raw deflate.
                try
                {
                    using (var inMs = new MemoryStream(input))
                    using (var df = new DeflateStream(inMs, CompressionMode.Decompress))
                        return ReadAll(df);
                }
                catch { }
            }
            return Array.Empty<byte>();
        }

        // BrotliStream only exists on .NET Core / .NET 5+. Resolve it via
        // reflection so this file still compiles for .NET Framework 4.8 (where
        // brotli is simply unavailable and the input is returned unchanged).
        private static readonly Type BrotliStreamType =
            Type.GetType("System.IO.Compression.BrotliStream, System.IO.Compression.Brotli")
            ?? Type.GetType("System.IO.Compression.BrotliStream, System.IO.Compression");

        internal static byte[] Brotli(byte[] input)
        {
            if (input == null || input.Length == 0) return Array.Empty<byte>();
            if (BrotliStreamType == null) return input; // unsupported on this runtime
            try
            {
                using (var inMs = new MemoryStream(input))
                {
                    var ctor = BrotliStreamType.GetConstructor(new[] { typeof(Stream), typeof(CompressionMode) });
                    using (var br = (Stream)ctor.Invoke(new object[] { inMs, CompressionMode.Decompress }))
                        return ReadAll(br);
                }
            }
            catch { return input; }
        }

        private static byte[] ReadAll(Stream s)
        {
            using (var outMs = new MemoryStream())
            {
                var buf = new byte[8192];
                try
                {
                    int r;
                    while ((r = s.Read(buf, 0, buf.Length)) > 0)
                        outMs.Write(buf, 0, r);
                }
                catch { /* keep partial output on truncated streams */ }
                return outMs.ToArray();
            }
        }

        public static string HeaderValue(string head, string name)
        {
            if (head == null) return "";
            string lname = name.ToLowerInvariant();
            foreach (var line in head.Split('\n'))
            {
                string l = line.TrimEnd('\r');
                int colon = l.IndexOf(':');
                if (colon <= 0) continue;
                if (l.Substring(0, colon).Trim().ToLowerInvariant() == lname)
                    return l.Substring(colon + 1).Trim();
            }
            return "";
        }

        private static string RewriteHeaders(string head, int newLength)
        {
            string[] lines = head.Replace("\r\n", "\n").Split('\n');
            var sb = new StringBuilder();
            bool wroteCl = false;
            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i];
                if (i == 0) { sb.Append(line); continue; }
                int colon = line.IndexOf(':');
                string key = colon > 0 ? line.Substring(0, colon).Trim().ToLowerInvariant() : "";
                if (key == "transfer-encoding" || key == "content-encoding") continue;
                if (key == "content-length")
                {
                    sb.Append("\r\n").Append("Content-Length: ").Append(newLength);
                    wroteCl = true;
                    continue;
                }
                if (line.Length == 0) continue;
                sb.Append("\r\n").Append(line);
            }
            if (!wroteCl) sb.Append("\r\n").Append("Content-Length: ").Append(newLength);
            return sb.ToString();
        }

        private static bool ByteEquals(byte[] a, byte[] b)
        {
            if (a == b) return true;
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        private static int IndexOf(byte[] data, byte[] pattern, int from)
        {
            for (int i = Math.Max(0, from); i <= data.Length - pattern.Length; i++)
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
