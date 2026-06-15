using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using ECaptureFiddler.Core;

class Program
{
    static int _pass = 0, _fail = 0;
    static readonly Encoding Latin1 = Encoding.GetEncoding("ISO-8859-1");

    static void Check(string name, bool ok, string detail = "")
    {
        if (ok) { _pass++; Console.WriteLine("  PASS  " + name); }
        else { _fail++; Console.WriteLine("  FAIL  " + name + "  " + detail); }
    }

    static byte[] Gzip(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, true)) gz.Write(data, 0, data.Length);
        return ms.ToArray();
    }

    static byte[] Deflate(byte[] data)
    {
        // zlib wrapper: 0x78 0x9C + raw deflate + adler32
        using var raw = new MemoryStream();
        using (var df = new DeflateStream(raw, CompressionMode.Compress, true)) df.Write(data, 0, data.Length);
        byte[] rawDeflate = raw.ToArray();
        uint a = Adler32(data);
        using var ms = new MemoryStream();
        ms.WriteByte(0x78); ms.WriteByte(0x9C);
        ms.Write(rawDeflate, 0, rawDeflate.Length);
        ms.WriteByte((byte)(a >> 24)); ms.WriteByte((byte)(a >> 16));
        ms.WriteByte((byte)(a >> 8)); ms.WriteByte((byte)a);
        return ms.ToArray();
    }

    static uint Adler32(byte[] data)
    {
        const uint MOD = 65521;
        uint a = 1, b = 0;
        foreach (var t in data) { a = (a + t) % MOD; b = (b + a) % MOD; }
        return (b << 16) | a;
    }

    static byte[] Concat(params byte[][] arrs)
    {
        using var ms = new MemoryStream();
        foreach (var x in arrs) ms.Write(x, 0, x.Length);
        return ms.ToArray();
    }

    static byte[] B(string s) => Latin1.GetBytes(s);

    static void CodecTests()
    {
        Console.WriteLine("== Codec tests ==");
        string text = "{\"hello\":\"world\",\"n\":12345,\"arr\":[1,2,3,4,5]}";
        byte[] plain = B(text);

        // 1. gzip via Content-Encoding
        {
            byte[] body = Gzip(plain);
            byte[] msg = Concat(B("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: " + body.Length + "\r\n\r\n"), body);
            byte[] dec = HttpBodyCodec.DecodeHttpMessage(msg);
            string s = Latin1.GetString(dec);
            Check("gzip Content-Encoding", s.Contains(text) && !s.Contains("Content-Encoding"), s);
        }
        // 2. chunked + gzip
        {
            byte[] gz = Gzip(plain);
            byte[] chunk = Concat(B(gz.Length.ToString("x") + "\r\n"), gz, B("\r\n0\r\n\r\n"));
            byte[] msg = Concat(B("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n"), chunk);
            byte[] dec = HttpBodyCodec.DecodeHttpMessage(msg);
            Check("chunked+gzip", Latin1.GetString(dec).Contains(text));
        }
        // 3. leading CRLF + chunked + gzip (the user's 0D 0A 1F 8B case)
        {
            byte[] gz = Gzip(plain);
            byte[] chunk = Concat(B("\r\n" + gz.Length.ToString("x") + "\r\n"), gz, B("\r\n0\r\n\r\n"));
            byte[] msg = Concat(B("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"), chunk);
            byte[] dec = HttpBodyCodec.DecodeHttpMessage(msg);
            Check("leading-CRLF chunked+gzip (undeclared CE)", Latin1.GetString(dec).Contains(text));
        }
        // 4. nested gzip (gzip of gzip), undeclared
        {
            byte[] once = Gzip(plain);
            byte[] twice = Gzip(once);
            byte[] msg = Concat(B("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: " + twice.Length + "\r\n\r\n"), twice);
            byte[] dec = HttpBodyCodec.DecodeHttpMessage(msg);
            Check("nested gzip (recursive)", Latin1.GetString(dec).Contains(text));
        }
        // 5. deflate (zlib)
        {
            byte[] body = Deflate(plain);
            byte[] msg = Concat(B("HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\nContent-Length: " + body.Length + "\r\n\r\n"), body);
            byte[] dec = HttpBodyCodec.DecodeHttpMessage(msg);
            Check("deflate(zlib)", Latin1.GetString(dec).Contains(text));
        }
        // 6. plain unchanged
        {
            byte[] msg = Concat(B("HTTP/1.1 200 OK\r\nContent-Length: " + plain.Length + "\r\n\r\n"), plain);
            byte[] dec = HttpBodyCodec.DecodeHttpMessage(msg);
            Check("plain unchanged", Latin1.GetString(dec).Contains(text));
        }
        // 7. request without body
        {
            byte[] msg = B("GET /a/b HTTP/1.1\r\nHost: example.com\r\n\r\n");
            byte[] dec = HttpBodyCodec.DecodeHttpMessage(msg);
            Check("request no body", Latin1.GetString(dec).Contains("GET /a/b"));
        }
        // 8. result contains no gzip magic
        {
            byte[] gz = Gzip(plain);
            byte[] msg = Concat(B("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: " + gz.Length + "\r\n\r\n"), gz);
            byte[] dec = HttpBodyCodec.DecodeHttpMessage(msg);
            bool hasMagic = false;
            for (int i = 0; i < dec.Length - 2; i++)
                if (dec[i] == 0x1F && dec[i + 1] == 0x8B && dec[i + 2] == 0x08) { hasMagic = true; break; }
            Check("no gzip magic after decode", !hasMagic);
        }
    }

    static CapturedEvent Ev(string header, byte[] httpBody)
    {
        byte[] payload = Concat(B(header + "\n"), httpBody);
        return new CapturedEvent(0, "1.2.3.4", 443, 0, "x", payload);
    }

    static void ParseTests()
    {
        Console.WriteLine("== Parse tests ==");
        {
            var e = Ev("[ts] PID:24394, Comm:guvideo, TID:24499, FD:152, WRITE (50 bytes):",
                       B("GET /vms-match/v6/x HTTP/1.1\r\nHost: v1-sc.miguvideo.com\r\n\r\n"));
            Check("WRITE -> request direction", e.Direction == Direction.Write);
            Check("PID/TID extracted", e.ConnKey == "24394_24499", e.ConnKey);
            Check("Comm extracted", e.ProcessName == "guvideo");
            Check("method", e.GetHttpMethod() == "GET", e.GetHttpMethod());
            Check("url", e.GetUrl() == "/vms-match/v6/x", e.GetUrl());
            Check("host", e.GetHost() == "v1-sc.miguvideo.com", e.GetHost());
        }
        {
            var e = Ev("[ts] PID:24394, Comm:guvideo, TID:24499, FD:152, READ (16 bytes):",
                       B("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
            Check("READ -> response direction", e.Direction == Direction.Read);
            Check("status code", e.GetStatusCode() == "200", e.GetStatusCode());
        }
        {
            var e = Ev("PID:24394, Comm:sk_rpt, TID:24499, FD:152, Tuple: [1.2.3.4]:45620->[5.6.7.8]:11443.", B(""));
            Check("Tuple -> connection event ignored", e.IsConnectionEvent);
        }
    }

    static void ReassemblyTests()
    {
        Console.WriteLine("== Reassembly + pairing tests ==");
        // Content-Length response split into 3 READ fragments, one connection.
        {
            var em = new EventManager();
            MatchedHttpPair completed = null;
            em.PairUpdated += p => { if (p.IsComplete) completed = p; };

            string conn = "100, Comm:app, TID:200";
            em.ProcessEvent(Ev("PID:" + conn + ", FD:1, WRITE (n):",
                B("GET /big HTTP/1.1\r\nHost: h.com\r\n\r\n")));

            string respBody = new string('A', 30);
            byte[] head = B("HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\n");
            em.ProcessEvent(Ev("PID:" + conn + ", FD:1, READ (n):", Concat(head, B(respBody.Substring(0, 10)))));
            Check("not complete after fragment 1", completed == null);
            em.ProcessEvent(Ev("PID:" + conn + ", FD:1, READ (n):", B(respBody.Substring(10, 10))));
            // second/third fragments have no HTTP header; appended to buffer
            em.ProcessEvent(Ev("PID:" + conn + ", FD:1, READ (n):", B(respBody.Substring(20, 10))));
            Check("complete after Content-Length satisfied", completed != null && completed.IsComplete);
            if (completed != null)
                Check("response body reassembled", Latin1.GetString(completed.Response.Payload).Contains(respBody));
        }
        // Chunked response split across fragments.
        {
            var em = new EventManager();
            MatchedHttpPair completed = null;
            em.PairUpdated += p => { if (p.IsComplete) completed = p; };
            string conn = "101, Comm:app, TID:201";
            em.ProcessEvent(Ev("PID:" + conn + ", FD:1, WRITE (n):", B("GET /c HTTP/1.1\r\nHost: h.com\r\n\r\n")));
            em.ProcessEvent(Ev("PID:" + conn + ", FD:1, READ (n):", B("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello")));
            Check("chunked not complete mid-stream", completed == null);
            em.ProcessEvent(Ev("PID:" + conn + ", FD:1, READ (n):", B("\r\n0\r\n\r\n")));
            Check("chunked complete at terminator", completed != null);
        }
        // Two interleaved connections, out-of-order responses pair correctly.
        {
            var em = new EventManager();
            var done = new List<MatchedHttpPair>();
            em.PairUpdated += p => { if (p.IsComplete) done.Add(p); };
            em.ProcessEvent(Ev("PID:1, Comm:a, TID:1, FD:1, WRITE (n):", B("GET /A HTTP/1.1\r\nHost: a.com\r\n\r\n")));
            em.ProcessEvent(Ev("PID:2, Comm:b, TID:2, FD:1, WRITE (n):", B("GET /B HTTP/1.1\r\nHost: b.com\r\n\r\n")));
            // response for conn 2 arrives first
            em.ProcessEvent(Ev("PID:2, Comm:b, TID:2, FD:1, READ (n):", B("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")));
            em.ProcessEvent(Ev("PID:1, Comm:a, TID:1, FD:1, READ (n):", B("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")));
            bool ok = false;
            MatchedHttpPair a = done.Find(p => p.Url == "/A");
            MatchedHttpPair b = done.Find(p => p.Url == "/B");
            if (a != null && b != null)
                ok = a.StatusCode == "200" && b.StatusCode == "201";
            Check("out-of-order responses paired by connection", ok,
                a != null && b != null ? $"A={a.StatusCode} B={b.StatusCode}" : "missing pair");
        }
        // Connection (Tuple) events are ignored.
        {
            var em = new EventManager();
            em.ProcessEvent(Ev("PID:9, Comm:x, TID:9, FD:1, Tuple: [1]:2->[3]:4.", B("")));
            Check("connection event produces no pair", em.TotalPairs == 0);
        }
    }

    static int Main()
    {
        CodecTests();
        ParseTests();
        ReassemblyTests();
        Console.WriteLine();
        Console.WriteLine($"RESULT: {_pass} passed, {_fail} failed");
        return _fail == 0 ? 0 : 1;
    }
}
