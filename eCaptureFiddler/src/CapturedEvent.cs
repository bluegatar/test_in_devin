using System;
using System.Text;
using System.Text.RegularExpressions;

namespace ECaptureFiddler.Core
{
    public enum Direction { Write, Read, Connect, None }

    /// <summary>
    /// One captured HTTP event from eCapture. In eCaptureQ text mode the event
    /// payload is prefixed by an eCapture header line, e.g.
    /// <c>[ts] PID:24394, Comm:guvideo, TID:24499, FD:152, WRITE (1457 bytes):\n&lt;HTTP&gt;</c>.
    /// We parse the header to get the direction (WRITE=request, READ=response)
    /// and PID/TID, then strip it so <see cref="Payload"/> is the raw HTTP bytes.
    /// </summary>
    public sealed class CapturedEvent
    {
        private static readonly Encoding Latin1 = Encoding.GetEncoding("ISO-8859-1");
        private static readonly Regex PidRe = new Regex(@"PID:(\d+)", RegexOptions.Compiled);
        private static readonly Regex TidRe = new Regex(@"TID:(\d+)", RegexOptions.Compiled);
        private static readonly Regex CommRe = new Regex(@"Comm:([^,\s]+)", RegexOptions.Compiled);

        public long Timestamp { get; }
        public string DstIp { get; }
        public int DstPort { get; }
        public long Pid { get; private set; }
        public long Tid { get; private set; }
        public string ProcessName { get; private set; }
        public Direction Direction { get; }
        public bool IsConnectionEvent => Direction == Direction.Connect;
        public byte[] Payload { get; }

        public string ConnKey => Pid + "_" + Tid;
        public int Length => Payload?.Length ?? 0;

        /// <summary>Build from a raw eCapture event (header still attached).</summary>
        public CapturedEvent(long timestamp, string dstIp, int dstPort, long pid,
                             string processName, byte[] rawPayload)
        {
            Timestamp = timestamp;
            DstIp = dstIp;
            DstPort = dstPort;
            Pid = pid;
            Tid = 0;
            ProcessName = processName;

            var ph = ParseHeader(rawPayload);
            Direction = ph.Direction;
            Payload = ph.Body;
            if (ph.Pid >= 0) Pid = ph.Pid;
            if (ph.Tid >= 0) Tid = ph.Tid;
            if (!string.IsNullOrEmpty(ph.Comm)) ProcessName = ph.Comm;
        }

        /// <summary>Build from a fully reassembled HTTP message (no header).</summary>
        private CapturedEvent(long timestamp, string dstIp, int dstPort, long pid, long tid,
                              string processName, bool response, byte[] httpBytes)
        {
            Timestamp = timestamp;
            DstIp = dstIp;
            DstPort = dstPort;
            Pid = pid;
            Tid = tid;
            ProcessName = processName;
            Direction = response ? Direction.Read : Direction.Write;
            Payload = httpBytes ?? Array.Empty<byte>();
        }

        public static CapturedEvent Assembled(long ts, string dstIp, int dstPort, long pid,
                                              long tid, string proc, bool response, byte[] httpBytes)
        {
            return new CapturedEvent(ts, dstIp, dstPort, pid, tid, proc, response, httpBytes);
        }

        private sealed class ParsedHeader
        {
            public Direction Direction = Direction.None;
            public long Pid = -1;
            public long Tid = -1;
            public string Comm;
            public byte[] Body;
        }

        private static ParsedHeader ParseHeader(byte[] raw)
        {
            var ph = new ParsedHeader();
            if (raw == null || raw.Length == 0)
            {
                ph.Body = raw ?? Array.Empty<byte>();
                return ph;
            }

            int nl = -1;
            int scan = Math.Min(raw.Length, 512);
            for (int i = 0; i < scan; i++)
            {
                if (raw[i] == (byte)'\n') { nl = i; break; }
            }

            string firstLine = Latin1.GetString(raw, 0, nl >= 0 ? nl : raw.Length);
            bool looksLikeHeader = firstLine.Contains("PID:")
                && (firstLine.Contains("WRITE") || firstLine.Contains("READ") || firstLine.Contains("Tuple:"));

            if (!looksLikeHeader)
            {
                ph.Body = raw;
                return ph;
            }

            var mPid = PidRe.Match(firstLine);
            if (mPid.Success) ph.Pid = long.Parse(mPid.Groups[1].Value);
            var mTid = TidRe.Match(firstLine);
            if (mTid.Success) ph.Tid = long.Parse(mTid.Groups[1].Value);
            var mComm = CommRe.Match(firstLine);
            if (mComm.Success) ph.Comm = mComm.Groups[1].Value;

            if (firstLine.Contains("Tuple:") && !firstLine.Contains("WRITE") && !firstLine.Contains("READ"))
                ph.Direction = Direction.Connect;
            else if (firstLine.Contains("WRITE"))
                ph.Direction = Direction.Write;
            else if (firstLine.Contains("READ"))
                ph.Direction = Direction.Read;

            int bodyStart = nl >= 0 ? nl + 1 : raw.Length;
            int len = Math.Max(0, raw.Length - bodyStart);
            var body = new byte[len];
            if (len > 0) Array.Copy(raw, bodyStart, body, 0, len);
            ph.Body = body;
            return ph;
        }

        public bool StartsHttpMessage()
        {
            if (Payload == null || Payload.Length < 4) return false;
            string s = Latin1.GetString(Payload, 0, Math.Min(Payload.Length, 20));
            if (s.StartsWith("HTTP/")) return true;
            return s.StartsWith("GET ") || s.StartsWith("POST ") || s.StartsWith("PUT ")
                || s.StartsWith("DELETE ") || s.StartsWith("HEAD ") || s.StartsWith("OPTIONS ")
                || s.StartsWith("PATCH ") || s.StartsWith("CONNECT ") || s.StartsWith("TRACE ");
        }

        public bool IsRequestStart()
        {
            if (Payload == null || Payload.Length < 4) return false;
            string s = Latin1.GetString(Payload, 0, Math.Min(Payload.Length, 20));
            return !s.StartsWith("HTTP/") && StartsHttpMessage();
        }

        public string GetHttpMethod()
        {
            if (Payload == null || Payload.Length == 0) return "-";
            string s = Latin1.GetString(Payload, 0, Math.Min(Payload.Length, 40));
            int sp = s.IndexOf(' ');
            return (sp > 0 && sp < 10) ? s.Substring(0, sp) : "-";
        }

        public string GetUrl()
        {
            if (Payload == null || Payload.Length == 0) return "-";
            string s = Latin1.GetString(Payload, 0, Math.Min(Payload.Length, 2048));
            int first = s.IndexOf(' ');
            if (first > 0)
            {
                int second = s.IndexOf(' ', first + 1);
                if (second > first) return s.Substring(first + 1, second - first - 1);
            }
            return "-";
        }

        public string GetStatusCode()
        {
            if (Payload == null || Payload.Length == 0) return "-";
            string s = Latin1.GetString(Payload, 0, Math.Min(Payload.Length, 40));
            int first = s.IndexOf(' ');
            if (first > 0)
            {
                int second = s.IndexOf(' ', first + 1);
                int end = second > first ? second : Math.Min(s.Length, first + 4);
                if (end > first + 1) return s.Substring(first + 1, end - first - 1).Trim();
            }
            return "-";
        }

        public string GetHost()
        {
            if (Payload == null || Payload.Length == 0) return DstIp;
            string s = Latin1.GetString(Payload, 0, Math.Min(Payload.Length, 4096));
            string key = "Host:";
            int idx = s.IndexOf(key, StringComparison.OrdinalIgnoreCase);
            if (idx >= 0)
            {
                int start = idx + key.Length;
                int end = s.IndexOf('\r', start);
                if (end == -1) end = s.IndexOf('\n', start);
                if (end > start) return s.Substring(start, end - start).Trim();
            }
            return DstIp;
        }
    }
}
