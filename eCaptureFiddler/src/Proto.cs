using System;
using System.Text;

namespace ECaptureFiddler.Core
{
    /// <summary>
    /// Minimal protobuf (proto3) wire-format reader. Hand-rolled so the
    /// extension has zero external dependencies (a single drop-in DLL).
    /// Only the field types used by the eCaptureQ schema are supported.
    /// </summary>
    internal sealed class ProtoReader
    {
        private readonly byte[] _buf;
        private int _pos;
        private readonly int _end;

        public ProtoReader(byte[] buf) : this(buf, 0, buf.Length) { }

        public ProtoReader(byte[] buf, int offset, int length)
        {
            _buf = buf;
            _pos = offset;
            _end = offset + length;
        }

        public bool HasMore => _pos < _end;

        public ulong ReadVarint()
        {
            ulong result = 0;
            int shift = 0;
            while (_pos < _end)
            {
                byte b = _buf[_pos++];
                result |= (ulong)(b & 0x7F) << shift;
                if ((b & 0x80) == 0) break;
                shift += 7;
            }
            return result;
        }

        public int ReadTag()
        {
            if (_pos >= _end) return 0;
            return (int)ReadVarint();
        }

        public string ReadString()
        {
            int len = (int)ReadVarint();
            string s = Encoding.UTF8.GetString(_buf, _pos, len);
            _pos += len;
            return s;
        }

        public byte[] ReadBytes()
        {
            int len = (int)ReadVarint();
            byte[] b = new byte[len];
            Array.Copy(_buf, _pos, b, 0, len);
            _pos += len;
            return b;
        }

        /// <summary>Returns a reader scoped to a length-delimited sub-message.</summary>
        public ProtoReader ReadMessage()
        {
            int len = (int)ReadVarint();
            var sub = new ProtoReader(_buf, _pos, len);
            _pos += len;
            return sub;
        }

        /// <summary>Skip a field whose contents we don't care about.</summary>
        public void SkipField(int wireType)
        {
            switch (wireType)
            {
                case 0: ReadVarint(); break;
                case 1: _pos += 8; break;
                case 2: { int len = (int)ReadVarint(); _pos += len; break; }
                case 5: _pos += 4; break;
                default: throw new InvalidOperationException("Unknown wire type " + wireType);
            }
        }

        public static int FieldNumber(int tag) => tag >> 3;
        public static int WireType(int tag) => tag & 0x07;
    }

    internal enum LogType
    {
        Heartbeat = 0,
        ProcessLog = 1,
        Event = 2
    }

    internal sealed class EcaptureEvent
    {
        public long Timestamp;
        public string Uuid = "";
        public string SrcIp = "";
        public uint SrcPort;
        public string DstIp = "";
        public uint DstPort;
        public long Pid;
        public string Pname = "";
        public uint Type;
        public uint Length;
        public byte[] Payload = Array.Empty<byte>();
    }

    internal sealed class Heartbeat
    {
        public long Timestamp;
        public long Count;
        public string Message = "";
    }

    internal sealed class LogEntry
    {
        public LogType LogType;
        public EcaptureEvent Event;
        public Heartbeat Heartbeat;
        public string RunLog;

        public static LogEntry Parse(byte[] data)
        {
            var entry = new LogEntry();
            var r = new ProtoReader(data);
            while (r.HasMore)
            {
                int tag = r.ReadTag();
                if (tag == 0) break;
                int field = ProtoReader.FieldNumber(tag);
                int wt = ProtoReader.WireType(tag);
                switch (field)
                {
                    case 1: entry.LogType = (LogType)r.ReadVarint(); break;
                    case 2: entry.Event = ParseEvent(r.ReadMessage()); break;
                    case 3: entry.Heartbeat = ParseHeartbeat(r.ReadMessage()); break;
                    case 4: entry.RunLog = r.ReadString(); break;
                    default: r.SkipField(wt); break;
                }
            }
            return entry;
        }

        private static EcaptureEvent ParseEvent(ProtoReader r)
        {
            var e = new EcaptureEvent();
            while (r.HasMore)
            {
                int tag = r.ReadTag();
                if (tag == 0) break;
                int field = ProtoReader.FieldNumber(tag);
                int wt = ProtoReader.WireType(tag);
                switch (field)
                {
                    case 1: e.Timestamp = (long)r.ReadVarint(); break;
                    case 2: e.Uuid = r.ReadString(); break;
                    case 3: e.SrcIp = r.ReadString(); break;
                    case 4: e.SrcPort = (uint)r.ReadVarint(); break;
                    case 5: e.DstIp = r.ReadString(); break;
                    case 6: e.DstPort = (uint)r.ReadVarint(); break;
                    case 7: e.Pid = (long)r.ReadVarint(); break;
                    case 8: e.Pname = r.ReadString(); break;
                    case 9: e.Type = (uint)r.ReadVarint(); break;
                    case 10: e.Length = (uint)r.ReadVarint(); break;
                    case 11: e.Payload = r.ReadBytes(); break;
                    default: r.SkipField(wt); break;
                }
            }
            return e;
        }

        private static Heartbeat ParseHeartbeat(ProtoReader r)
        {
            var h = new Heartbeat();
            while (r.HasMore)
            {
                int tag = r.ReadTag();
                if (tag == 0) break;
                int field = ProtoReader.FieldNumber(tag);
                int wt = ProtoReader.WireType(tag);
                switch (field)
                {
                    case 1: h.Timestamp = (long)r.ReadVarint(); break;
                    case 2: h.Count = (long)r.ReadVarint(); break;
                    case 3: h.Message = r.ReadString(); break;
                    default: r.SkipField(wt); break;
                }
            }
            return h;
        }
    }
}
