using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

namespace ECaptureFiddler.Core
{
    /// <summary>
    /// Reassembles fragmented HTTP messages and pairs requests with responses
    /// by connection (PID_TID). Raises <see cref="PairUpdated"/> whenever a pair
    /// is created or its response completes. This class has no Fiddler
    /// dependency so it can be unit-tested standalone.
    /// </summary>
    public sealed class EventManager
    {
        private readonly object _lock = new object();
        private readonly Dictionary<string, MessageBuffer> _reqBuffers = new Dictionary<string, MessageBuffer>();
        private readonly Dictionary<string, MessageBuffer> _respBuffers = new Dictionary<string, MessageBuffer>();
        private readonly Dictionary<string, LinkedList<MatchedHttpPair>> _pendingByConn =
            new Dictionary<string, LinkedList<MatchedHttpPair>>();

        private long _pairSeq;
        public long TotalEvents { get; private set; }
        public long TotalPairs { get; private set; }
        public long HeartbeatCount { get; private set; }
        public DateTime LastHeartbeatUtc { get; private set; }

        /// <summary>Raised when a pair is created (request) or completed (response).</summary>
        public event Action<MatchedHttpPair> PairUpdated;
        /// <summary>Raised for eCapture run-log / debug lines.</summary>
        public event Action<string> Log;

        public void ProcessEvent(CapturedEvent ev)
        {
            lock (_lock)
            {
                TotalEvents++;
                if (ev.IsConnectionEvent) return;

                bool outbound = ev.Direction == Direction.Write;
                bool inbound = ev.Direction == Direction.Read;
                if (!outbound && !inbound)
                {
                    // Direction unknown: fall back to content sniffing.
                    if (ev.StartsHttpMessage())
                    {
                        string s = Encoding.ASCII.GetString(ev.Payload, 0, Math.Min(ev.Payload.Length, 8));
                        if (s.StartsWith("HTTP/")) inbound = true; else outbound = true;
                    }
                    else return;
                }

                if (outbound) HandleOutbound(ev.ConnKey, ev);
                else HandleInbound(ev.ConnKey, ev);
            }
        }

        private void HandleOutbound(string connKey, CapturedEvent ev)
        {
            var req = Get(_reqBuffers, connKey);
            if (ev.StartsHttpMessage())
            {
                if (req.Started && !req.IsEmpty) FinalizeRequest(connKey, req.ToBytes(), ev);
                req.Reset();
                req.Started = true;
                req.Append(ev.Payload);
            }
            else
            {
                if (!req.Started) return;
                req.Append(ev.Payload);
            }
            if (req.Started && req.IsComplete())
            {
                FinalizeRequest(connKey, req.ToBytes(), ev);
                req.Reset();
            }
        }

        private void HandleInbound(string connKey, CapturedEvent ev)
        {
            var resp = Get(_respBuffers, connKey);
            if (ev.StartsHttpMessage())
            {
                if (resp.Started && !resp.IsEmpty) FinalizeResponse(connKey, resp.ToBytes(), ev);
                resp.Reset();
                resp.Started = true;
                resp.Append(ev.Payload);
            }
            else
            {
                if (!resp.Started) return;
                resp.Append(ev.Payload);
            }
            if (resp.Started && resp.IsComplete())
            {
                FinalizeResponse(connKey, resp.ToBytes(), ev);
                resp.Reset();
            }
        }

        private void FinalizeRequest(string connKey, byte[] bytes, CapturedEvent src)
        {
            var reqEvent = CapturedEvent.Assembled(src.Timestamp, src.DstIp, src.DstPort,
                src.Pid, src.Tid, src.ProcessName, false, bytes);
            string url = reqEvent.GetUrl();
            string host = reqEvent.GetHost();
            if (url == "-" || url.Length == 0) return;
            if (string.IsNullOrEmpty(host) || host == "-" || host == "0.0.0.0") return;

            var pair = new MatchedHttpPair("pair_" + Interlocked.Increment(ref _pairSeq));
            pair.SetRequest(reqEvent);
            if (!_pendingByConn.TryGetValue(connKey, out var list))
            {
                list = new LinkedList<MatchedHttpPair>();
                _pendingByConn[connKey] = list;
            }
            list.AddLast(pair);
            TotalPairs++;
            Log?.Invoke($"[KEEP request] conn={connKey} {reqEvent.GetHttpMethod()} {host}{url} ({bytes.Length}B)");
            PairUpdated?.Invoke(pair);
        }

        private void FinalizeResponse(string connKey, byte[] bytes, CapturedEvent src)
        {
            var respEvent = CapturedEvent.Assembled(src.Timestamp, src.DstIp, src.DstPort,
                src.Pid, src.Tid, src.ProcessName, true, bytes);

            MatchedHttpPair pair = null;
            if (_pendingByConn.TryGetValue(connKey, out var list))
            {
                foreach (var p in list)
                {
                    if (!p.HasResponse) { pair = p; break; }
                }
            }
            if (pair == null)
            {
                Log?.Invoke($"[DROP response] conn={connKey} no pending request (status {respEvent.GetStatusCode()})");
                return;
            }
            pair.SetResponse(respEvent);
            Log?.Invoke($"[KEEP response] conn={connKey} status={respEvent.GetStatusCode()} ({bytes.Length}B)");
            PairUpdated?.Invoke(pair);
        }

        public void ProcessHeartbeat(long timestamp, long count, string message)
        {
            HeartbeatCount = count;
            LastHeartbeatUtc = DateTime.UtcNow;
            Log?.Invoke($"[HEARTBEAT] count={count}");
        }

        public void ProcessRuntimeLog(string log)
        {
            if (!string.IsNullOrEmpty(log)) Log?.Invoke("[eCapture] " + log.Trim());
        }

        public void Clear()
        {
            lock (_lock)
            {
                _reqBuffers.Clear();
                _respBuffers.Clear();
                _pendingByConn.Clear();
                TotalEvents = 0;
                TotalPairs = 0;
            }
        }

        public int PendingCount
        {
            get
            {
                lock (_lock)
                {
                    int c = 0;
                    foreach (var list in _pendingByConn.Values)
                        foreach (var p in list) if (!p.HasResponse) c++;
                    return c;
                }
            }
        }

        private static MessageBuffer Get(Dictionary<string, MessageBuffer> map, string key)
        {
            if (!map.TryGetValue(key, out var b)) { b = new MessageBuffer(); map[key] = b; }
            return b;
        }
    }
}
