using System;

namespace ECaptureFiddler.Core
{
    public sealed class MatchedHttpPair
    {
        public string Id { get; }
        public CapturedEvent Request { get; private set; }
        public CapturedEvent Response { get; private set; }
        public long CreatedAt { get; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        public bool Injected { get; set; }

        public MatchedHttpPair(string id) { Id = id; }

        public void SetRequest(CapturedEvent r) { Request = r; }
        public void SetResponse(CapturedEvent r) { Response = r; }

        public bool HasRequest => Request != null;
        public bool HasResponse => Response != null;
        public bool IsComplete => HasRequest && HasResponse;

        public string Method => Request != null ? Request.GetHttpMethod() : "-";
        public string Url => Request != null ? Request.GetUrl() : "-";
        public string Host => Request != null ? Request.GetHost() : (Response != null ? Response.DstIp : "-");
        public string StatusCode => Response != null ? Response.GetStatusCode() : "-";
        public int RequestLength => Request?.Length ?? 0;
        public int ResponseLength => Response?.Length ?? 0;
        public string ProcessInfo => Request != null ? Request.ProcessName : (Response != null ? Response.ProcessName : "");
        public long TimestampSeconds => Request?.Timestamp ?? Response?.Timestamp ?? 0;

        public int Port
        {
            get
            {
                int p = Request?.DstPort ?? Response?.DstPort ?? 0;
                return p > 0 ? p : 443;
            }
        }

        public bool IsHttps => Port == 443 || Port == 8443;
    }
}
