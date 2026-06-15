using System;
using System.IO;
using System.Text;
using ECaptureFiddler.Core;
using Fiddler;

namespace ECaptureFiddler.Fiddler
{
    /// <summary>
    /// Builds a Fiddler <see cref="Session"/> from a matched request/response
    /// pair and injects it into the Fiddler session list. Bodies are decoded
    /// (de-chunked + decompressed) before injection so Fiddler shows plaintext.
    /// </summary>
    internal static class SessionInjector
    {
        private static readonly Encoding Latin1 = Encoding.GetEncoding("ISO-8859-1");

        public static void Inject(MatchedHttpPair pair)
        {
            if (pair == null || !pair.HasRequest) return;

            byte[] reqBytes = HttpBodyCodec.DecodeHttpMessage(pair.Request.Payload);
            byte[] respBytes = pair.HasResponse
                ? HttpBodyCodec.DecodeHttpMessage(pair.Response.Payload)
                : Latin1.GetBytes("HTTP/1.1 0 No Response\r\nContent-Length: 0\r\n\r\n");

            string host = pair.Host;
            bool https = pair.IsHttps;
            int port = pair.Port;

            // Rewrite an origin-form request target ("GET /path") into absolute
            // form ("GET https://host/path") so Fiddler shows scheme + host.
            reqBytes = MakeAbsoluteRequest(reqBytes, host, port, https);

            try
            {
                var oS = new Session(reqBytes, respBytes);
                TrySetFlag(oS, SessionFlags.ImportedFromOtherTool);
                TrySetFlag(oS, SessionFlags.LoadedFromSAZ);
                oS.oFlags["x-source"] = "eCapture";
                if (https) oS.oFlags["x-ecapture-https"] = "1";

                if (FiddlerApplication.UI != null)
                {
                    FiddlerApplication.UI.actLoadSessions(new[] { oS });
                    oS.RefreshUI();
                }
            }
            catch (Exception ex)
            {
                FiddlerApplication.Log.LogString("eCapture inject error: " + ex.Message);
            }
        }

        private static void TrySetFlag(Session oS, SessionFlags flag)
        {
            try { oS.SetBitFlag(flag, true); } catch { }
        }

        private static byte[] MakeAbsoluteRequest(byte[] reqBytes, string host, int port, bool https)
        {
            try
            {
                int sep = IndexOfCrlf(reqBytes);
                if (sep < 0) return reqBytes;
                string firstLine = Latin1.GetString(reqBytes, 0, sep);
                string[] parts = firstLine.Split(' ');
                if (parts.Length < 3) return reqBytes;
                string method = parts[0];
                string target = parts[1];
                string version = parts[2];
                if (target.StartsWith("http://") || target.StartsWith("https://"))
                    return reqBytes; // already absolute

                string scheme = https ? "https" : "http";
                string authority = host;
                if (port > 0 && port != 80 && port != 443)
                    authority = host + ":" + port;
                string absolute = scheme + "://" + authority + target;
                string newFirstLine = method + " " + absolute + " " + version;

                byte[] newHead = Latin1.GetBytes(newFirstLine);
                using (var ms = new MemoryStream())
                {
                    ms.Write(newHead, 0, newHead.Length);
                    ms.Write(reqBytes, sep, reqBytes.Length - sep);
                    return ms.ToArray();
                }
            }
            catch
            {
                return reqBytes;
            }
        }

        private static int IndexOfCrlf(byte[] data)
        {
            for (int i = 0; i < data.Length - 1; i++)
                if (data[i] == '\r' && data[i + 1] == '\n') return i;
            for (int i = 0; i < data.Length; i++)
                if (data[i] == '\n') return i;
            return -1;
        }
    }
}
