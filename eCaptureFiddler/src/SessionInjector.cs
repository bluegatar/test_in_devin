using System;
using System.IO;
using System.Reflection;
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

        // Wired by the extension so diagnostics show up in the in-panel Debug Log.
        internal static Action<string> Log;

        private static void LogLine(string s)
        {
            try { Log?.Invoke(s); } catch { }
            try { FiddlerApplication.Log.LogString(s); } catch { }
        }

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
                TrySetBitFlags(oS);
                oS.oFlags["x-source"] = "eCapture";
                if (https) oS.oFlags["x-ecapture-https"] = "1";

                LoadIntoUi(oS);
            }
            catch (Exception ex)
            {
                LogLine("eCapture inject error: " + ex.Message);
            }
        }

        // Mark the session as imported (so Fiddler won't try to re-issue it).
        // The flag API differs across Fiddler versions (SetBitFlag method vs.
        // BitFlags property), so set it reflectively and never fail if absent.
        private static void TrySetBitFlags(Session oS)
        {
            const SessionFlags want = SessionFlags.ImportedFromOtherTool | SessionFlags.LoadedFromSAZ;
            try
            {
                Type t = oS.GetType();
                MethodInfo setBit = t.GetMethod("SetBitFlag", new[] { typeof(SessionFlags), typeof(bool) });
                if (setBit != null)
                {
                    setBit.Invoke(oS, new object[] { want, true });
                    return;
                }
                MemberInfo[] bf = t.GetMember("BitFlags", BindingFlags.Public | BindingFlags.Instance);
                foreach (var m in bf)
                {
                    if (m is PropertyInfo pi && pi.CanRead && pi.CanWrite)
                    {
                        var cur = (SessionFlags)pi.GetValue(oS, null);
                        pi.SetValue(oS, cur | want, null);
                        return;
                    }
                    if (m is FieldInfo fi)
                    {
                        var cur = (SessionFlags)fi.GetValue(oS);
                        fi.SetValue(oS, cur | want);
                        return;
                    }
                }
            }
            catch { /* cosmetic flag; ignore if unavailable */ }
        }

        // Add the synthetic session to Fiddler's Web Sessions list. The API
        // differs across versions: current Fiddler Classic (5.x) exposes the
        // public instance method frmViewer.addSession(Session); older builds had
        // actLoadSessions(Session[]). We resolve by EXACT, known-good method
        // names only — never a generic "any method taking Session[]" fallback,
        // because that previously picked ChangeGlobal/an export method and
        // popped a "Select Export Format" dialog on every captured packet.
        private static MethodInfo _loadMethod;
        private static bool _loadResolved;
        private static bool _loadIsArray;  // true: param is Session[]; false: single Session
        private static bool _logged;

        // Exact method names that add a session to the list (case-sensitive match
        // first, then case-insensitive). Single-Session adders are preferred for
        // modern Fiddler; the Session[] loader covers older builds.
        private static readonly string[] SingleSessionAdders =
            { "addSession", "AddReportedSession", "AddSessionToTreeView", "addSessionToList" };
        private static readonly string[] ArrayLoaders =
            { "actLoadSessions", "LoadSessions", "ImportSessions" };

        private static void LoadIntoUi(Session oS)
        {
            object ui = FiddlerApplication.UI;
            if (ui == null) return;
            MethodInfo mi = ResolveLoadMethod(ui.GetType());
            if (!_logged)
            {
                _logged = true;
                LogLine("eCapture: UI type = " + ui.GetType().FullName);
                LogLine("eCapture: Session[] candidates = " + DescribeCandidates(ui.GetType()));
                LogLine(mi != null
                    ? "eCapture: injecting via UI." + mi.Name + (_loadIsArray ? "(Session[])" : "(Session)")
                    : "eCapture: NO known session-add method found (not injecting).");
            }
            if (mi == null) return;
            object arg = _loadIsArray ? (object)new[] { oS } : oS;
            mi.Invoke(ui, new object[] { arg });
            try { oS.RefreshUI(); } catch { }
        }

        // For diagnostics: list UI methods taking a single Session or Session[].
        private static string DescribeCandidates(Type uiType)
        {
            var sb = new StringBuilder();
            foreach (var m in uiType.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance))
            {
                ParameterInfo[] ps = m.GetParameters();
                if (ps.Length != 1) continue;
                Type pt = ps[0].ParameterType;
                bool arr = pt == typeof(Session[]);
                bool one = pt == typeof(Session);
                if (!arr && !one) continue;
                sb.Append(m.IsPublic ? "" : "[np]").Append(m.Name)
                  .Append(arr ? "(Session[]) " : "(Session) ");
            }
            return sb.Length == 0 ? "(none)" : sb.ToString();
        }

        private static MethodInfo ResolveLoadMethod(Type uiType)
        {
            if (_loadResolved) return _loadMethod;
            _loadResolved = true;

            // Include non-public methods (full trust inside Fiddler), but only
            // accept the exact known-good names above.
            MethodInfo[] methods = uiType.GetMethods(
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);

            // Prefer the single-Session adder used by modern Fiddler Classic.
            MethodInfo m1 = PickExact(methods, SingleSessionAdders, typeof(Session));
            if (m1 != null) { _loadMethod = m1; _loadIsArray = false; return _loadMethod; }

            MethodInfo m2 = PickExact(methods, ArrayLoaders, typeof(Session[]));
            if (m2 != null) { _loadMethod = m2; _loadIsArray = true; return _loadMethod; }

            _loadMethod = null;
            return _loadMethod;
        }

        private static MethodInfo PickExact(MethodInfo[] methods, string[] names, Type paramType)
        {
            // Case-sensitive pass first, then case-insensitive.
            for (int pass = 0; pass < 2; pass++)
            {
                var cmp = pass == 0 ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
                foreach (var want in names)
                {
                    foreach (var m in methods)
                    {
                        if (!string.Equals(m.Name, want, cmp)) continue;
                        ParameterInfo[] ps = m.GetParameters();
                        if (ps.Length == 1 && ps[0].ParameterType == paramType)
                            return m;
                    }
                }
            }
            return null;
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
