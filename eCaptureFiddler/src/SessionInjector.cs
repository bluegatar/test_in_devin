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

        // Add the synthetic session to Fiddler's Web Sessions list. The exact
        // method name on the main window has changed across Fiddler versions
        // (e.g. actLoadSessions), so resolve any public instance method that
        // takes a single Session[] argument and invoke it.
        private static MethodInfo _loadMethod;
        private static bool _loadResolved;

        private static bool _logged;

        private static void LoadIntoUi(Session oS)
        {
            object ui = FiddlerApplication.UI;
            if (ui == null) return;
            MethodInfo mi = ResolveLoadMethod(ui.GetType());
            if (!_logged)
            {
                _logged = true;
                LogLine("eCapture: UI type = " + ui.GetType().FullName);
                LogLine("eCapture: methods taking Session[] = " + DescribeCandidates(ui.GetType()));
                LogLine(mi != null
                    ? "eCapture: injecting via UI." + mi.Name + "(Session[])"
                    : "eCapture: NO suitable session-load method picked (not injecting).");
            }
            if (mi == null) return;
            mi.Invoke(ui, new object[] { new[] { oS } });
            try { oS.RefreshUI(); } catch { }
        }

        // For diagnostics: list every UI method that takes a single Session[]
        // parameter, so the correct injection API can be pinned exactly.
        private static string DescribeCandidates(Type uiType)
        {
            var sb = new StringBuilder();
            foreach (var m in uiType.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance))
            {
                ParameterInfo[] ps = m.GetParameters();
                if (ps.Length != 1 || ps[0].ParameterType != typeof(Session[])) continue;
                sb.Append(m.IsPublic ? "" : "[nonpublic]").Append(m.Name).Append("(Session[]) ");
            }
            return sb.Length == 0 ? "(none)" : sb.ToString();
        }

        private static MethodInfo ResolveLoadMethod(Type uiType)
        {
            if (_loadResolved) return _loadMethod;
            _loadResolved = true;

            // Include non-public methods: some Fiddler builds made the loader
            // internal. Reflection runs in full trust inside Fiddler so this is
            // invokable. We deliberately DO NOT fall back to "any method taking
            // Session[]" — that previously picked an export/save method and
            // popped a "Select Export Format" dialog per packet. Only accept a
            // method whose name clearly adds sessions to the list: exact
            // "actLoadSessions", or a (load|import|add)+"session" name that is
            // not a destructive verb (save/select/export/...).
            MethodInfo[] methods = uiType.GetMethods(
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
            _loadMethod = Pick(methods, m => m.Name == "actLoadSessions")
                       ?? Pick(methods, m => IsLoadName(m.Name));
            return _loadMethod;
        }

        private static readonly string[] DestructiveVerbs =
            { "save", "select", "export", "remove", "delete", "close", "zip", "saz", "clear", "tag" };

        private static bool IsDestructiveName(string name)
        {
            foreach (var v in DestructiveVerbs)
                if (name.IndexOf(v, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            return false;
        }

        private static bool IsLoadName(string name)
        {
            if (IsDestructiveName(name)) return false;
            if (name.IndexOf("session", StringComparison.OrdinalIgnoreCase) < 0) return false;
            return name.IndexOf("load", StringComparison.OrdinalIgnoreCase) >= 0
                || name.IndexOf("import", StringComparison.OrdinalIgnoreCase) >= 0
                || name.IndexOf("add", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static MethodInfo Pick(MethodInfo[] methods, Func<MethodInfo, bool> nameFilter)
        {
            foreach (var m in methods)
            {
                if (!nameFilter(m)) continue;
                ParameterInfo[] ps = m.GetParameters();
                if (ps.Length == 1 && ps[0].ParameterType == typeof(Session[]))
                    return m;
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
