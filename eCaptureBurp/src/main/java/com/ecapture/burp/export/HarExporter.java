package com.ecapture.burp.export;

import com.ecapture.burp.event.CapturedEvent;
import com.ecapture.burp.event.MatchedHttpPair;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Exports matched HTTP pairs to HAR 1.2 (HTTP Archive) JSON.
 *
 * <p>Bodies are de-chunked and decompressed via {@link HttpBodyCodec} before
 * being placed into the HAR so the archive contains plaintext. Binary bodies
 * are base64-encoded and flagged with {@code "encoding":"base64"}.
 */
public final class HarExporter {

    private HarExporter() {}

    public static String toHar(List<MatchedHttpPair> pairs) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"log\": {\n");
        sb.append("    \"version\": \"1.2\",\n");
        sb.append("    \"creator\": { \"name\": \"eCaptureBurp\", \"version\": \"1.0.0\" },\n");
        sb.append("    \"entries\": [\n");

        List<String> entries = new ArrayList<>();
        for (MatchedHttpPair pair : pairs) {
            if (pair == null || !pair.hasRequest()) {
                continue;
            }
            String entry = buildEntry(pair);
            if (entry != null) {
                entries.add(entry);
            }
        }
        for (int i = 0; i < entries.size(); i++) {
            sb.append(entries.get(i));
            if (i < entries.size() - 1) {
                sb.append(",");
            }
            sb.append("\n");
        }

        sb.append("    ]\n");
        sb.append("  }\n");
        sb.append("}\n");
        return sb.toString();
    }

    private static String buildEntry(MatchedHttpPair pair) {
        try {
            CapturedEvent reqEvent = pair.getRequest();
            byte[] reqBytes = HttpBodyCodec.decodeHttpMessage(reqEvent.getPayload());
            HttpParts req = HttpParts.parse(reqBytes);

            String host = pair.getHost();
            int port = pair.getPort();
            if (port <= 0) port = 443;
            boolean https = pair.isHttps();
            String scheme = https ? "https" : "http";
            String path = pair.getUrl();
            String url;
            if (path.startsWith("http://") || path.startsWith("https://")) {
                url = path;
            } else if (port == 80 || port == 443) {
                url = scheme + "://" + host + path;
            } else {
                url = scheme + "://" + host + ":" + port + path;
            }

            String method = pair.getMethod();
            String httpVersion = req.httpVersion != null ? req.httpVersion : "HTTP/1.1";

            StringBuilder e = new StringBuilder();
            e.append("      {\n");
            e.append("        \"startedDateTime\": \"").append(pair.getTimestamp()).append("\",\n");
            e.append("        \"time\": 0,\n");

            // request
            e.append("        \"request\": {\n");
            e.append("          \"method\": \"").append(esc(method)).append("\",\n");
            e.append("          \"url\": \"").append(esc(url)).append("\",\n");
            e.append("          \"httpVersion\": \"").append(esc(httpVersion)).append("\",\n");
            e.append("          \"cookies\": [],\n");
            e.append("          \"headers\": ").append(headersJson(req.headers)).append(",\n");
            e.append("          \"queryString\": ").append(queryJson(path)).append(",\n");
            if (req.body != null && req.body.length > 0) {
                e.append("          \"postData\": ").append(postDataJson(req)).append(",\n");
            }
            e.append("          \"headersSize\": -1,\n");
            e.append("          \"bodySize\": ").append(req.body != null ? req.body.length : 0).append("\n");
            e.append("        },\n");

            // response
            e.append("        \"response\": {\n");
            if (pair.hasResponse()) {
                byte[] respBytes = HttpBodyCodec.decodeHttpMessage(pair.getResponse().getPayload());
                HttpParts resp = HttpParts.parse(respBytes);
                int status = parseStatus(resp.firstLine);
                e.append("          \"status\": ").append(status).append(",\n");
                e.append("          \"statusText\": \"").append(esc(statusText(resp.firstLine))).append("\",\n");
                e.append("          \"httpVersion\": \"").append(esc(resp.httpVersion != null ? resp.httpVersion : "HTTP/1.1")).append("\",\n");
                e.append("          \"cookies\": [],\n");
                e.append("          \"headers\": ").append(headersJson(resp.headers)).append(",\n");
                e.append("          \"redirectURL\": \"\",\n");
                e.append("          \"content\": ").append(contentJson(resp)).append(",\n");
                e.append("          \"headersSize\": -1,\n");
                e.append("          \"bodySize\": ").append(resp.body != null ? resp.body.length : 0).append("\n");
            } else {
                e.append("          \"status\": 0,\n");
                e.append("          \"statusText\": \"\",\n");
                e.append("          \"httpVersion\": \"HTTP/1.1\",\n");
                e.append("          \"cookies\": [],\n");
                e.append("          \"headers\": [],\n");
                e.append("          \"redirectURL\": \"\",\n");
                e.append("          \"content\": { \"size\": 0, \"mimeType\": \"\" },\n");
                e.append("          \"headersSize\": -1,\n");
                e.append("          \"bodySize\": 0\n");
            }
            e.append("        },\n");
            e.append("        \"cache\": {},\n");
            e.append("        \"timings\": { \"send\": 0, \"wait\": 0, \"receive\": 0 }\n");
            e.append("      }");
            return e.toString();
        } catch (Exception ex) {
            return null;
        }
    }

    private static String headersJson(List<String[]> headers) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < headers.size(); i++) {
            String[] h = headers.get(i);
            sb.append("{ \"name\": \"").append(esc(h[0])).append("\", \"value\": \"").append(esc(h[1])).append("\" }");
            if (i < headers.size() - 1) sb.append(", ");
        }
        sb.append("]");
        return sb.toString();
    }

    private static String queryJson(String path) {
        StringBuilder sb = new StringBuilder("[");
        int q = path.indexOf('?');
        if (q >= 0 && q < path.length() - 1) {
            String query = path.substring(q + 1);
            String[] params = query.split("&");
            List<String> items = new ArrayList<>();
            for (String p : params) {
                int eq = p.indexOf('=');
                String name = eq >= 0 ? p.substring(0, eq) : p;
                String value = eq >= 0 ? p.substring(eq + 1) : "";
                items.add("{ \"name\": \"" + esc(name) + "\", \"value\": \"" + esc(value) + "\" }");
            }
            sb.append(String.join(", ", items));
        }
        sb.append("]");
        return sb.toString();
    }

    private static String postDataJson(HttpParts req) {
        String mime = headerValue(req.headers, "Content-Type");
        String text;
        if (isPrintable(req.body)) {
            text = new String(req.body, StandardCharsets.UTF_8);
        } else {
            text = Base64.getEncoder().encodeToString(req.body);
        }
        return "{ \"mimeType\": \"" + esc(mime) + "\", \"text\": \"" + esc(text) + "\" }";
    }

    private static String contentJson(HttpParts resp) {
        String mime = headerValue(resp.headers, "Content-Type");
        byte[] body = resp.body != null ? resp.body : new byte[0];
        StringBuilder sb = new StringBuilder();
        sb.append("{ \"size\": ").append(body.length).append(", \"mimeType\": \"").append(esc(mime)).append("\"");
        if (body.length > 0) {
            if (isPrintable(body)) {
                sb.append(", \"text\": \"").append(esc(new String(body, StandardCharsets.UTF_8))).append("\"");
            } else {
                sb.append(", \"text\": \"").append(esc(Base64.getEncoder().encodeToString(body)))
                        .append("\", \"encoding\": \"base64\"");
            }
        }
        sb.append(" }");
        return sb.toString();
    }

    private static int parseStatus(String firstLine) {
        if (firstLine == null) return 0;
        String[] parts = firstLine.split(" ");
        if (parts.length >= 2) {
            try {
                return Integer.parseInt(parts[1].trim());
            } catch (NumberFormatException ignored) {
            }
        }
        return 0;
    }

    private static String statusText(String firstLine) {
        if (firstLine == null) return "";
        String[] parts = firstLine.split(" ", 3);
        return parts.length >= 3 ? parts[2].trim() : "";
    }

    private static String headerValue(List<String[]> headers, String name) {
        for (String[] h : headers) {
            if (h[0].equalsIgnoreCase(name)) {
                return h[1];
            }
        }
        return "";
    }

    private static boolean isPrintable(byte[] data) {
        if (data == null) return true;
        int sample = Math.min(data.length, 2048);
        int nonText = 0;
        for (int i = 0; i < sample; i++) {
            int b = data[i] & 0xFF;
            if (b == 0) return false;
            if (b < 0x09 || (b > 0x0D && b < 0x20)) {
                nonText++;
            }
        }
        return nonText < sample / 20 + 1;
    }

    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    /** Parsed view of an HTTP message: first line, headers, body. */
    private static final class HttpParts {
        String firstLine;
        String httpVersion;
        final List<String[]> headers = new ArrayList<>();
        byte[] body = new byte[0];

        static HttpParts parse(byte[] data) {
            HttpParts p = new HttpParts();
            if (data == null || data.length == 0) {
                return p;
            }
            int sep = indexOf(data, new byte[]{'\r', '\n', '\r', '\n'});
            int sepLen = 4;
            if (sep < 0) {
                sep = indexOf(data, new byte[]{'\n', '\n'});
                sepLen = 2;
            }
            int headEnd = sep < 0 ? data.length : sep;
            String head = new String(data, 0, headEnd, StandardCharsets.ISO_8859_1);
            String[] lines = head.split("\r\n|\n");
            if (lines.length > 0) {
                p.firstLine = lines[0];
                String[] flParts = p.firstLine.split(" ");
                for (String tok : flParts) {
                    if (tok.startsWith("HTTP/")) {
                        p.httpVersion = tok;
                        break;
                    }
                }
                for (int i = 1; i < lines.length; i++) {
                    int colon = lines[i].indexOf(':');
                    if (colon > 0) {
                        p.headers.add(new String[]{
                                lines[i].substring(0, colon).trim(),
                                lines[i].substring(colon + 1).trim()
                        });
                    }
                }
            }
            if (sep >= 0) {
                int bodyStart = sep + sepLen;
                p.body = new byte[data.length - bodyStart];
                System.arraycopy(data, bodyStart, p.body, 0, p.body.length);
            }
            return p;
        }

        private static int indexOf(byte[] data, byte[] pattern) {
            outer:
            for (int i = 0; i <= data.length - pattern.length; i++) {
                for (int j = 0; j < pattern.length; j++) {
                    if (data[i + j] != pattern[j]) continue outer;
                }
                return i;
            }
            return -1;
        }
    }
}
