package com.ecapture.burp.export;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;

/**
 * Decodes raw HTTP message bytes captured by eCapture so they display as
 * plaintext: removes Transfer-Encoding: chunked framing and recursively
 * decompresses common Content-Encodings (gzip / deflate(zlib) / br) until the
 * body is no longer a recognised compression format.
 *
 * eCapture's text mode forwards the raw SSL_read bytes without any decoding, so
 * a gzipped/chunked body arrives verbatim. Burp does not always auto-decode it
 * (e.g. when the body is chunked, fragmented, or the encoding is undeclared),
 * which is why we decode it ourselves here.
 */
public final class HttpBodyCodec {

    private HttpBodyCodec() {}

    private static final byte[] CRLFCRLF = {'\r', '\n', '\r', '\n'};
    private static final byte[] LFLF = {'\n', '\n'};

    /**
     * Decode a full HTTP message (request or response): de-chunk + decompress
     * the body, then fix up the headers (drop Transfer-Encoding /
     * Content-Encoding, set Content-Length to the decoded length).
     * Returns the original bytes unchanged if no header terminator is found or
     * on any error.
     */
    public static byte[] decodeHttpMessage(byte[] rawHttp) {
        if (rawHttp == null || rawHttp.length == 0) {
            return rawHttp;
        }
        try {
            int sep = indexOf(rawHttp, CRLFCRLF, 0);
            int sepLen = 4;
            if (sep < 0) {
                sep = indexOf(rawHttp, LFLF, 0);
                sepLen = 2;
            }
            if (sep < 0) {
                // No header/body boundary: nothing to decode.
                return rawHttp;
            }

            byte[] head = new byte[sep];
            System.arraycopy(rawHttp, 0, head, 0, sep);
            int bodyStart = sep + sepLen;
            byte[] body = new byte[rawHttp.length - bodyStart];
            System.arraycopy(rawHttp, bodyStart, body, 0, body.length);

            String headStr = new String(head, StandardCharsets.ISO_8859_1);
            String transferEncoding = headerValue(headStr, "Transfer-Encoding");
            String contentEncoding = headerValue(headStr, "Content-Encoding");

            if ((transferEncoding == null || transferEncoding.isEmpty())
                    && (contentEncoding == null || contentEncoding.isEmpty())
                    && !looksCompressed(body)) {
                // Nothing to do.
                return rawHttp;
            }

            byte[] decoded = decodeBody(body, transferEncoding, contentEncoding);

            String newHead = rewriteHeaders(headStr, decoded.length);
            byte[] newHeadBytes = newHead.getBytes(StandardCharsets.ISO_8859_1);

            ByteArrayOutputStream out = new ByteArrayOutputStream(newHeadBytes.length + 4 + decoded.length);
            out.write(newHeadBytes);
            out.write('\r');
            out.write('\n');
            out.write('\r');
            out.write('\n');
            out.write(decoded);
            return out.toByteArray();
        } catch (Exception e) {
            return rawHttp;
        }
    }

    /**
     * Decode just a body: de-chunk (if chunked) then recursively decompress.
     */
    public static byte[] decodeBody(byte[] body, String transferEncoding, String contentEncoding) {
        if (body == null) {
            return new byte[0];
        }
        byte[] data = body;

        // 1. De-chunk if Transfer-Encoding indicates chunked framing.
        if (transferEncoding != null && transferEncoding.toLowerCase().contains("chunked")) {
            data = dechunk(data);
        }

        // 2. Apply declared Content-Encoding tokens in reverse order.
        //    "Content-Encoding: gzip, deflate" means deflate was applied last,
        //    so we must inflate then gunzip (reverse of application order).
        if (contentEncoding != null && !contentEncoding.isEmpty()) {
            List<String> tokens = new ArrayList<>();
            for (String t : contentEncoding.split(",")) {
                String tok = t.trim().toLowerCase();
                if (!tok.isEmpty()) {
                    tokens.add(tok);
                }
            }
            for (int i = tokens.size() - 1; i >= 0; i--) {
                data = applyDecode(data, tokens.get(i));
            }
        }

        // 3. Magic-byte loop: catch undeclared / stacked compression. Keep
        //    decompressing while the data still starts with a known magic.
        for (int round = 0; round < 8; round++) {
            if (isGzip(data)) {
                byte[] r = gunzip(data);
                if (r.length == 0 || java.util.Arrays.equals(r, data)) break;
                data = r;
            } else if (isZlib(data)) {
                byte[] r = inflate(data, false);
                if (r.length == 0 || java.util.Arrays.equals(r, data)) break;
                data = r;
            } else {
                break;
            }
        }
        return data;
    }

    private static byte[] applyDecode(byte[] data, String token) {
        switch (token) {
            case "gzip":
            case "x-gzip":
                return gunzip(data);
            case "deflate":
                return inflate(data, false);
            case "br":
                return brotli(data);
            case "identity":
            case "":
                return data;
            default:
                return data;
        }
    }

    /** Parse Transfer-Encoding: chunked framing into the raw body. */
    static byte[] dechunk(byte[] in) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int pos = 0;
            int n = in.length;
            // Tolerate leading CRLF/whitespace before the first chunk-size.
            while (pos < n && (in[pos] == '\r' || in[pos] == '\n')) {
                pos++;
            }
            while (pos < n) {
                int lineEnd = pos;
                while (lineEnd < n && in[lineEnd] != '\n') {
                    lineEnd++;
                }
                if (lineEnd >= n) break;
                String sizeLine = new String(in, pos, lineEnd - pos, StandardCharsets.ISO_8859_1).trim();
                // chunk-size may have extensions: "1a;name=value"
                int semi = sizeLine.indexOf(';');
                if (semi >= 0) {
                    sizeLine = sizeLine.substring(0, semi).trim();
                }
                if (sizeLine.isEmpty()) {
                    pos = lineEnd + 1;
                    continue;
                }
                int chunkSize;
                try {
                    chunkSize = Integer.parseInt(sizeLine, 16);
                } catch (NumberFormatException e) {
                    // Not chunked after all - return what we have plus the rest.
                    out.write(in, pos, n - pos);
                    break;
                }
                pos = lineEnd + 1; // move past the size line
                if (chunkSize == 0) {
                    break; // last chunk
                }
                if (pos + chunkSize > n) {
                    // Truncated chunk: keep whatever data remains.
                    out.write(in, pos, n - pos);
                    break;
                }
                out.write(in, pos, chunkSize);
                pos += chunkSize;
                // Skip trailing CRLF after chunk data.
                while (pos < n && (in[pos] == '\r' || in[pos] == '\n')) {
                    pos++;
                }
            }
            return out.toByteArray();
        } catch (Exception e) {
            return in;
        }
    }

    static boolean isGzip(byte[] d) {
        return d != null && d.length >= 3
                && (d[0] & 0xFF) == 0x1F && (d[1] & 0xFF) == 0x8B && (d[2] & 0xFF) == 0x08;
    }

    static boolean isZlib(byte[] d) {
        if (d == null || d.length < 2) return false;
        int b0 = d[0] & 0xFF;
        int b1 = d[1] & 0xFF;
        // zlib: CMF=0x78 (deflate, 32K window) and (CMF*256+FLG) % 31 == 0
        return b0 == 0x78 && ((b0 << 8 | b1) % 31 == 0);
    }

    private static boolean looksCompressed(byte[] d) {
        return isGzip(d) || isZlib(d);
    }

    static byte[] gunzip(byte[] in) {
        if (in == null || in.length == 0) return new byte[0];
        try (GZIPInputStream gz = new GZIPInputStream(new ByteArrayInputStream(in))) {
            return readAll(gz);
        } catch (Exception e) {
            // Lenient: eCapture may truncate; return whatever inflate recovers.
            byte[] partial = gunzipRaw(in);
            return partial.length > 0 ? partial : in;
        }
    }

    /** Raw inflate of gzip payload skipping the 10-byte header (best-effort). */
    private static byte[] gunzipRaw(byte[] in) {
        try {
            if (in.length <= 10) return new byte[0];
            byte[] deflated = new byte[in.length - 10];
            System.arraycopy(in, 10, deflated, 0, deflated.length);
            return inflate(deflated, true);
        } catch (Exception e) {
            return new byte[0];
        }
    }

    static byte[] inflate(byte[] in, boolean nowrap) {
        if (in == null || in.length == 0) return new byte[0];
        Inflater inflater = new Inflater(nowrap);
        try {
            inflater.setInput(in);
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(64, in.length * 3));
            byte[] buf = new byte[8192];
            while (!inflater.finished()) {
                int count = inflater.inflate(buf);
                if (count == 0) {
                    if (inflater.needsInput() || inflater.needsDictionary()) {
                        break;
                    }
                }
                out.write(buf, 0, count);
            }
            byte[] result = out.toByteArray();
            if (result.length == 0 && !nowrap) {
                // Some servers send raw deflate without zlib header.
                return inflate(in, true);
            }
            return result;
        } catch (Exception e) {
            if (!nowrap) {
                return inflate(in, true);
            }
            return new byte[0];
        } finally {
            inflater.end();
        }
    }

    static byte[] brotli(byte[] in) {
        if (in == null || in.length == 0) return new byte[0];
        try {
            org.brotli.dec.BrotliInputStream bis =
                    new org.brotli.dec.BrotliInputStream(new ByteArrayInputStream(in));
            try {
                return readAll(bis);
            } finally {
                bis.close();
            }
        } catch (Throwable e) {
            return in;
        }
    }

    private static byte[] readAll(java.io.InputStream is) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int r;
        try {
            while ((r = is.read(buf)) != -1) {
                out.write(buf, 0, r);
            }
        } catch (Exception e) {
            // Keep partial output on truncated streams.
        }
        return out.toByteArray();
    }

    /**
     * Return the (comma-joined) value of an HTTP header, case-insensitive.
     */
    public static String headerValue(String head, String name) {
        if (head == null) return "";
        String lname = name.toLowerCase();
        for (String line : head.split("\r\n|\n")) {
            int colon = line.indexOf(':');
            if (colon <= 0) continue;
            if (line.substring(0, colon).trim().toLowerCase().equals(lname)) {
                return line.substring(colon + 1).trim();
            }
        }
        return "";
    }

    /**
     * Drop Transfer-Encoding and Content-Encoding headers and set
     * Content-Length to the decoded length.
     */
    private static String rewriteHeaders(String head, int newLength) {
        String[] lines = head.split("\r\n|\n", -1);
        StringBuilder sb = new StringBuilder();
        boolean wroteContentLength = false;
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (i == 0) {
                sb.append(line); // status / request line
                continue;
            }
            int colon = line.indexOf(':');
            String key = colon > 0 ? line.substring(0, colon).trim().toLowerCase() : "";
            if (key.equals("transfer-encoding") || key.equals("content-encoding")) {
                continue; // strip
            }
            if (key.equals("content-length")) {
                sb.append("\r\n").append("Content-Length: ").append(newLength);
                wroteContentLength = true;
                continue;
            }
            if (line.isEmpty()) {
                continue;
            }
            sb.append("\r\n").append(line);
        }
        if (!wroteContentLength) {
            sb.append("\r\n").append("Content-Length: ").append(newLength);
        }
        return sb.toString();
    }

    private static int indexOf(byte[] data, byte[] pattern, int from) {
        outer:
        for (int i = Math.max(0, from); i <= data.length - pattern.length; i++) {
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
