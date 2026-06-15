package com.ecapture.burp.event;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Represents a captured HTTP event from eCapture.
 *
 * <p>In eCaptureQ "text" mode (the mode used when running
 * {@code ./ecapture tls --ecaptureq=ws://...}) every event payload is the
 * textual form of a single SSL_read / SSL_write, prefixed by an eCapture
 * header line, e.g.:
 *
 * <pre>
 *   2026-06-15T03:23:20Z PID:24394, Comm:guvideo, TID:24499, FD:152, WRITE (1457 bytes):
 *   GET /path HTTP/1.1
 *   Host: ...
 * </pre>
 *
 * or a "connect" event:
 *
 * <pre>
 *   PID:24394, Comm:sk_rpt, TID:24499, FD:152, Tuple: [a]:p-&gt;[b]:p.
 * </pre>
 *
 * The direction (WRITE = request the app sent, READ = response the app
 * received) is far more reliable than sniffing the content, so we parse the
 * header and key the rest of the pipeline off it. The header line is stripped
 * so {@link #getPayload()} returns the raw HTTP bytes.
 */
public class CapturedEvent {

    public enum EventType {
        UNKNOWN(0, "Unknown"),
        HTTP1_REQUEST(1, "HTTP/1.x Request"),
        HTTP2_REQUEST(2, "HTTP/2 Request"),
        HTTP1_RESPONSE(3, "HTTP/1.x Response"),
        HTTP2_RESPONSE(4, "HTTP/2 Response"),
        AUTO_REQUEST(-1, "Request"),
        AUTO_RESPONSE(-2, "Response"),
        CONNECTION(-3, "Connection");

        private final int code;
        private final String description;

        EventType(int code, String description) {
            this.code = code;
            this.description = description;
        }

        public int getCode() {
            return code;
        }

        public String getDescription() {
            return description;
        }

        public boolean isRequest() {
            return this == HTTP1_REQUEST || this == HTTP2_REQUEST || this == AUTO_REQUEST;
        }

        public boolean isResponse() {
            return this == HTTP1_RESPONSE || this == HTTP2_RESPONSE || this == AUTO_RESPONSE;
        }
    }

    public enum Direction { WRITE, READ, CONNECT, NONE }

    private static final Pattern PID_PATTERN = Pattern.compile("PID:(\\d+)");
    private static final Pattern TID_PATTERN = Pattern.compile("TID:(\\d+)");
    private static final Pattern COMM_PATTERN = Pattern.compile("Comm:([^,\\s]+)");

    private final long timestamp;
    private final String uuid;
    private final String srcIp;
    private final int srcPort;
    private final String dstIp;
    private final int dstPort;
    private long pid;
    private long tid;
    private String processName;
    private final EventType eventType;
    private final Direction direction;
    private final boolean connectionEvent;
    private final int length;
    private final byte[] payload;   // raw HTTP bytes (eCapture header stripped)
    private final long receivedAt;

    /** Constructor used by the WebSocket client for raw eCapture events. */
    public CapturedEvent(long timestamp, String uuid, String srcIp, int srcPort,
                         String dstIp, int dstPort, long pid, String processName,
                         int type, int length, byte[] rawPayload) {
        this.timestamp = timestamp;
        this.uuid = uuid;
        this.srcIp = srcIp;
        this.srcPort = srcPort;
        this.dstIp = dstIp;
        this.dstPort = dstPort;
        this.pid = pid;
        this.tid = 0;
        this.processName = processName;
        this.length = length;
        this.receivedAt = System.currentTimeMillis();

        // Parse the eCapture text-mode header and strip it off the payload.
        ParsedHeader ph = parseHeader(rawPayload);
        this.direction = ph.direction;
        this.connectionEvent = ph.direction == Direction.CONNECT;
        this.payload = ph.body;
        if (ph.pid >= 0) this.pid = ph.pid;
        if (ph.tid >= 0) this.tid = ph.tid;
        if (ph.comm != null && !ph.comm.isEmpty()) this.processName = ph.comm;

        this.eventType = classify(ph.direction, this.payload);
    }

    /** Constructor for a fully reassembled HTTP message (header already clean). */
    private CapturedEvent(long timestamp, String dstIp, int dstPort, long pid, long tid,
                          String processName, boolean response, byte[] httpBytes) {
        this.timestamp = timestamp;
        this.uuid = "";
        this.srcIp = "";
        this.srcPort = 0;
        this.dstIp = dstIp;
        this.dstPort = dstPort;
        this.pid = pid;
        this.tid = tid;
        this.processName = processName;
        this.length = httpBytes != null ? httpBytes.length : 0;
        this.payload = httpBytes;
        this.receivedAt = System.currentTimeMillis();
        this.direction = response ? Direction.READ : Direction.WRITE;
        this.connectionEvent = false;
        this.eventType = response ? EventType.AUTO_RESPONSE : EventType.AUTO_REQUEST;
    }

    public static CapturedEvent assembled(long timestamp, String dstIp, int dstPort, long pid,
                                          long tid, String processName, boolean response, byte[] httpBytes) {
        return new CapturedEvent(timestamp, dstIp, dstPort, pid, tid, processName, response, httpBytes);
    }

    private static EventType classify(Direction dir, byte[] body) {
        switch (dir) {
            case WRITE:
                return EventType.AUTO_REQUEST;
            case READ:
                return EventType.AUTO_RESPONSE;
            case CONNECT:
                return EventType.CONNECTION;
            default:
                return detectEventType(body);
        }
    }

    private static final class ParsedHeader {
        Direction direction = Direction.NONE;
        long pid = -1;
        long tid = -1;
        String comm = null;
        byte[] body;
    }

    /**
     * Detect and strip the eCapture text-mode header line. If the payload does
     * not look like an eCapture event header, it is treated as raw HTTP.
     */
    private static ParsedHeader parseHeader(byte[] raw) {
        ParsedHeader ph = new ParsedHeader();
        if (raw == null || raw.length == 0) {
            ph.body = raw == null ? new byte[0] : raw;
            return ph;
        }

        // The header line is everything up to the first '\n'.
        int nl = -1;
        int scan = Math.min(raw.length, 512);
        for (int i = 0; i < scan; i++) {
            if (raw[i] == '\n') {
                nl = i;
                break;
            }
        }

        String firstLine = new String(raw, 0, nl >= 0 ? nl : raw.length, StandardCharsets.ISO_8859_1);
        boolean looksLikeHeader = firstLine.contains("PID:")
                && (firstLine.contains("WRITE") || firstLine.contains("READ")
                    || firstLine.contains("Tuple:"));

        if (!looksLikeHeader) {
            // No eCapture header: treat the whole payload as raw HTTP.
            ph.body = raw;
            return ph;
        }

        Matcher mPid = PID_PATTERN.matcher(firstLine);
        if (mPid.find()) ph.pid = Long.parseLong(mPid.group(1));
        Matcher mTid = TID_PATTERN.matcher(firstLine);
        if (mTid.find()) ph.tid = Long.parseLong(mTid.group(1));
        Matcher mComm = COMM_PATTERN.matcher(firstLine);
        if (mComm.find()) ph.comm = mComm.group(1);

        if (firstLine.contains("Tuple:") && !firstLine.contains("WRITE") && !firstLine.contains("READ")) {
            ph.direction = Direction.CONNECT;
        } else if (firstLine.contains("WRITE")) {
            ph.direction = Direction.WRITE;
        } else if (firstLine.contains("READ")) {
            ph.direction = Direction.READ;
        }

        int bodyStart = nl >= 0 ? nl + 1 : raw.length;
        byte[] body = new byte[Math.max(0, raw.length - bodyStart)];
        if (body.length > 0) {
            System.arraycopy(raw, bodyStart, body, 0, body.length);
        }
        ph.body = body;
        return ph;
    }

    private static EventType detectEventType(byte[] payload) {
        if (payload == null || payload.length < 4) {
            return EventType.UNKNOWN;
        }
        String start = new String(payload, 0, Math.min(payload.length, 20), StandardCharsets.ISO_8859_1);
        if (start.startsWith("HTTP/")) {
            return EventType.AUTO_RESPONSE;
        }
        if (start.startsWith("GET ") || start.startsWith("POST ") || start.startsWith("PUT ")
                || start.startsWith("DELETE ") || start.startsWith("HEAD ") || start.startsWith("OPTIONS ")
                || start.startsWith("PATCH ") || start.startsWith("CONNECT ") || start.startsWith("TRACE ")) {
            return EventType.AUTO_REQUEST;
        }
        return EventType.UNKNOWN;
    }

    /** Connection key for pairing: same thread (PID_TID) handles req + resp. */
    public String getConnKey() {
        return pid + "_" + tid;
    }

    public Direction getDirection() {
        return direction;
    }

    public boolean isConnectionEvent() {
        return connectionEvent;
    }

    /** Whether the stripped payload begins a new HTTP message. */
    public boolean startsHttpMessage() {
        if (payload == null || payload.length < 4) return false;
        String start = new String(payload, 0, Math.min(payload.length, 20), StandardCharsets.ISO_8859_1);
        if (start.startsWith("HTTP/")) return true;
        return start.startsWith("GET ") || start.startsWith("POST ") || start.startsWith("PUT ")
                || start.startsWith("DELETE ") || start.startsWith("HEAD ") || start.startsWith("OPTIONS ")
                || start.startsWith("PATCH ") || start.startsWith("CONNECT ") || start.startsWith("TRACE ");
    }

    public long getTimestamp() {
        return timestamp;
    }

    public String getFormattedTimestamp() {
        return Instant.ofEpochSecond(timestamp)
                .atZone(ZoneId.systemDefault())
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }

    public String getUuid() {
        return uuid;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public String getDstIp() {
        return dstIp;
    }

    public int getDstPort() {
        return dstPort;
    }

    public long getPid() {
        return pid;
    }

    public long getTid() {
        return tid;
    }

    public String getProcessName() {
        return processName;
    }

    public EventType getEventType() {
        return eventType;
    }

    public int getLength() {
        return payload != null ? payload.length : length;
    }

    public byte[] getPayload() {
        return payload;
    }

    public long getReceivedAt() {
        return receivedAt;
    }

    public boolean isRequest() {
        return eventType.isRequest();
    }

    public boolean isResponse() {
        return eventType.isResponse();
    }

    public String getHttpMethod() {
        if (payload == null || payload.length == 0) {
            return "-";
        }
        String payloadStr = new String(payload, 0, Math.min(payload.length, 40), StandardCharsets.ISO_8859_1);
        int spaceIndex = payloadStr.indexOf(' ');
        if (spaceIndex > 0 && spaceIndex < 10) {
            return payloadStr.substring(0, spaceIndex);
        }
        return "-";
    }

    public String getUrl() {
        if (payload == null || payload.length == 0) {
            return "-";
        }
        String payloadStr = new String(payload, 0, Math.min(payload.length, 2048), StandardCharsets.ISO_8859_1);
        int firstSpace = payloadStr.indexOf(' ');
        if (firstSpace > 0) {
            int secondSpace = payloadStr.indexOf(' ', firstSpace + 1);
            if (secondSpace > firstSpace) {
                return payloadStr.substring(firstSpace + 1, secondSpace);
            }
        }
        return "-";
    }

    public String getStatusCode() {
        if (payload == null || payload.length == 0) {
            return "-";
        }
        String payloadStr = new String(payload, 0, Math.min(payload.length, 40), StandardCharsets.ISO_8859_1);
        int firstSpace = payloadStr.indexOf(' ');
        if (firstSpace > 0) {
            int secondSpace = payloadStr.indexOf(' ', firstSpace + 1);
            int endIndex = secondSpace > firstSpace ? secondSpace : Math.min(payloadStr.length(), firstSpace + 4);
            if (endIndex > firstSpace + 1) {
                return payloadStr.substring(firstSpace + 1, endIndex).trim();
            }
        }
        return "-";
    }

    public String getHost() {
        if (payload == null || payload.length == 0) {
            return dstIp;
        }
        String payloadStr = new String(payload, 0, Math.min(payload.length, 4096), StandardCharsets.ISO_8859_1);
        String hostHeader = "Host:";
        int hostIndex = payloadStr.indexOf(hostHeader);
        if (hostIndex == -1) {
            hostHeader = "host:";
            hostIndex = payloadStr.indexOf(hostHeader);
        }
        if (hostIndex >= 0) {
            int start = hostIndex + hostHeader.length();
            int end = payloadStr.indexOf('\r', start);
            if (end == -1) {
                end = payloadStr.indexOf('\n', start);
            }
            if (end > start) {
                return payloadStr.substring(start, end).trim();
            }
        }
        return dstIp;
    }

    @Override
    public String toString() {
        return String.format("CapturedEvent[dir=%s, type=%s, conn=%s, process=%s(%d/%d), len=%d]",
                direction, eventType.getDescription(), getConnKey(), processName, pid, tid, getLength());
    }
}
