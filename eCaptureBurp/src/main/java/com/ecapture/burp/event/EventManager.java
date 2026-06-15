package com.ecapture.burp.event;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import com.ecapture.burp.export.HttpBodyCodec;
import com.ecapture.burp.util.DebugLog;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Manages captured events: reassembles fragmented HTTP messages, matches
 * request/response pairs by connection (PID_TID), and feeds the UI / Site Map.
 *
 * <p>eCapture emits one event per SSL_read / SSL_write, so a large response is
 * split across several READ events. We reassemble those by the thread that
 * owns them (PID_TID), since under HTTP/1.x a request and its response are
 * sent/received on the same thread in order.
 */
public class EventManager {

    private final MontoyaApi api;
    private final Logging logging;

    private final List<MatchedHttpPair> matchedPairs = new CopyOnWriteArrayList<>();
    private final List<String> runtimeLogs = new CopyOnWriteArrayList<>();

    private final List<Consumer<MatchedHttpPair>> pairListeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<String>> logListeners = new CopyOnWriteArrayList<>();

    // Reassembly state, keyed by PID_TID.
    private final Map<String, MessageBuffer> requestBuffers = new ConcurrentHashMap<>();
    private final Map<String, MessageBuffer> responseBuffers = new ConcurrentHashMap<>();
    // Requests awaiting a response, per connection (FIFO).
    private final Map<String, LinkedList<MatchedHttpPair>> pendingByConn = new ConcurrentHashMap<>();

    private final AtomicLong pairIdSeq = new AtomicLong(0);

    private long totalEventsReceived;
    private long totalPairsMatched;
    private long lastHeartbeatTime;
    private long heartbeatCount;

    public EventManager(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
    }

    public synchronized void processEvent(CapturedEvent event) {
        totalEventsReceived++;

        if (event.isConnectionEvent()) {
            DebugLog.log("[EVENT] connection event ignored conn=" + event.getConnKey());
            return;
        }

        CapturedEvent.Direction dir = event.getDirection();
        String connKey = event.getConnKey();

        DebugLog.log(String.format("[EVENT] dir=%s conn=%s startsMsg=%s payloadBytes=%d first40=%s",
                dir, connKey, event.startsHttpMessage(), event.getLength(),
                preview(event.getPayload())));

        boolean outbound = dir == CapturedEvent.Direction.WRITE
                || (dir == CapturedEvent.Direction.NONE && event.isRequest());
        boolean inbound = dir == CapturedEvent.Direction.READ
                || (dir == CapturedEvent.Direction.NONE && event.isResponse());

        if (outbound) {
            handleOutbound(connKey, event);
        } else if (inbound) {
            handleInbound(connKey, event);
        }

        cleanupOldConnections();
    }

    private void handleOutbound(String connKey, CapturedEvent event) {
        MessageBuffer req = requestBuffers.computeIfAbsent(connKey, k -> new MessageBuffer());
        if (event.startsHttpMessage()) {
            if (req.started && !req.isEmpty()) {
                // A previous request never completed; flush it as-is.
                finalizeRequest(connKey, req.toBytes(), event);
            }
            req.reset();
            req.started = true;
            req.append(event.getPayload());
        } else {
            if (!req.started) {
                return; // stray fragment with no request context
            }
            req.append(event.getPayload());
        }
        if (req.started && req.isComplete()) {
            finalizeRequest(connKey, req.toBytes(), event);
            req.reset();
        }
    }

    private void handleInbound(String connKey, CapturedEvent event) {
        MessageBuffer resp = responseBuffers.computeIfAbsent(connKey, k -> new MessageBuffer());
        if (event.startsHttpMessage()) {
            if (resp.started && !resp.isEmpty()) {
                finalizeResponse(connKey, resp.toBytes(), event);
            }
            resp.reset();
            resp.started = true;
            resp.append(event.getPayload());
        } else {
            if (!resp.started) {
                return;
            }
            resp.append(event.getPayload());
        }
        if (resp.started && resp.isComplete()) {
            finalizeResponse(connKey, resp.toBytes(), event);
            resp.reset();
        }
    }

    private void finalizeRequest(String connKey, byte[] httpBytes, CapturedEvent src) {
        CapturedEvent reqEvent = CapturedEvent.assembled(
                src.getTimestamp(), src.getDstIp(), src.getDstPort(),
                src.getPid(), src.getTid(), src.getProcessName(), false, httpBytes);

        String method = reqEvent.getHttpMethod();
        String url = reqEvent.getUrl();
        String host = reqEvent.getHost();
        if (url.equals("-") || url.isEmpty()) {
            return;
        }
        if (host == null || host.isEmpty() || host.equals("-") || host.equals("0.0.0.0")) {
            return;
        }

        MatchedHttpPair pair = new MatchedHttpPair("pair_" + pairIdSeq.incrementAndGet());
        pair.setRequest(reqEvent);
        pendingByConn.computeIfAbsent(connKey, k -> new LinkedList<>()).add(pair);
        matchedPairs.add(pair);
        totalPairsMatched++;
        DebugLog.log("[KEEP request] conn=" + connKey + " " + method + " " + host + url
                + " (" + httpBytes.length + " bytes)");
        notifyPairListeners(pair);
    }

    private void finalizeResponse(String connKey, byte[] httpBytes, CapturedEvent src) {
        CapturedEvent respEvent = CapturedEvent.assembled(
                src.getTimestamp(), src.getDstIp(), src.getDstPort(),
                src.getPid(), src.getTid(), src.getProcessName(), true, httpBytes);

        LinkedList<MatchedHttpPair> pending = pendingByConn.get(connKey);
        MatchedHttpPair pair = null;
        if (pending != null) {
            for (MatchedHttpPair p : pending) {
                if (!p.hasResponse()) {
                    pair = p;
                    break;
                }
            }
        }
        if (pair == null) {
            DebugLog.log("[DROP response] conn=" + connKey + " no pending request (status "
                    + respEvent.getStatusCode() + ")");
            return; // standalone responses are not displayed
        }
        pair.setResponse(respEvent);
        DebugLog.log("[KEEP response] conn=" + connKey + " status=" + respEvent.getStatusCode()
                + " (" + httpBytes.length + " bytes)");
        notifyPairListeners(pair);
        sendToSiteMapSafe(pair);
    }

    private void cleanupOldConnections() {
        long now = System.currentTimeMillis();
        pendingByConn.entrySet().removeIf(e -> {
            LinkedList<MatchedHttpPair> list = e.getValue();
            if (list.isEmpty()) return true;
            MatchedHttpPair oldest = list.peekFirst();
            return oldest != null
                    && (now - oldest.getCreatedAt() > 5 * 60 * 1000)
                    && list.stream().allMatch(MatchedHttpPair::isComplete);
        });
    }

    private void sendToSiteMapSafe(MatchedHttpPair pair) {
        try {
            CapturedEvent request = pair.getRequest();
            CapturedEvent response = pair.getResponse();
            if (request == null || request.getPayload() == null) {
                return;
            }
            String host = pair.getHost();
            if (host == null || host.isEmpty() || host.equals("0.0.0.0") || host.equals("-")) {
                return;
            }
            int port = pair.getPort();
            if (port <= 0) port = 443;
            boolean useHttps = (port == 443 || port == 8443);

            HttpService service = HttpService.httpService(host, port, useHttps);
            byte[] reqBytes = HttpBodyCodec.decodeHttpMessage(request.getPayload());
            HttpRequest httpRequest = HttpRequest.httpRequest(service, ByteArray.byteArray(reqBytes));

            if (response != null && response.getPayload() != null) {
                byte[] respBytes = HttpBodyCodec.decodeHttpMessage(response.getPayload());
                HttpResponse httpResponse = HttpResponse.httpResponse(ByteArray.byteArray(respBytes));
                api.siteMap().add(HttpRequestResponse.httpRequestResponse(httpRequest, httpResponse));
            }
        } catch (Exception e) {
            logging.logToError("Site Map error (ignored): " + e.getMessage());
        }
    }

    public void processHeartbeat(long timestamp, long count, String message) {
        this.lastHeartbeatTime = System.currentTimeMillis();
        this.heartbeatCount = count;
        DebugLog.log("[HEARTBEAT] count=" + count);
    }

    public void processRuntimeLog(String logMessage) {
        runtimeLogs.add(logMessage);
        while (runtimeLogs.size() > 1000) {
            runtimeLogs.remove(0);
        }
        notifyLogListeners(logMessage);
    }

    public void addPairListener(Consumer<MatchedHttpPair> listener) {
        pairListeners.add(listener);
    }

    public void addLogListener(Consumer<String> listener) {
        logListeners.add(listener);
    }

    private void notifyPairListeners(MatchedHttpPair pair) {
        for (Consumer<MatchedHttpPair> listener : pairListeners) {
            try {
                listener.accept(pair);
            } catch (Exception e) {
                logging.logToError("Error in pair listener: " + e.getMessage());
            }
        }
    }

    private void notifyLogListeners(String log) {
        for (Consumer<String> listener : logListeners) {
            try {
                listener.accept(log);
            } catch (Exception e) {
                logging.logToError("Error in log listener: " + e.getMessage());
            }
        }
    }

    public List<MatchedHttpPair> getMatchedPairs() {
        return new ArrayList<>(matchedPairs);
    }

    public List<String> getRuntimeLogs() {
        return new ArrayList<>(runtimeLogs);
    }

    public void clear() {
        matchedPairs.clear();
        requestBuffers.clear();
        responseBuffers.clear();
        pendingByConn.clear();
        runtimeLogs.clear();
        totalEventsReceived = 0;
        totalPairsMatched = 0;
    }

    public long getTotalEventsReceived() {
        return totalEventsReceived;
    }

    public long getTotalPairsMatched() {
        return totalPairsMatched;
    }

    public long getLastHeartbeatTime() {
        return lastHeartbeatTime;
    }

    public long getHeartbeatCount() {
        return heartbeatCount;
    }

    public int getPendingPairsCount() {
        int count = 0;
        for (LinkedList<MatchedHttpPair> list : pendingByConn.values()) {
            for (MatchedHttpPair p : list) {
                if (!p.hasResponse()) count++;
            }
        }
        return count;
    }

    private static String preview(byte[] data) {
        if (data == null || data.length == 0) return "(empty)";
        int n = Math.min(data.length, 40);
        String s = new String(data, 0, n, StandardCharsets.ISO_8859_1);
        return s.replaceAll("[\\r\\n]", " ");
    }

    /**
     * Accumulates the bytes of one HTTP message and determines when it is
     * complete (headers present + body satisfied per Content-Length /
     * chunked terminator).
     */
    private static final class MessageBuffer {
        final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        boolean started = false;

        void append(byte[] b) {
            if (b != null && b.length > 0) {
                buf.write(b, 0, b.length);
            }
        }

        boolean isEmpty() {
            return buf.size() == 0;
        }

        byte[] toBytes() {
            return buf.toByteArray();
        }

        void reset() {
            buf.reset();
            started = false;
        }

        boolean isComplete() {
            byte[] data = buf.toByteArray();
            int headerEnd = indexOf(data, new byte[]{'\r', '\n', '\r', '\n'});
            int sepLen = 4;
            if (headerEnd < 0) {
                headerEnd = indexOf(data, new byte[]{'\n', '\n'});
                sepLen = 2;
            }
            if (headerEnd < 0) {
                return false; // headers not fully received yet
            }
            String head = new String(data, 0, headerEnd, StandardCharsets.ISO_8859_1);
            int bodyStart = headerEnd + sepLen;
            int bodyLen = data.length - bodyStart;

            String te = HttpBodyCodec.headerValue(head, "Transfer-Encoding");
            if (te != null && te.toLowerCase().contains("chunked")) {
                return chunkedComplete(data, bodyStart);
            }
            String cl = HttpBodyCodec.headerValue(head, "Content-Length");
            if (cl != null && !cl.isEmpty()) {
                try {
                    long want = Long.parseLong(cl.trim());
                    return bodyLen >= want;
                } catch (NumberFormatException e) {
                    return true;
                }
            }
            // No Content-Length and not chunked. For responses with no body
            // (1xx/204/304) or requests this is complete at the header. For
            // bodies terminated by connection close we cannot know precisely,
            // so treat header presence as complete (best effort).
            String firstLine = head.split("\r\n|\n", 2)[0];
            if (firstLine.startsWith("HTTP/")) {
                String code = statusOf(firstLine);
                if (code.startsWith("1") || code.equals("204") || code.equals("304")) {
                    return true;
                }
                // Response body without length indicator: complete once we have
                // headers; further fragments (rare) will start a new message.
                return true;
            }
            return true; // request line, no body expected
        }

        private static String statusOf(String statusLine) {
            String[] parts = statusLine.split(" ");
            return parts.length >= 2 ? parts[1].trim() : "";
        }

        private static boolean chunkedComplete(byte[] data, int bodyStart) {
            int pos = bodyStart;
            int n = data.length;
            while (pos < n && (data[pos] == '\r' || data[pos] == '\n')) {
                pos++;
            }
            while (pos < n) {
                int lineEnd = pos;
                while (lineEnd < n && data[lineEnd] != '\n') {
                    lineEnd++;
                }
                if (lineEnd >= n) {
                    return false; // size line incomplete
                }
                String sizeLine = new String(data, pos, lineEnd - pos, StandardCharsets.ISO_8859_1).trim();
                int semi = sizeLine.indexOf(';');
                if (semi >= 0) sizeLine = sizeLine.substring(0, semi).trim();
                if (sizeLine.isEmpty()) {
                    pos = lineEnd + 1;
                    continue;
                }
                int chunkSize;
                try {
                    chunkSize = Integer.parseInt(sizeLine, 16);
                } catch (NumberFormatException e) {
                    return true; // not actually chunked
                }
                if (chunkSize == 0) {
                    return true; // terminating chunk reached
                }
                pos = lineEnd + 1 + chunkSize;
                while (pos < n && (data[pos] == '\r' || data[pos] == '\n')) {
                    pos++;
                }
            }
            return false;
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
