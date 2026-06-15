package com.ecapture.burp.websocket;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.ecapture.burp.event.CapturedEvent;
import com.ecapture.burp.event.EventManager;
import com.ecapture.burp.proto.ECaptureProto;
import com.ecapture.burp.util.DebugLog;
import com.google.protobuf.InvalidProtocolBufferException;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * WebSocket client for receiving events from eCapture.
 * Supports auto-reconnection.
 */
public class ECaptureWebSocketClient {
    
    private final MontoyaApi api;
    private final Logging logging;
    private final EventManager eventManager;
    
    private WebSocketClient wsClient;
    private String serverUrl;
    private final AtomicBoolean shouldReconnect;
    private final AtomicBoolean isConnecting;
    
    // Auto-reconnect settings
    private final ScheduledExecutorService scheduler;
    private ScheduledFuture<?> reconnectTask;
    private int reconnectAttempts;
    private static final int MAX_RECONNECT_DELAY_SECONDS = 30;
    private static final int INITIAL_RECONNECT_DELAY_SECONDS = 2;
    
    // Connection state listeners
    private Consumer<ConnectionState> stateListener;
    
    public enum ConnectionState {
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
        RECONNECTING,
        ERROR
    }
    
    private volatile ConnectionState currentState = ConnectionState.DISCONNECTED;
    
    public ECaptureWebSocketClient(MontoyaApi api, EventManager eventManager) {
        this.api = api;
        this.logging = api.logging();
        this.eventManager = eventManager;
        this.shouldReconnect = new AtomicBoolean(false);
        this.isConnecting = new AtomicBoolean(false);
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "eCapture-Reconnect");
            t.setDaemon(true);
            return t;
        });
        this.reconnectAttempts = 0;
    }
    
    /**
     * Connect to the eCapture WebSocket server.
     */
    public void connect(String url) {
        if (isConnecting.get()) {
            return;
        }
        
        this.serverUrl = url;
        this.shouldReconnect.set(true);
        this.reconnectAttempts = 0;
        
        doConnect();
    }
    
    private void doConnect() {
        if (!shouldReconnect.get()) {
            return;
        }
        
        if (!isConnecting.compareAndSet(false, true)) {
            return;
        }
        
        try {
            // Close existing connection if any
            if (wsClient != null) {
                try {
                    wsClient.close();
                } catch (Exception e) {
                    // Ignore
                }
            }
            
            updateState(reconnectAttempts > 0 ? ConnectionState.RECONNECTING : ConnectionState.CONNECTING);
            
            URI uri = new URI(serverUrl);
            logging.logToOutput("Connecting to eCapture at " + serverUrl + 
                    (reconnectAttempts > 0 ? " (attempt " + (reconnectAttempts + 1) + ")" : ""));
            
            // Create WebSocket client with custom headers
            java.util.Map<String, String> httpHeaders = new java.util.HashMap<>();
            httpHeaders.put("Origin", "http://localhost");
            
            wsClient = new WebSocketClient(uri, httpHeaders) {
                @Override
                public void onOpen(ServerHandshake handshake) {
                    logging.logToOutput("Connected to eCapture WebSocket server!");
                    reconnectAttempts = 0;
                    isConnecting.set(false);
                    updateState(ConnectionState.CONNECTED);
                }
                
                @Override
                public void onMessage(String message) {
                    int len = message != null ? message.length() : 0;
                    DebugLog.log("[WS] <<< TEXT message: " + len + " chars (unexpected in binary protocol)");
                }
                
                @Override
                public void onMessage(ByteBuffer bytes) {
                    handleBinaryMessage(bytes);
                }
                
                @Override
                public void onClose(int code, String reason, boolean remote) {
                    logging.logToOutput("WebSocket closed: code=" + code + ", reason=" + reason + 
                            ", remote=" + remote);
                    isConnecting.set(false);
                    
                    if (shouldReconnect.get()) {
                        updateState(ConnectionState.RECONNECTING);
                        scheduleReconnect();
                    } else {
                        updateState(ConnectionState.DISCONNECTED);
                    }
                }
                
                @Override
                public void onError(Exception ex) {
                    logging.logToError("WebSocket error: " + ex.getMessage());
                    isConnecting.set(false);
                    updateState(ConnectionState.ERROR);
                }
            };
            
            wsClient.connect();
            
        } catch (Exception e) {
            logging.logToError("Failed to create WebSocket connection: " + e.getMessage());
            isConnecting.set(false);
            updateState(ConnectionState.ERROR);
            
            if (shouldReconnect.get()) {
                scheduleReconnect();
            }
        }
    }
    
    /**
     * Handle binary protobuf message from eCapture.
     */
    private void handleBinaryMessage(ByteBuffer bytes) {
        try {
            byte[] data = new byte[bytes.remaining()];
            bytes.get(data);
            DebugLog.log("[WS] <<< BINARY message: " + data.length + " bytes; first16(hex)=" + hexPreview(data));

            ECaptureProto.LogEntry logEntry = ECaptureProto.LogEntry.parseFrom(data);
            
            switch (logEntry.getLogType()) {
                case LOG_TYPE_HEARTBEAT:
                    handleHeartbeat(logEntry.getHeartbeatPayload());
                    break;
                    
                case LOG_TYPE_PROCESS_LOG:
                    handleProcessLog(logEntry.getRunLog());
                    break;
                    
                case LOG_TYPE_EVENT:
                    handleEvent(logEntry.getEventPayload());
                    break;
                    
                default:
                    logging.logToOutput("Unknown log type: " + logEntry.getLogType());
            }
            
        } catch (InvalidProtocolBufferException e) {
            DebugLog.log("[WS] Failed to parse protobuf message: " + e.getMessage());
            logging.logToError("Failed to parse protobuf message: " + e.getMessage());
        }
    }

    private static String hexPreview(byte[] data) {
        int n = Math.min(data.length, 16);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            sb.append(String.format("%02X ", data[i] & 0xFF));
        }
        return sb.toString().trim();
    }
    
    private void handleHeartbeat(ECaptureProto.Heartbeat heartbeat) {
        if (heartbeat != null) {
            eventManager.processHeartbeat(
                    heartbeat.getTimestamp(),
                    heartbeat.getCount(),
                    heartbeat.getMessage()
            );
        }
    }
    
    private void handleProcessLog(String log) {
        if (log != null && !log.isEmpty()) {
            eventManager.processRuntimeLog(log);
        }
    }
    
    private void handleEvent(ECaptureProto.Event event) {
        if (event == null) {
            return;
        }
        
        CapturedEvent capturedEvent = new CapturedEvent(
                event.getTimestamp(),
                event.getUuid(),
                event.getSrcIp(),
                event.getSrcPort(),
                event.getDstIp(),
                event.getDstPort(),
                event.getPid(),
                event.getPname(),
                event.getType(),
                event.getLength(),
                event.getPayload().toByteArray()
        );
        
        eventManager.processEvent(capturedEvent);
    }
    
    /**
     * Schedule a reconnection attempt with exponential backoff.
     */
    private void scheduleReconnect() {
        if (!shouldReconnect.get()) {
            return;
        }
        
        // Cancel any existing reconnect task
        if (reconnectTask != null && !reconnectTask.isDone()) {
            reconnectTask.cancel(false);
        }
        
        // Calculate delay with exponential backoff
        int delay = Math.min(
                INITIAL_RECONNECT_DELAY_SECONDS * (1 << Math.min(reconnectAttempts, 4)),
                MAX_RECONNECT_DELAY_SECONDS
        );
        
        reconnectAttempts++;
        
        logging.logToOutput("Scheduling reconnect in " + delay + " seconds...");
        
        reconnectTask = scheduler.schedule(this::doConnect, delay, TimeUnit.SECONDS);
    }
    
    /**
     * Disconnect from the WebSocket server.
     */
    public void disconnect() {
        shouldReconnect.set(false);
        
        // Cancel any pending reconnect
        if (reconnectTask != null) {
            reconnectTask.cancel(false);
        }
        
        // Close WebSocket connection
        if (wsClient != null) {
            try {
                wsClient.close();
            } catch (Exception e) {
                logging.logToError("Error closing WebSocket: " + e.getMessage());
            }
        }
        
        updateState(ConnectionState.DISCONNECTED);
        logging.logToOutput("Disconnected from eCapture");
    }
    
    /**
     * Check if currently connected.
     */
    public boolean isConnected() {
        return wsClient != null && wsClient.isOpen();
    }
    
    /**
     * Get current connection state.
     */
    public ConnectionState getState() {
        return currentState;
    }
    
    /**
     * Set state change listener.
     */
    public void setStateListener(Consumer<ConnectionState> listener) {
        this.stateListener = listener;
    }
    
    private void updateState(ConnectionState newState) {
        this.currentState = newState;
        if (stateListener != null) {
            try {
                stateListener.accept(newState);
            } catch (Exception e) {
                logging.logToError("Error in state listener: " + e.getMessage());
            }
        }
    }
    
    /**
     * Get current server URL.
     */
    public String getServerUrl() {
        return serverUrl;
    }
    
    /**
     * Shutdown the client and scheduler.
     */
    public void shutdown() {
        disconnect();
        scheduler.shutdownNow();
    }
}

