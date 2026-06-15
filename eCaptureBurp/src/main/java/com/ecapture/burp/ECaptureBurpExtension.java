package com.ecapture.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.ecapture.burp.ui.ECaptureTab;
import com.ecapture.burp.util.DebugLog;
import com.ecapture.burp.websocket.ECaptureWebSocketClient;
import com.ecapture.burp.event.EventManager;

/**
 * Main entry point for the eCapture Burp Suite Extension.
 * Receives TLS/HTTP data from eCapture via WebSocket and displays it in Burp.
 */
public class ECaptureBurpExtension implements BurpExtension {
    
    public static final String EXTENSION_NAME = "eCapture";
    public static final String DEFAULT_WS_URL = "ws://127.0.0.1:28257/";
    
    private MontoyaApi api;
    private Logging logging;
    private ECaptureWebSocketClient wsClient;
    private EventManager eventManager;
    private ECaptureTab mainTab;
    
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        
        // Set extension name
        api.extension().setName(EXTENSION_NAME);

        // Initialize the debug logger (file + in-panel Debug Log tab).
        DebugLog.init();

        logging.logToOutput("===========================================");
        logging.logToOutput("  eCapture Burp Extension v1.0.0 [DEBUG BUILD]");
        logging.logToOutput("  Receive TLS/HTTP data from eCapture");
        logging.logToOutput("  Debug log: " + DebugLog.getLogFilePath());
        logging.logToOutput("===========================================");
        
        // Initialize event manager
        this.eventManager = new EventManager(api);
        
        // Initialize WebSocket client
        this.wsClient = new ECaptureWebSocketClient(api, eventManager);
        
        // Initialize and register UI tab
        this.mainTab = new ECaptureTab(api, wsClient, eventManager);
        api.userInterface().registerSuiteTab(EXTENSION_NAME, mainTab.getComponent());
        
        // Register context menu
        api.userInterface().registerContextMenuItemsProvider(mainTab.getContextMenuProvider());
        
        // Register extension unload handler
        api.extension().registerUnloadingHandler(() -> {
            logging.logToOutput("Unloading eCapture extension...");
            if (wsClient != null) {
                wsClient.disconnect();
            }
        });
        
        logging.logToOutput("eCapture extension loaded successfully!");
        logging.logToOutput("Configure WebSocket URL and click Connect to start receiving data.");
    }
    
    public MontoyaApi getApi() {
        return api;
    }
    
    public ECaptureWebSocketClient getWsClient() {
        return wsClient;
    }
    
    public EventManager getEventManager() {
        return eventManager;
    }
}

