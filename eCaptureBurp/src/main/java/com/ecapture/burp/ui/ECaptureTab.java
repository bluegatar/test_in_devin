package com.ecapture.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.ecapture.burp.ECaptureBurpExtension;
import com.ecapture.burp.event.EventManager;
import com.ecapture.burp.event.MatchedHttpPair;
import com.ecapture.burp.export.HarExporter;
import com.ecapture.burp.export.HttpBodyCodec;
import com.ecapture.burp.util.DebugLog;
import com.ecapture.burp.websocket.ECaptureWebSocketClient;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Pattern;

import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;

/**
 * Main UI tab for the eCapture Burp extension.
 */
public class ECaptureTab {

    private final MontoyaApi api;
    private final Logging logging;
    private final ECaptureWebSocketClient wsClient;
    private final EventManager eventManager;

    private JPanel mainPanel;
    private JTextField urlField;
    private JButton connectButton;
    private JButton disconnectButton;
    private JLabel statusLabel;
    private JLabel heartbeatLabel;
    private JLabel statsLabel;

    private JTable eventTable;
    private DefaultTableModel tableModel;
    private TableRowSorter<DefaultTableModel> tableSorter;
    private JTextField searchField;
    private JTextArea debugArea;

    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;

    private ECaptureContextMenuProvider contextMenuProvider;

    private static final String[] COLUMN_NAMES = {
            "#", "Time", "Method", "Host", "URL", "Status", "Req Len", "Resp Len", "Process", "Complete"
    };

    // Maps a pair to its (model) row, and the per-row pair list kept strictly
    // in sync with the table model rows. The detail panel indexes into
    // rowPairs (NOT getMatchedPairs()) to avoid misalignment when filtered.
    private final java.util.Map<String, Integer> pairToRowMap = new java.util.concurrent.ConcurrentHashMap<>();
    private final List<MatchedHttpPair> rowPairs = new ArrayList<>();

    public ECaptureTab(MontoyaApi api, ECaptureWebSocketClient wsClient, EventManager eventManager) {
        this.api = api;
        this.logging = api.logging();
        this.wsClient = wsClient;
        this.eventManager = eventManager;

        initializeUI();
        setupListeners();

        this.contextMenuProvider = new ECaptureContextMenuProvider(api, this);
    }

    private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout(5, 5));
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        JPanel topPanel = createTopPanel();
        mainPanel.add(topPanel, BorderLayout.NORTH);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplit.setResizeWeight(0.5);

        // Top half: tabs for the traffic table and the debug log.
        JTabbedPane topTabs = new JTabbedPane();
        topTabs.addTab("Captured Traffic", createTablePanel());
        topTabs.addTab("Debug Log", createDebugPanel());
        mainSplit.setTopComponent(topTabs);

        JSplitPane detailSplit = createDetailSplitPane();
        mainSplit.setBottomComponent(detailSplit);

        mainPanel.add(mainSplit, BorderLayout.CENTER);
    }

    private JPanel createTopPanel() {
        JPanel topPanel = new JPanel(new BorderLayout(10, 5));

        JPanel connectionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        connectionPanel.setBorder(new TitledBorder("Connection"));

        connectionPanel.add(new JLabel("WebSocket URL:"));
        urlField = new JTextField(ECaptureBurpExtension.DEFAULT_WS_URL, 26);
        connectionPanel.add(urlField);

        connectButton = new JButton("Connect");
        connectButton.setBackground(new Color(76, 175, 80));
        connectButton.setForeground(Color.WHITE);
        connectionPanel.add(connectButton);

        disconnectButton = new JButton("Disconnect");
        disconnectButton.setEnabled(false);
        connectionPanel.add(disconnectButton);

        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> clearAll());
        connectionPanel.add(clearButton);

        JButton exportHarButton = new JButton("Export to HAR");
        exportHarButton.addActionListener(e -> exportAllToHar());
        connectionPanel.add(exportHarButton);

        topPanel.add(connectionPanel, BorderLayout.WEST);

        JPanel statusPanel = new JPanel(new GridLayout(3, 1, 5, 2));
        statusPanel.setBorder(new TitledBorder("Status"));

        statusLabel = new JLabel("\u25CF Disconnected");
        statusLabel.setForeground(Color.GRAY);
        statusPanel.add(statusLabel);

        heartbeatLabel = new JLabel("Heartbeat: -");
        statusPanel.add(heartbeatLabel);

        statsLabel = new JLabel("Events: 0 | Pairs: 0 | Pending: 0");
        statusPanel.add(statsLabel);

        topPanel.add(statusPanel, BorderLayout.EAST);

        return topPanel;
    }

    private JPanel createTablePanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(new TitledBorder("Captured HTTP Traffic"));

        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        searchPanel.add(new JLabel("Search:"));
        searchField = new JTextField(30);
        searchField.setToolTipText("Filter by host, URL, method, or process name");
        searchPanel.add(searchField);

        JButton searchButton = new JButton("Filter");
        searchButton.addActionListener(e -> applyFilter());
        searchPanel.add(searchButton);

        JButton clearFilterButton = new JButton("Clear Filter");
        clearFilterButton.addActionListener(e -> {
            searchField.setText("");
            applyFilter();
        });
        searchPanel.add(clearFilterButton);

        panel.add(searchPanel, BorderLayout.NORTH);

        tableModel = new DefaultTableModel(COLUMN_NAMES, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        eventTable = new JTable(tableModel);
        eventTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        eventTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);

        eventTable.getColumnModel().getColumn(0).setPreferredWidth(40);
        eventTable.getColumnModel().getColumn(1).setPreferredWidth(120);
        eventTable.getColumnModel().getColumn(2).setPreferredWidth(60);
        eventTable.getColumnModel().getColumn(3).setPreferredWidth(150);
        eventTable.getColumnModel().getColumn(4).setPreferredWidth(250);
        eventTable.getColumnModel().getColumn(5).setPreferredWidth(50);
        eventTable.getColumnModel().getColumn(6).setPreferredWidth(60);
        eventTable.getColumnModel().getColumn(7).setPreferredWidth(60);
        eventTable.getColumnModel().getColumn(8).setPreferredWidth(120);
        eventTable.getColumnModel().getColumn(9).setPreferredWidth(60);

        tableSorter = new TableRowSorter<>(tableModel);
        // Numeric (natural) sort for numeric columns; default lexicographic
        // sort would order 1,10,11,2 instead of 1,2,3,...,10,11.
        Comparator<Object> numeric = (a, b) -> Long.compare(toLong(a), toLong(b));
        tableSorter.setComparator(0, numeric); // #
        tableSorter.setComparator(5, numeric); // Status
        tableSorter.setComparator(6, numeric); // Req Len
        tableSorter.setComparator(7, numeric); // Resp Len
        eventTable.setRowSorter(tableSorter);

        eventTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelectedPairDetails();
            }
        });

        JScrollPane scrollPane = new JScrollPane(eventTable);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createDebugPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));

        JPanel header = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        JLabel pathLabel = new JLabel("Log file: " + DebugLog.getLogFilePath());
        header.add(pathLabel);
        JButton openButton = new JButton("Open log file");
        openButton.addActionListener(e -> openLogFile());
        header.add(openButton);
        JButton clearLog = new JButton("Clear log view");
        clearLog.addActionListener(e -> debugArea.setText(""));
        header.add(clearLog);
        panel.add(header, BorderLayout.NORTH);

        debugArea = new JTextArea();
        debugArea.setEditable(false);
        debugArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        panel.add(new JScrollPane(debugArea), BorderLayout.CENTER);

        DebugLog.addListener(line -> SwingUtilities.invokeLater(() -> {
            if (debugArea.getDocument().getLength() > 1_000_000) {
                debugArea.replaceRange("", 0, 200_000);
            }
            debugArea.append(line + "\n");
            debugArea.setCaretPosition(debugArea.getDocument().getLength());
        }));

        return panel;
    }

    private JSplitPane createDetailSplitPane() {
        requestEditor = api.userInterface().createHttpRequestEditor(READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(READ_ONLY);

        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(new TitledBorder("Request"));
        requestPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);

        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(new TitledBorder("Response"));
        responsePanel.add(responseEditor.uiComponent(), BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestPanel, responsePanel);
        splitPane.setResizeWeight(0.5);
        splitPane.setDividerLocation(0.5);

        return splitPane;
    }

    private void setupListeners() {
        connectButton.addActionListener(e -> {
            String url = urlField.getText().trim();
            if (url.isEmpty()) {
                JOptionPane.showMessageDialog(mainPanel, "Please enter WebSocket URL",
                        "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            wsClient.connect(url);
        });

        disconnectButton.addActionListener(e -> wsClient.disconnect());

        wsClient.setStateListener(state -> SwingUtilities.invokeLater(() -> {
            switch (state) {
                case CONNECTED:
                    statusLabel.setText("\u25CF Connected");
                    statusLabel.setForeground(new Color(76, 175, 80));
                    connectButton.setEnabled(false);
                    disconnectButton.setEnabled(true);
                    urlField.setEnabled(false);
                    break;
                case CONNECTING:
                    statusLabel.setText("\u25CF Connecting...");
                    statusLabel.setForeground(new Color(255, 193, 7));
                    connectButton.setEnabled(false);
                    disconnectButton.setEnabled(true);
                    break;
                case RECONNECTING:
                    statusLabel.setText("\u25CF Reconnecting...");
                    statusLabel.setForeground(new Color(255, 152, 0));
                    break;
                case DISCONNECTED:
                    statusLabel.setText("\u25CF Disconnected");
                    statusLabel.setForeground(Color.GRAY);
                    connectButton.setEnabled(true);
                    disconnectButton.setEnabled(false);
                    urlField.setEnabled(true);
                    break;
                case ERROR:
                    statusLabel.setText("\u25CF Error");
                    statusLabel.setForeground(Color.RED);
                    break;
            }
        }));

        eventManager.addPairListener(pair -> SwingUtilities.invokeLater(() -> {
            try {
                updateTableSafe(pair);
                updateStats();
            } catch (Exception e) {
                logging.logToError("Error in pair listener: " + e.getMessage());
            }
        }));

        eventManager.addLogListener(log -> DebugLog.log("[eCapture] " + log.trim()));

        searchField.addActionListener(e -> applyFilter());

        Timer statsTimer = new Timer(1000, e -> updateHeartbeatAndStats());
        statsTimer.start();
    }

    private void updateTableSafe(MatchedHttpPair pair) {
        try {
            String pairId = pair.getUuid();
            Integer existingRow = pairToRowMap.get(pairId);

            if (existingRow != null && existingRow < tableModel.getRowCount()) {
                tableModel.setValueAt(pair.getStatusCode(), existingRow, 5);
                tableModel.setValueAt(pair.getResponseLength(), existingRow, 7);
                tableModel.setValueAt(pair.isComplete() ? "\u2713" : "...", existingRow, 9);
            } else {
                int rowNum = tableModel.getRowCount();
                java.util.Vector<Object> rowData = new java.util.Vector<>();
                rowData.add(rowNum + 1);
                rowData.add(pair.getTimestamp());
                rowData.add(pair.getMethod());
                rowData.add(pair.getHost());
                rowData.add(pair.getUrl());
                rowData.add(pair.getStatusCode());
                rowData.add(pair.getRequestLength());
                rowData.add(pair.getResponseLength());
                rowData.add(pair.getProcessInfo());
                rowData.add(pair.isComplete() ? "\u2713" : "...");
                tableModel.addRow(rowData);
                rowPairs.add(pair);
                pairToRowMap.put(pairId, rowNum);
            }
        } catch (Exception e) {
            logging.logToError("Error in updateTableSafe: " + e.getMessage());
        }
    }

    private void updateStats() {
        statsLabel.setText(String.format("Events: %d | Pairs: %d | Pending: %d",
                eventManager.getTotalEventsReceived(),
                eventManager.getTotalPairsMatched(),
                eventManager.getPendingPairsCount()));
    }

    private void updateHeartbeatAndStats() {
        long lastHeartbeat = eventManager.getLastHeartbeatTime();
        if (lastHeartbeat > 0) {
            long elapsed = (System.currentTimeMillis() - lastHeartbeat) / 1000;
            heartbeatLabel.setText(String.format("Heartbeat: %ds ago (count: %d)",
                    elapsed, eventManager.getHeartbeatCount()));
            if (elapsed < 10) {
                heartbeatLabel.setForeground(new Color(76, 175, 80));
            } else if (elapsed < 30) {
                heartbeatLabel.setForeground(new Color(255, 152, 0));
            } else {
                heartbeatLabel.setForeground(Color.RED);
            }
        }
        updateStats();
    }

    private void showSelectedPairDetails() {
        int selectedRow = eventTable.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }
        int modelRow = eventTable.convertRowIndexToModel(selectedRow);
        MatchedHttpPair pair = pairAtModelRow(modelRow);
        if (pair == null) {
            return;
        }

        try {
            if (pair.getRequest() != null && pair.getRequest().getPayload() != null) {
                byte[] decoded = HttpBodyCodec.decodeHttpMessage(pair.getRequest().getPayload());
                requestEditor.setRequest(HttpRequest.httpRequest(ByteArray.byteArray(decoded)));
            } else {
                requestEditor.setRequest(HttpRequest.httpRequest(""));
            }

            if (pair.getResponse() != null && pair.getResponse().getPayload() != null) {
                byte[] decoded = HttpBodyCodec.decodeHttpMessage(pair.getResponse().getPayload());
                responseEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(decoded)));
            } else {
                responseEditor.setResponse(HttpResponse.httpResponse(""));
            }
        } catch (Exception e) {
            logging.logToError("Error showing details: " + e.getMessage());
        }
    }

    private MatchedHttpPair pairAtModelRow(int modelRow) {
        if (modelRow >= 0 && modelRow < rowPairs.size()) {
            return rowPairs.get(modelRow);
        }
        return null;
    }

    private void applyFilter() {
        String filterText = searchField.getText().trim();
        if (filterText.isEmpty()) {
            tableSorter.setRowFilter(null);
        } else {
            try {
                tableSorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(filterText)));
            } catch (Exception e) {
                logging.logToError("Invalid filter pattern: " + e.getMessage());
            }
        }
    }

    private void clearAll() {
        eventManager.clear();
        tableModel.setRowCount(0);
        pairToRowMap.clear();
        rowPairs.clear();
        try {
            requestEditor.setRequest(HttpRequest.httpRequest(""));
            responseEditor.setResponse(HttpResponse.httpResponse(""));
        } catch (Exception e) {
            // ignore
        }
        updateStats();
    }

    /** Export all captured pairs to a HAR file chosen by the user. */
    private void exportAllToHar() {
        exportToHar(new ArrayList<>(rowPairs));
    }

    /** Export the given pairs to a HAR file chosen by the user. */
    public void exportToHar(List<MatchedHttpPair> pairs) {
        if (pairs == null || pairs.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "No captured records to export.",
                    "Export to HAR", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export to HAR");
        chooser.setSelectedFile(new java.io.File("ecapture-" + System.currentTimeMillis() + ".har"));
        if (chooser.showSaveDialog(mainPanel) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        java.io.File file = chooser.getSelectedFile();
        if (!file.getName().toLowerCase().endsWith(".har")) {
            file = new java.io.File(file.getParentFile(), file.getName() + ".har");
        }
        try (FileWriter writer = new FileWriter(file, StandardCharsets.UTF_8)) {
            writer.write(HarExporter.toHar(pairs));
            JOptionPane.showMessageDialog(mainPanel,
                    "Exported " + pairs.size() + " record(s) to:\n" + file.getAbsolutePath(),
                    "Export to HAR", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            logging.logToError("HAR export failed: " + e.getMessage());
            JOptionPane.showMessageDialog(mainPanel, "Export failed: " + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void openLogFile() {
        try {
            java.io.File f = new java.io.File(DebugLog.getLogFilePath());
            if (Desktop.isDesktopSupported() && f.exists()) {
                Desktop.getDesktop().open(f);
            } else {
                JOptionPane.showMessageDialog(mainPanel, "Log file: " + f.getAbsolutePath(),
                        "Debug Log", JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(mainPanel, "Log file: " + DebugLog.getLogFilePath(),
                    "Debug Log", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private static long toLong(Object v) {
        if (v instanceof Number) {
            return ((Number) v).longValue();
        }
        if (v != null) {
            try {
                return Long.parseLong(v.toString().trim());
            } catch (NumberFormatException ignored) {
            }
        }
        return Long.MIN_VALUE;
    }

    /** Get the single selected pair (for context menu single-row actions). */
    public MatchedHttpPair getSelectedPair() {
        int selectedRow = eventTable.getSelectedRow();
        if (selectedRow < 0) {
            return null;
        }
        return pairAtModelRow(eventTable.convertRowIndexToModel(selectedRow));
    }

    /** Get all selected pairs (for multi-row context menu actions). */
    public List<MatchedHttpPair> getSelectedPairs() {
        List<MatchedHttpPair> result = new ArrayList<>();
        int[] viewRows = eventTable.getSelectedRows();
        for (int viewRow : viewRows) {
            MatchedHttpPair pair = pairAtModelRow(eventTable.convertRowIndexToModel(viewRow));
            if (pair != null) {
                result.add(pair);
            }
        }
        return result;
    }

    public JTable getEventTable() {
        return eventTable;
    }

    public Component getComponent() {
        return mainPanel;
    }

    public ContextMenuItemsProvider getContextMenuProvider() {
        return contextMenuProvider;
    }
}
