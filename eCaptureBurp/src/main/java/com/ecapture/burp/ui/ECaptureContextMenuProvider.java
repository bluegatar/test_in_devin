package com.ecapture.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.ecapture.burp.event.CapturedEvent;
import com.ecapture.burp.event.MatchedHttpPair;
import com.ecapture.burp.export.HttpBodyCodec;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Provides a right-click context menu for the captured-traffic table.
 */
public class ECaptureContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final Logging logging;
    private final ECaptureTab tab;

    public ECaptureContextMenuProvider(MontoyaApi api, ECaptureTab tab) {
        this.api = api;
        this.logging = api.logging();
        this.tab = tab;
        setupTableContextMenu();
    }

    private void setupTableContextMenu() {
        JTable table = tab.getEventTable();
        JPopupMenu popupMenu = new JPopupMenu();

        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        sendToRepeater.addActionListener(e -> sendSelectedToRepeater());
        popupMenu.add(sendToRepeater);

        popupMenu.addSeparator();

        JMenuItem exportSelected = new JMenuItem("Export selected to HAR");
        exportSelected.addActionListener(e -> tab.exportToHar(tab.getSelectedPairs()));
        popupMenu.add(exportSelected);

        popupMenu.addSeparator();

        JMenuItem copyRequest = new JMenuItem("Copy Request");
        copyRequest.addActionListener(e -> copySelectedRequest());
        popupMenu.add(copyRequest);

        JMenuItem copyResponse = new JMenuItem("Copy Response");
        copyResponse.addActionListener(e -> copySelectedResponse());
        popupMenu.add(copyResponse);

        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> copySelectedUrl());
        popupMenu.add(copyUrl);

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                handlePopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                handlePopup(e);
            }

            private void handlePopup(MouseEvent e) {
                if (!e.isPopupTrigger()) {
                    return;
                }
                int row = table.rowAtPoint(e.getPoint());
                if (row >= 0 && row < table.getRowCount()) {
                    // Preserve a multi-row selection if the click is inside it;
                    // otherwise select just the clicked row.
                    boolean withinSelection = false;
                    for (int sel : table.getSelectedRows()) {
                        if (sel == row) {
                            withinSelection = true;
                            break;
                        }
                    }
                    if (!withinSelection) {
                        table.setRowSelectionInterval(row, row);
                    }
                }

                List<MatchedHttpPair> selected = tab.getSelectedPairs();
                int count = selected.size();
                MatchedHttpPair single = count == 1 ? selected.get(0) : null;
                boolean hasRequest = single != null && single.hasRequest();
                boolean hasResponse = single != null && single.hasResponse();

                sendToRepeater.setEnabled(hasRequest);
                copyRequest.setEnabled(hasRequest);
                copyResponse.setEnabled(hasResponse);
                copyUrl.setEnabled(hasRequest);
                exportSelected.setEnabled(count > 0);
                exportSelected.setText("Export selected to HAR (" + count + " row" + (count == 1 ? "" : "s") + ")");

                popupMenu.show(e.getComponent(), e.getX(), e.getY());
            }
        });
    }

    private void sendSelectedToRepeater() {
        MatchedHttpPair pair = tab.getSelectedPair();
        if (pair == null || !pair.hasRequest()) {
            return;
        }
        try {
            HttpRequest request = buildHttpRequest(pair);
            if (request != null) {
                String tabName = pair.getMethod() + " " + pair.getUrl();
                if (tabName.length() > 50) {
                    tabName = tabName.substring(0, 47) + "...";
                }
                api.repeater().sendToRepeater(request, tabName);
            } else {
                JOptionPane.showMessageDialog(tab.getEventTable(),
                        "Failed to build HTTP request. Host information may be missing.",
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        } catch (Exception e) {
            logging.logToError("Error sending to Repeater: " + e.getMessage());
        }
    }

    private void copySelectedRequest() {
        MatchedHttpPair pair = tab.getSelectedPair();
        if (pair == null || !pair.hasRequest()) {
            return;
        }
        CapturedEvent request = pair.getRequest();
        if (request.getPayload() != null) {
            byte[] decoded = HttpBodyCodec.decodeHttpMessage(request.getPayload());
            copyToClipboard(new String(decoded, StandardCharsets.UTF_8));
        }
    }

    private void copySelectedResponse() {
        MatchedHttpPair pair = tab.getSelectedPair();
        if (pair == null || !pair.hasResponse()) {
            return;
        }
        CapturedEvent response = pair.getResponse();
        if (response.getPayload() != null) {
            byte[] decoded = HttpBodyCodec.decodeHttpMessage(response.getPayload());
            copyToClipboard(new String(decoded, StandardCharsets.UTF_8));
        }
    }

    private void copySelectedUrl() {
        MatchedHttpPair pair = tab.getSelectedPair();
        if (pair == null || !pair.hasRequest()) {
            return;
        }
        String host = pair.getHost();
        String url = pair.getUrl();
        int port = pair.getPort();
        boolean useHttps = pair.isHttps();
        String fullUrl;
        if (port == 80 || port == 443 || port <= 0) {
            fullUrl = (useHttps ? "https://" : "http://") + host + url;
        } else {
            fullUrl = (useHttps ? "https://" : "http://") + host + ":" + port + url;
        }
        copyToClipboard(fullUrl);
    }

    private HttpRequest buildHttpRequest(MatchedHttpPair pair) {
        CapturedEvent request = pair.getRequest();
        if (request == null || request.getPayload() == null) {
            return null;
        }
        String host = pair.getHost();
        if (host == null || host.isEmpty() || host.equals("0.0.0.0") || host.equals("-")) {
            return null;
        }
        int port = pair.getPort();
        if (port <= 0) port = 443;
        boolean useHttps = (port == 443 || port == 8443);
        try {
            HttpService httpService = HttpService.httpService(host, port, useHttps);
            byte[] decoded = HttpBodyCodec.decodeHttpMessage(request.getPayload());
            return HttpRequest.httpRequest(httpService, ByteArray.byteArray(decoded));
        } catch (Exception e) {
            logging.logToError("Error building HttpRequest: " + e.getMessage());
            return null;
        }
    }

    private void copyToClipboard(String text) {
        java.awt.datatransfer.StringSelection selection = new java.awt.datatransfer.StringSelection(text);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        return new ArrayList<>();
    }
}
