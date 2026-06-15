package com.ecapture.burp.util;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Lightweight debug logger that writes to an on-disk file in the user's home
 * directory and fans out to in-panel listeners (the "Debug Log" tab). Burp's
 * Extensions &rarr; Output tab is not reliably visible in every build, so we
 * surface debug output here instead.
 */
public final class DebugLog {

    private DebugLog() {}

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
    private static final List<Consumer<String>> LISTENERS = new CopyOnWriteArrayList<>();
    private static final List<String> RING = new CopyOnWriteArrayList<>();
    private static final int RING_MAX = 5000;

    private static volatile boolean enabled = true;
    private static volatile File logFile;
    private static PrintWriter writer;

    public static synchronized void init() {
        try {
            String home = System.getProperty("user.home", ".");
            logFile = new File(home, "ecapture-burp-debug.log");
            writer = new PrintWriter(new FileWriter(logFile, false), true);
            log("DEBUG BUILD loaded. Debug log file: " + logFile.getAbsolutePath());
        } catch (Exception e) {
            writer = null;
        }
    }

    public static String getLogFilePath() {
        return logFile != null ? logFile.getAbsolutePath() : "(not initialized)";
    }

    public static void addListener(Consumer<String> listener) {
        LISTENERS.add(listener);
        // Replay existing buffer to a freshly attached listener.
        for (String line : new ArrayList<>(RING)) {
            try {
                listener.accept(line);
            } catch (Exception ignored) {
            }
        }
    }

    public static void setEnabled(boolean on) {
        enabled = on;
    }

    public static void log(String msg) {
        if (!enabled) return;
        String line = "[" + LocalDateTime.now().format(TS) + "] " + msg;
        RING.add(line);
        while (RING.size() > RING_MAX) {
            RING.remove(0);
        }
        PrintWriter w = writer;
        if (w != null) {
            w.println(line);
        }
        for (Consumer<String> l : LISTENERS) {
            try {
                l.accept(line);
            } catch (Exception ignored) {
            }
        }
    }
}
