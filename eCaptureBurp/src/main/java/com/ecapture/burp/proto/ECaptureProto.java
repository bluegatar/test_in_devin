package com.ecapture.burp.proto;

import com.google.protobuf.ByteString;
import com.google.protobuf.CodedInputStream;
import com.google.protobuf.InvalidProtocolBufferException;

import java.io.IOException;

/**
 * Manual implementation of eCapture protobuf messages.
 * This is a simplified implementation that parses the protobuf wire format directly.
 */
public final class ECaptureProto {

    private ECaptureProto() {}

    /**
     * Log type enum
     */
    public enum LogType {
        LOG_TYPE_HEARTBEAT(0),
        LOG_TYPE_PROCESS_LOG(1),
        LOG_TYPE_EVENT(2),
        UNRECOGNIZED(-1);

        private final int value;

        LogType(int value) {
            this.value = value;
        }

        public int getNumber() {
            return value;
        }

        public static LogType forNumber(int value) {
            switch (value) {
                case 0: return LOG_TYPE_HEARTBEAT;
                case 1: return LOG_TYPE_PROCESS_LOG;
                case 2: return LOG_TYPE_EVENT;
                default: return UNRECOGNIZED;
            }
        }
    }

    /**
     * Event message - represents a captured HTTP event
     */
    public static final class Event {
        private long timestamp;
        private String uuid = "";
        private String srcIp = "";
        private int srcPort;
        private String dstIp = "";
        private int dstPort;
        private long pid;
        private String pname = "";
        private int type;
        private int length;
        private ByteString payload = ByteString.EMPTY;

        public long getTimestamp() { return timestamp; }
        public String getUuid() { return uuid; }
        public String getSrcIp() { return srcIp; }
        public int getSrcPort() { return srcPort; }
        public String getDstIp() { return dstIp; }
        public int getDstPort() { return dstPort; }
        public long getPid() { return pid; }
        public String getPname() { return pname; }
        public int getType() { return type; }
        public int getLength() { return length; }
        public ByteString getPayload() { return payload; }

        public static Event parseFrom(byte[] data) throws InvalidProtocolBufferException {
            try {
                return parseFrom(CodedInputStream.newInstance(data));
            } catch (IOException e) {
                throw new InvalidProtocolBufferException(e);
            }
        }

        public static Event parseFrom(CodedInputStream input) throws IOException {
            Event event = new Event();
            while (!input.isAtEnd()) {
                int tag = input.readTag();
                switch (tag) {
                    case 0:
                        return event;
                    case 8: // field 1: timestamp (int64)
                        event.timestamp = input.readInt64();
                        break;
                    case 18: // field 2: uuid (string)
                        event.uuid = input.readStringRequireUtf8();
                        break;
                    case 26: // field 3: src_ip (string)
                        event.srcIp = input.readStringRequireUtf8();
                        break;
                    case 32: // field 4: src_port (uint32)
                        event.srcPort = input.readUInt32();
                        break;
                    case 42: // field 5: dst_ip (string)
                        event.dstIp = input.readStringRequireUtf8();
                        break;
                    case 48: // field 6: dst_port (uint32)
                        event.dstPort = input.readUInt32();
                        break;
                    case 56: // field 7: pid (int64)
                        event.pid = input.readInt64();
                        break;
                    case 66: // field 8: pname (string)
                        event.pname = input.readStringRequireUtf8();
                        break;
                    case 72: // field 9: type (uint32)
                        event.type = input.readUInt32();
                        break;
                    case 80: // field 10: length (uint32)
                        event.length = input.readUInt32();
                        break;
                    case 90: // field 11: payload (bytes)
                        event.payload = input.readBytes();
                        break;
                    default:
                        input.skipField(tag);
                        break;
                }
            }
            return event;
        }

        @Override
        public String toString() {
            return String.format("Event{timestamp=%d, uuid='%s', src=%s:%d, dst=%s:%d, pid=%d, pname='%s', type=%d, len=%d}",
                    timestamp, uuid, srcIp, srcPort, dstIp, dstPort, pid, pname, type, length);
        }
    }

    /**
     * Heartbeat message - connection keep-alive
     */
    public static final class Heartbeat {
        private long timestamp;
        private long count;
        private String message = "";

        public long getTimestamp() { return timestamp; }
        public long getCount() { return count; }
        public String getMessage() { return message; }

        public static Heartbeat parseFrom(byte[] data) throws InvalidProtocolBufferException {
            try {
                return parseFrom(CodedInputStream.newInstance(data));
            } catch (IOException e) {
                throw new InvalidProtocolBufferException(e);
            }
        }

        public static Heartbeat parseFrom(CodedInputStream input) throws IOException {
            Heartbeat hb = new Heartbeat();
            while (!input.isAtEnd()) {
                int tag = input.readTag();
                switch (tag) {
                    case 0:
                        return hb;
                    case 8: // field 1: timestamp (int64)
                        hb.timestamp = input.readInt64();
                        break;
                    case 16: // field 2: count (int64)
                        hb.count = input.readInt64();
                        break;
                    case 26: // field 3: message (string)
                        hb.message = input.readStringRequireUtf8();
                        break;
                    default:
                        input.skipField(tag);
                        break;
                }
            }
            return hb;
        }

        @Override
        public String toString() {
            return String.format("Heartbeat{timestamp=%d, count=%d, message='%s'}",
                    timestamp, count, message);
        }
    }

    /**
     * LogEntry - top level message wrapper
     */
    public static final class LogEntry {
        private LogType logType = LogType.LOG_TYPE_HEARTBEAT;
        private Event eventPayload;
        private Heartbeat heartbeatPayload;
        private String runLog;

        public LogType getLogType() { return logType; }
        
        public boolean hasEventPayload() { return eventPayload != null; }
        public Event getEventPayload() { return eventPayload; }
        
        public boolean hasHeartbeatPayload() { return heartbeatPayload != null; }
        public Heartbeat getHeartbeatPayload() { return heartbeatPayload; }
        
        public boolean hasRunLog() { return runLog != null; }
        public String getRunLog() { return runLog != null ? runLog : ""; }

        public static LogEntry parseFrom(byte[] data) throws InvalidProtocolBufferException {
            try {
                CodedInputStream input = CodedInputStream.newInstance(data);
                LogEntry entry = new LogEntry();
                
                while (!input.isAtEnd()) {
                    int tag = input.readTag();
                    switch (tag) {
                        case 0:
                            return entry;
                        case 8: // field 1: log_type (enum)
                            entry.logType = LogType.forNumber(input.readEnum());
                            break;
                        case 18: // field 2: event_payload (message)
                            int eventLength = input.readRawVarint32();
                            byte[] eventBytes = input.readRawBytes(eventLength);
                            entry.eventPayload = Event.parseFrom(eventBytes);
                            break;
                        case 26: // field 3: heartbeat_payload (message)
                            int hbLength = input.readRawVarint32();
                            byte[] hbBytes = input.readRawBytes(hbLength);
                            entry.heartbeatPayload = Heartbeat.parseFrom(hbBytes);
                            break;
                        case 34: // field 4: run_log (string)
                            entry.runLog = input.readStringRequireUtf8();
                            break;
                        default:
                            input.skipField(tag);
                            break;
                    }
                }
                return entry;
            } catch (IOException e) {
                throw new InvalidProtocolBufferException(e);
            }
        }

        @Override
        public String toString() {
            return String.format("LogEntry{logType=%s, event=%s, heartbeat=%s, runLog=%s}",
                    logType, eventPayload, heartbeatPayload, runLog != null ? "'" + runLog + "'" : "null");
        }
    }
}
