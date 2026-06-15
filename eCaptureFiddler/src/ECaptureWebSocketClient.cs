using System;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;

namespace ECaptureFiddler.Core
{
    public enum ConnectionState { Disconnected, Connecting, Connected, Reconnecting, Error }

    /// <summary>
    /// Connects to the eCapture eCaptureQ WebSocket server, receives binary
    /// protobuf frames, parses them and feeds the <see cref="EventManager"/>.
    /// Auto-reconnects with exponential backoff. No Fiddler dependency.
    /// </summary>
    public sealed class ECaptureWebSocketClient
    {
        private readonly EventManager _eventManager;
        private ClientWebSocket _ws;
        private CancellationTokenSource _cts;
        private string _url;
        private volatile bool _shouldReconnect;
        private int _attempts;

        public event Action<ConnectionState> StateChanged;
        public event Action<string> Log;
        public ConnectionState State { get; private set; } = ConnectionState.Disconnected;

        public ECaptureWebSocketClient(EventManager eventManager)
        {
            _eventManager = eventManager;
        }

        public void Connect(string url)
        {
            _url = url;
            _shouldReconnect = true;
            _attempts = 0;
            _cts = new CancellationTokenSource();
            Task.Run(() => RunLoop(_cts.Token));
        }

        public void Disconnect()
        {
            _shouldReconnect = false;
            try { _cts?.Cancel(); } catch { }
            try
            {
                _ws?.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye", CancellationToken.None)
                    .Wait(1000);
            }
            catch { }
            SetState(ConnectionState.Disconnected);
        }

        private async Task RunLoop(CancellationToken token)
        {
            while (_shouldReconnect && !token.IsCancellationRequested)
            {
                try
                {
                    SetState(_attempts > 0 ? ConnectionState.Reconnecting : ConnectionState.Connecting);
                    _ws = new ClientWebSocket();
                    _ws.Options.SetRequestHeader("Origin", "http://localhost");
                    Log?.Invoke("Connecting to " + _url + (_attempts > 0 ? $" (attempt {_attempts + 1})" : ""));
                    await _ws.ConnectAsync(new Uri(_url), token).ConfigureAwait(false);
                    _attempts = 0;
                    SetState(ConnectionState.Connected);
                    Log?.Invoke("Connected to eCapture WebSocket server!");
                    await ReceiveLoop(token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Log?.Invoke("WebSocket error: " + ex.Message);
                    SetState(ConnectionState.Error);
                }

                if (!_shouldReconnect || token.IsCancellationRequested) break;
                int delay = Math.Min(2 * (1 << Math.Min(_attempts, 4)), 30);
                _attempts++;
                SetState(ConnectionState.Reconnecting);
                Log?.Invoke($"Reconnecting in {delay}s...");
                try { await Task.Delay(delay * 1000, token).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
            SetState(ConnectionState.Disconnected);
        }

        private async Task ReceiveLoop(CancellationToken token)
        {
            var buffer = new byte[64 * 1024];
            using (var ms = new System.IO.MemoryStream())
            {
                while (_ws.State == WebSocketState.Open && !token.IsCancellationRequested)
                {
                    ms.SetLength(0);
                    WebSocketReceiveResult result;
                    do
                    {
                        result = await _ws.ReceiveAsync(new ArraySegment<byte>(buffer), token).ConfigureAwait(false);
                        if (result.MessageType == WebSocketMessageType.Close)
                        {
                            Log?.Invoke("WebSocket closed by server.");
                            return;
                        }
                        ms.Write(buffer, 0, result.Count);
                    } while (!result.EndOfMessage);

                    if (result.MessageType == WebSocketMessageType.Binary)
                        HandleBinary(ms.ToArray());
                    else
                        Log?.Invoke($"[WS] <<< TEXT message: {ms.Length} bytes (unexpected)");
                }
            }
        }

        private void HandleBinary(byte[] data)
        {
            try
            {
                var entry = LogEntry.Parse(data);
                switch (entry.LogType)
                {
                    case LogType.Heartbeat:
                        if (entry.Heartbeat != null)
                            _eventManager.ProcessHeartbeat(entry.Heartbeat.Timestamp,
                                entry.Heartbeat.Count, entry.Heartbeat.Message);
                        break;
                    case LogType.ProcessLog:
                        _eventManager.ProcessRuntimeLog(entry.RunLog);
                        break;
                    case LogType.Event:
                        if (entry.Event != null)
                        {
                            var ce = new CapturedEvent(entry.Event.Timestamp, entry.Event.DstIp,
                                (int)entry.Event.DstPort, entry.Event.Pid, entry.Event.Pname,
                                entry.Event.Payload);
                            _eventManager.ProcessEvent(ce);
                        }
                        break;
                }
            }
            catch (Exception ex)
            {
                Log?.Invoke("Failed to parse protobuf message: " + ex.Message);
            }
        }

        private void SetState(ConnectionState s)
        {
            State = s;
            StateChanged?.Invoke(s);
        }
    }
}
