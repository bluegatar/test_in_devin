using System;
using System.Drawing;
using System.Windows.Forms;
using ECaptureFiddler.Core;
using Fiddler;

[assembly: RequiredVersion("4.0.0.0")]

namespace ECaptureFiddler.Fiddler
{
    /// <summary>
    /// Fiddler Classic extension that connects to eCapture over WebSocket,
    /// reassembles + pairs HTTP/1.x traffic, decompresses bodies, and injects
    /// each pair into the Fiddler session list as a synthetic Session.
    /// </summary>
    public sealed class ECaptureExtension : IFiddlerExtension
    {
        public const string DefaultUrl = "ws://127.0.0.1:28257/";

        private EventManager _eventManager;
        private ECaptureWebSocketClient _wsClient;

        private TabPage _tab;
        private TextBox _urlBox;
        private Button _connectBtn;
        private Button _disconnectBtn;
        private Label _statusLabel;
        private Label _statsLabel;
        private TextBox _logBox;
        private System.Windows.Forms.Timer _statsTimer;

        public void OnLoad()
        {
            _eventManager = new EventManager();
            _wsClient = new ECaptureWebSocketClient(_eventManager);

            _eventManager.PairUpdated += OnPairUpdated;
            _eventManager.Log += AppendLog;
            _wsClient.Log += AppendLog;
            SessionInjector.Log = AppendLog;
            _wsClient.StateChanged += OnStateChanged;

            BuildUi();
        }

        public void OnBeforeUnload()
        {
            try { _wsClient?.Disconnect(); } catch { }
            try { _statsTimer?.Stop(); } catch { }
        }

        private void BuildUi()
        {
            _tab = new TabPage("eCapture");

            var top = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 40, Padding = new Padding(5) };
            top.Controls.Add(new Label { Text = "WS URL:", AutoSize = true, Padding = new Padding(0, 6, 0, 0) });
            _urlBox = new TextBox { Text = DefaultUrl, Width = 240 };
            top.Controls.Add(_urlBox);

            _connectBtn = new Button { Text = "Connect", BackColor = Color.FromArgb(76, 175, 80), ForeColor = Color.White };
            _connectBtn.Click += (s, e) => _wsClient.Connect(_urlBox.Text.Trim());
            top.Controls.Add(_connectBtn);

            _disconnectBtn = new Button { Text = "Disconnect", Enabled = false };
            _disconnectBtn.Click += (s, e) => _wsClient.Disconnect();
            top.Controls.Add(_disconnectBtn);

            var clearBtn = new Button { Text = "Clear Counters" };
            clearBtn.Click += (s, e) => _eventManager.Clear();
            top.Controls.Add(clearBtn);

            var exportBtn = new Button { Text = "Export all to HAR" };
            exportBtn.Click += (s, e) => ExportAllToHar();
            top.Controls.Add(exportBtn);

            var status = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 28, Padding = new Padding(5, 2, 5, 2) };
            _statusLabel = new Label { Text = "\u25CF Disconnected", ForeColor = Color.Gray, AutoSize = true };
            status.Controls.Add(_statusLabel);
            _statsLabel = new Label { Text = "   Events: 0 | Pairs: 0 | Pending: 0 | Heartbeat: -", AutoSize = true };
            status.Controls.Add(_statsLabel);

            _logBox = new TextBox
            {
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Both,
                WordWrap = false,
                Dock = DockStyle.Fill,
                Font = new Font(FontFamily.GenericMonospace, 8.5f)
            };

            var logHeader = new Label { Text = "Debug Log", Dock = DockStyle.Top, Height = 18, Padding = new Padding(5, 2, 0, 0) };

            _tab.Controls.Add(_logBox);
            _tab.Controls.Add(logHeader);
            _tab.Controls.Add(status);
            _tab.Controls.Add(top);

            FiddlerApplication.UI.tabsViews.TabPages.Add(_tab);

            _statsTimer = new System.Windows.Forms.Timer { Interval = 1000 };
            _statsTimer.Tick += (s, e) => UpdateStats();
            _statsTimer.Start();

            AppendLog("eCapture Fiddler extension loaded. Enter the eCaptureQ WS URL and click Connect.");
        }

        private void OnPairUpdated(MatchedHttpPair pair)
        {
            if (pair == null || !pair.IsComplete || pair.Injected) return;
            pair.Injected = true;
            UiInvoke(() => SessionInjector.Inject(pair));
        }

        private void OnStateChanged(ConnectionState state)
        {
            UiInvoke(() =>
            {
                switch (state)
                {
                    case ConnectionState.Connected:
                        _statusLabel.Text = "\u25CF Connected";
                        _statusLabel.ForeColor = Color.FromArgb(76, 175, 80);
                        _connectBtn.Enabled = false; _disconnectBtn.Enabled = true; _urlBox.Enabled = false;
                        break;
                    case ConnectionState.Connecting:
                        _statusLabel.Text = "\u25CF Connecting..."; _statusLabel.ForeColor = Color.Orange;
                        _connectBtn.Enabled = false; _disconnectBtn.Enabled = true;
                        break;
                    case ConnectionState.Reconnecting:
                        _statusLabel.Text = "\u25CF Reconnecting..."; _statusLabel.ForeColor = Color.DarkOrange;
                        break;
                    case ConnectionState.Disconnected:
                        _statusLabel.Text = "\u25CF Disconnected"; _statusLabel.ForeColor = Color.Gray;
                        _connectBtn.Enabled = true; _disconnectBtn.Enabled = false; _urlBox.Enabled = true;
                        break;
                    case ConnectionState.Error:
                        _statusLabel.Text = "\u25CF Error"; _statusLabel.ForeColor = Color.Red;
                        break;
                }
            });
        }

        private void UpdateStats()
        {
            string hb = _eventManager.LastHeartbeatUtc == default(DateTime)
                ? "-"
                : (int)(DateTime.UtcNow - _eventManager.LastHeartbeatUtc).TotalSeconds + "s ago";
            _statsLabel.Text = string.Format("   Events: {0} | Pairs: {1} | Pending: {2} | Heartbeat: {3}",
                _eventManager.TotalEvents, _eventManager.TotalPairs, _eventManager.PendingCount, hb);
        }

        private void ExportAllToHar()
        {
            try
            {
                var sessions = FiddlerApplication.UI.GetAllSessions();
                if (sessions == null || sessions.Length == 0)
                {
                    MessageBox.Show("No sessions to export.", "Export to HAR");
                    return;
                }
                // Use Fiddler's built-in HAR 1.2 exporter (prompts for a file).
                FiddlerApplication.DoExport("HTTPArchive v1.2", sessions, null, null);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Export failed: " + ex.Message + "\n\nYou can also use File \u2192 Export Sessions \u2192 All Sessions \u2192 HTTPArchive v1.2.",
                    "Export to HAR");
            }
        }

        private void AppendLog(string line)
        {
            UiInvoke(() =>
            {
                if (_logBox.TextLength > 1_000_000) _logBox.Text = _logBox.Text.Substring(200_000);
                _logBox.AppendText("[" + DateTime.Now.ToString("HH:mm:ss.fff") + "] " + line + "\r\n");
            });
        }

        private void UiInvoke(Action action)
        {
            try
            {
                // FiddlerApplication.UI is the main window (a Form); marshal onto
                // its thread so synthetic-session injection and log/stat updates
                // happen on the UI thread regardless of whether our tab is open.
                var form = FiddlerApplication.UI as Control;
                if (form != null && !form.IsDisposed && form.InvokeRequired)
                {
                    form.BeginInvoke(action);
                    return;
                }
                action();
            }
            catch { /* UI may be tearing down */ }
        }
    }
}
