# eCapture → Fiddler Classic 插件

把 [eCapture](https://github.com/gojue/ecapture) 通过 eBPF 抓到的 TLS/HTTP 明文，
经 WebSocket（eCaptureQ）实时送进 **Fiddler Classic** 的会话列表里查看、检索、导出。

本插件是 [eCaptureBurp](../eCaptureBurp) 的 C# 移植版，核心逻辑完全一致：

```
┌──────────────┐   WebSocket + protobuf   ┌──────────────────────────────┐
│   eCapture   │ ───────────────────────> │   ECaptureFiddler.dll         │
│ (手机/Android)│  ws://手机IP:28257/      │  ┌────────────────────────┐  │
└──────────────┘                          │  │ protobuf 解析(自带)     │  │
                                          │  │ text-mode 事件头解析    │  │
                                          │  │ PID_TID 配对 + 分片重组 │  │
                                          │  │ de-chunk + 解压(gzip..) │  │
                                          │  └───────────┬────────────┘  │
                                          │     合成 Session 注入         │
                                          │  Fiddler 会话列表 + Inspectors│
                                          └──────────────────────────────┘
```

> 适用：**Fiddler Classic**（基于 .NET Framework 的 Windows 版）。
> Fiddler Everywhere 是另一套扩展模型，本插件不适用。

---

## 1. 它做了什么（与 Burp 版一致）

- **WebSocket 客户端**：连 eCapture 的 `--ecaptureq=ws://...`，接收二进制 protobuf 帧。
- **protobuf 解析**：内置极简 proto3 解码器（无外部依赖，单 DLL 即可用），解析
  `LogEntry / Event / Heartbeat`。
- **text-mode 事件头解析**：eCaptureQ text 模式下 payload 形如
  `[ts] PID:.. Comm:.. TID:.. FD:.. WRITE|READ (N bytes):\n<HTTP>`；按方向判定
  WRITE=请求 / READ=响应，剥掉事件头取真正的 HTTP 字节，`Tuple:` 连接事件忽略。
- **分片重组**：按连接键 `PID_TID` 把被拆成多个 SSL_read/SSL_write 事件的同一条 HTTP
  消息拼起来，按 `Content-Length` 或 chunked 终止符判完整。
- **配对**：同一连接内 FIFO 配对请求/响应，响应乱序到达也能配回正确请求。
- **解码**：先 de-chunk，再按 `Content-Encoding` + 魔数循环解压
  **gzip / deflate(zlib) / br**，一直解到不再是压缩格式为止。
- **注入 Fiddler**：把请求/响应合成为 Fiddler `Session` 注入会话列表，于是 Fiddler 原生的
  Inspectors、查找、以及 **导出 HAR**（File → Export Sessions）全部可用。

> ⚠️ Brotli 说明：`br` 解压依赖 `System.IO.Compression.BrotliStream`，该类型只在
> .NET Core/.NET 5+ 存在。**.NET Framework 4.8 上没有 Brotli**，此时 `br` 响应会原样
> 显示（不解压）。gzip/deflate 不受影响（绝大多数响应是 gzip）。如确需 Brotli，可在工程里
> 加 `Brotli.NET` NuGet 包并改 `HttpBodyCodec.Brotli`。

---

## 2. 编译出 DLL

### 前置条件（在 Windows 上）
- 已安装 **Fiddler Classic**（用来引用 `Fiddler.exe`）。
- **.NET Framework 4.8 开发包**（Developer Pack）。
- 以下任一构建工具：
  - **.NET SDK**（命令行 `dotnet`），或
  - **Visual Studio 2019/2022**（含「.NET 桌面开发」工作负载），或
  - **Build Tools for Visual Studio**（提供 `msbuild`）。

### 方式 A：一键脚本（推荐）
```bat
cd eCaptureFiddler
build.bat
```
脚本会自动定位 Fiddler.exe（常见安装路径），调用 `dotnet` 或 `msbuild` 编译。
若自动定位失败，手动指定 Fiddler 安装目录：
```bat
build.bat "C:\Users\你的用户名\AppData\Local\Programs\Fiddler"
```

### 方式 B：dotnet 命令行
```bat
cd eCaptureFiddler
dotnet build ECaptureFiddler.csproj -c Release ^
  /p:FiddlerPath="C:\Users\你的用户名\AppData\Local\Programs\Fiddler"
```

### 方式 C：Visual Studio
1. 用 VS 打开 `ECaptureFiddler.csproj`。
2. 如果引用 `Fiddler` 报红：右键「引用 / Dependencies」→ 删除原 Fiddler 引用 →
   重新「添加引用」→ 浏览到你的 `Fiddler.exe`（如
   `%LOCALAPPDATA%\Programs\Fiddler\Fiddler.exe`）。
3. 选择 **Release**，生成。

编译产物：`eCaptureFiddler\bin\Release\ECaptureFiddler.dll`

---

## 3. 安装到 Fiddler

1. **关闭** Fiddler Classic。
2. 把 `ECaptureFiddler.dll` 复制到下面任一「扩展/Inspectors」目录（推荐第一个）：
   - `%USERPROFILE%\Documents\Fiddler2\Inspectors\`
   - 或 Fiddler 安装目录下的 `Inspectors\`（如 `%LOCALAPPDATA%\Programs\Fiddler\Inspectors\`）

   > 目录不存在就手动新建 `Inspectors` 文件夹。
3. **解除锁定（重要）**：DLL 若来自下载/网络，Windows 会标记为「来自其他计算机」导致
   Fiddler 拒绝加载。右键 `ECaptureFiddler.dll` → 属性 → 勾选「解除锁定 (Unblock)」→ 确定。
   （或 PowerShell：`Unblock-File "路径\ECaptureFiddler.dll"`）
4. 启动 Fiddler Classic。顶部主标签栏应出现一个新标签 **「eCapture」**。
   - 若想确认是否加载成功：菜单 **Help → About** 或 **Tools → ...**，以及
     **Rules → ...** 不一定显示扩展；最直接的判据就是有没有出现「eCapture」标签页。

---

## 4. 使用

### 4.1 手机端启动 eCapture
在被抓的 Android 设备上（已 root / 具备 eBPF 条件）：
```bash
./ecapture tls --ecaptureq=ws://<手机IP>:28257/
```
例如手机 IP 是 `192.168.1.83`：
```bash
./ecapture tls --ecaptureq=ws://192.168.1.83:28257/
```
看到 `Listen for eCaptureQ=ws://192.168.1.83:28257/` 即表示监听已就绪。

### 4.2 PC 端 Fiddler 连接
1. 打开 Fiddler 的 **eCapture** 标签页。
2. **WS URL** 填 `ws://<手机IP>:28257/`（如 `ws://192.168.1.83:28257/`）。
   - 注意：URL 用**手机的 IP**（eCapture 在手机上监听），不是 PC 的 IP。
3. 点 **Connect**。状态变为绿色「● Connected」，下方计数器开始动
   （Events / Pairs / Pending / Heartbeat）。
4. 在手机上操作目标 App 产生 HTTPS 流量。
5. 配对完成的请求/响应会作为会话出现在 **Fiddler 主会话列表**里，点开即可在右侧
   Inspectors 看 Headers / Raw / JSON 等（body 已解压为明文）。

### 4.3 导出 HAR / 清空列表（用 Fiddler 原生功能）
eCapture 标签页**不再提供** Clear / Export 按钮——会话注入到 Fiddler 主列表后，
清空和导出直接用 Fiddler 自带能力即可：
- **全部导出**：**File → Export Sessions → All Sessions… → 选择 “HTTPArchive v1.2”**。
- **导出选中**：在主会话列表里多选（Shift/Ctrl）→ 右键 → **Save → Selected Sessions…**，
  或 File → Export Sessions → Selected Sessions → HTTPArchive v1.2。
- **清空列表**：主菜单 **Edit → Remove → All Sessions**（或工具栏 X 按钮 / 快捷键 Ctrl+X）。

### 4.4 计数器/调试
- eCapture 标签页底部状态栏显示 **Events / Pairs / Pending / Heartbeat**。
- 下方 **Debug Log** 文本框打印 WS 连接、心跳、KEEP/DROP 配对等信息，用于排查。

---

## 5. 判断问题在哪一层（与 Burp 版同款判断树）

| 现象 | 说明 / 处理 |
|------|------|
| 连不上、状态红 / 一直 Reconnecting | WS 地址或网络问题：确认手机 IP、端口 28257、PC 能 ping 通手机、防火墙放行 |
| 绿色已连，但 **Heartbeat 不动** | eCapture 没在推二进制帧，或 protobuf 不匹配（看 Debug Log 是否有 parse 失败）|
| Heartbeat 在动，**Events=0** | eCapture 连上但没抓到目标 App 的 TLS 明文（hook 错进程 / App 没走 BoringSSL / 走了 QUIC/HTTP3）|
| Events>0，**Pairs=0 / 列表空** | 全是连接(Tuple)事件或非 HTTP/1.x 明文；本插件只解析 HTTP/1.x |
| 响应是乱码 / 还有 `1F 8B` | 正常情况下已自动 de-chunk+解压；若仍出现，多半是 zstd/br 等本插件未解的编码 |

---

## 6. 限制

- 仅解析 **HTTP/1.x 明文**。HTTP/2（HPACK 二进制头）方向能判对，但 method/URL 解析不出，
  会被丢弃——这是与 Burp 版一致的硬限制。
- **.NET Framework 4.8 无 Brotli**（见上文）。gzip/deflate 正常。
- eCapture text 模式不提供 socket/uuid，配对按 **PID+TID** 进行；同线程上的 HTTP/1.1
  pipelining/连接复用在极端乱序时可能配错（HTTP/1.1 下罕见）。

---

## 7. 目录结构

```
eCaptureFiddler/
├─ ECaptureFiddler.csproj   # net48 工程，引用 Fiddler.exe + WinForms
├─ build.bat                # Windows 一键编译脚本
├─ README_CN.md             # 本文件
├─ src/
│  ├─ Proto.cs              # 极简 protobuf(proto3) 解码器 + LogEntry/Event/Heartbeat
│  ├─ CapturedEvent.cs      # text-mode 事件头解析、方向、PID_TID、HTTP 字段
│  ├─ MessageBuffer.cs      # 分片缓冲 + 完整性判定(Content-Length/chunked)
│  ├─ EventManager.cs       # 重组 + PID_TID 配对(无 Fiddler 依赖，可单测)
│  ├─ HttpBodyCodec.cs      # de-chunk + 递归解压 gzip/deflate/br
│  ├─ MatchedHttpPair.cs    # 一对请求/响应
│  ├─ ECaptureWebSocketClient.cs  # ClientWebSocket 连接 + 自动重连
│  ├─ SessionInjector.cs    # 合成 Fiddler Session 并注入(引用 Fiddler.exe)
│  └─ ECaptureExtension.cs  # IFiddlerExtension + eCapture 标签页 UI(WinForms)
└─ coretest/                # 离线回归测试(.NET 8 控制台, 24 个用例)
   ├─ coretest.csproj
   └─ Program.cs
```

> `coretest` 用 .NET 8 编译，验证 protobuf/解码/解析/重组/配对等**与 Fiddler 无关**的核心逻辑
> （24/24 通过）。Fiddler 相关代码需在 Windows 上随 Fiddler.exe 一起编译。
