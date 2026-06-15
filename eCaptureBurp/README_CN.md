# eCapture Burp Suite Extension

[English](README.md) | 中文

一个 Burp Suite 扩展，用于接收 [eCapture](https://github.com/gojue/ecapture) 捕获的 TLS/HTTP 流量数据。

![Screenshot](images/demo.png)

## 构建

```bash
cd eCaptureBurp
./gradlew jar
```

## 使用方法

### 1. 启动 eCapture

```bash
sudo ./ecapture tls --ecaptureq=ws://127.0.0.1:28257/
```

### 2. 在 Burp Suite 中连接

1. 输入 WebSocket URL（默认 `ws://127.0.0.1:28257/`）
2. 点击 **Connect** 按钮
3. 状态指示灯变绿表示连接成功

## 配置说明

| 参数 | 默认值 | 说明 |
|------|--------|------|
| WebSocket URL | `ws://127.0.0.1:28257/` | eCapture eCaptureQ 服务地址 |

## 技术架构

```
┌─────────────────┐     WebSocket + Protobuf     ┌──────────────────┐
│    eCapture     │ ───────────────────────────> │  Burp Extension  │
│  (eBPF capture) │                              │                  │
└─────────────────┘                              │  ┌────────────┐  │
                                                 │  │ Event Mgr  │  │
                                                 │  │  (pairing) │  │
                                                 │  └─────┬──────┘  │
                                                 │        │         │
                                                 │  ┌─────▼──────┐  │
                                                 │  │ Site Map   │  │
                                                 │  │ + Tab UI   │  │
                                                 │  └────────────┘  │
                                                 └──────────────────┘
```

## 许可证

Apache License 2.0

## 相关链接

- [eCapture 项目](https://github.com/gojue/ecapture)
- [eCapture 事件转发 API 文档](https://github.com/gojue/ecapture/blob/master/docs/event-forward-api.md)
- [Burp Suite Montoya API](https://portswigger.github.io/burp-extensions-montoya-api/)

