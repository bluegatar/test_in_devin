# eCaptureBurp 修改说明

本目录是在原始 `eCaptureBurp` 基础上，针对 eCapture v2.4.2（Android 13 / BoringSSL，
`--ecaptureq` **text 模式**）实测调试后做的一系列修复与增强。下面按问题逐条说明改动点。

## 1. 抓到包但表格为空 —— text 模式事件头解析

eCapture 在 `--ecaptureq` text 模式下，EVENT 的 `payload` 不是裸 HTTP，而是带一行
eCapture 事件头的文本：

```
[时间] PID:24394, Comm:guvideo, TID:24499, FD:152, WRITE (1457 bytes):
GET /path HTTP/1.1
Host: ...
```

连接事件则是：`PID:.., Comm:.., TID:.., FD:.., Tuple: ip->ip`。

原插件用「payload 是否以 `GET `/`HTTP/` 开头」判断，因为前面多了事件头永远匹配不上，
于是全部被判 Unknown 丢弃。

改动（`CapturedEvent.java`）：
- 解析事件头，按方向判定：`WRITE`=请求，`READ`=响应（比猜内容更可靠）。
- 剥掉事件头，`getPayload()` 返回真正的 HTTP 原始字节。
- `Tuple:` 连接事件自动忽略；进程名改用事件里的 `Comm`。
- 放宽到全部标准 HTTP 方法。

## 2. 详情面板/配对错位（加 filter 更严重）

- **详情面板按行直接取 pair 引用**（`ECaptureTab.rowPairs`，与表格行严格同步），不再用
  `getMatchedPairs().get(行号)` 按下标取——这是「整对都错、加 filter 更严重」的根因。
- **pairId 改用自增序号**（`AtomicLong`），消除并发同毫秒碰撞导致的行覆盖。
- **按 PID+TID 配对**（`EventManager`）：HTTP/1.1 下同一请求与其响应基本都在同一线程顺序
  收发，按连接键 `PID_TID` 分组配对，比全局 FIFO 准确得多；响应乱序到达也能配回正确请求。

## 3. 分片重组

eCapture 把每次 SSL_read/SSL_write 当作独立事件发送，大响应会被拆成多个 READ 事件。
`EventManager` 按 `PID_TID` 把同一 HTTP 消息的多个事件拼接：首个带请求行/`HTTP/` 的事件
开新消息，后续无头分片追加到 body，按 `Content-Length` 或 `chunked`（`0\r\n\r\n`）判完整。

## 4. 响应乱码 / gzip 未解压 —— 原始字节 + 主动解码

- 显示改用 Burp 的 `ByteArray` 原始字节构建请求/响应，不再经 `new String()`
  （此前所有非 UTF-8 字节被替换为 `0xFD`，满屏乱码）。
- 新增 `HttpBodyCodec`：先 **de-chunk**（容忍开头多余的 `\r\n`），再按 `Content-Encoding`
  + **魔数循环**解压 **gzip / deflate(zlib) / br(Brotli)**，**一直解到不再是压缩格式为止**
  （支持嵌套与未声明的二次压缩）。解完后改正 `Content-Length`、去掉编码头。
- 同一套解码逻辑应用到详情面板显示、HAR 导出、右键 Copy Request/Response。
- `build.gradle` 增加 `org.brotli:dec:0.1.2` 依赖（已打进 fat jar）。

## 5. HAR 导出（全部 / 多选）

- `HarExporter`：把抓包记录导出为 HAR 1.2 JSON，body 解压后存 `content.text`，二进制
  自动 base64（带 `encoding:"base64"`）。
- 「Connection」区 **Clear** 旁新增 **Export to HAR** 按钮：导出全部，弹文件对话框选路径/文件名。
- 表格支持 Shift/Ctrl 多选 → 右键 **Export selected to HAR (N rows)** 导出选中记录；右键
  点在已选区域内会保留多选。

## 6. `#` 列自然数排序

`#` / Status / Req Len / Resp Len 改为**数值比较**，排序结果为 1,2,3,…,10,11，
而不是字符串序的 1,10,11,2。

## 7. 调试输出（DEBUG 版）

- `DebugLog`：所有 `[eCapture-DEBUG]` 行写入磁盘日志文件
  `<用户主目录>/ecapture-burp-debug.log`，同时显示在插件内新增的 **Debug Log** 子标签页
  （Burp 的 Extensions→Output 在部分版本不可见）。

## 离线验证

源码内逻辑已用离线样本回归验证（见仓库提交说明）：
- 解码：chunked+gzip、开头带 `\r\n` 的 chunked+gzip、嵌套 gzip、deflate、未声明 gzip、
  纯文本不变、请求无 body —— 全部解出明文且不再含 gzip 魔数。
- 重组与配对：Content-Length 多分片重组、chunked 多分片重组、两连接乱序响应正确配对、
  连接事件忽略 —— 全部通过。
