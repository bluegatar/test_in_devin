# factor 来源分析（DEX 静态分析 + Frida 动态钩子）

目标：找到 `PlayUrlEncryptionUtil` 中 `factor`（形如 `"E8KmOzDHdgb0EGGi9uBJRw=="` 的
base64 + AES 密文）的**最初来源**。

## 1. 入口类与算法确认

`com.cmvideo.foundation.mgutil.PlayUrlEncryptionUtil`（位于 `classes3.dex`）。

- 静态字段 `factorOfEncryption = new int[]{8, 3, 7, 6, 6}` —— 这正是 native 侧解析出的
  “5 个整数”的**默认值**；Java 里的 `encrypt(char c)`：

  ```java
  private static char encrypt(char c) {
      return (char)(((c ^ factorOfEncryption[4]) % 26) + 97);
  }
  ```

  与 native `gedSCacGnl` 的 XOR 变体（`(key ^ byte) % 26 + 'a'`）完全一致，互相印证。

- 真正的运行时入口是 `parsePlayUrl(in)`：
  - `iPlayerConfig.isUsePlayUrlUniEncryption()` 为真 → `parsePlayUrlNative(in)`
  - 否则 → `parsePlayUrlLegacy(in)`（纯 Java，老算法，不走 .so）

## 2. factor 在 Java 侧的直接来源

`parsePlayUrlNative(url)` / `parseJSPlayUrlNative(url)` 取 factor 的逻辑（smali 已核实）：

```java
String sv = "", factor = "";
IPlayerConfig cfg = ServiceCenterKt.getService(IPlayerConfig.class);
if (cfg != null) {
    Pair p = cfg.getPlayUrlFactor();      // JS 版: getJSPlayUrlFactor()
    sv     = (String) p.getFirst();
    factor = (String) p.getSecond();      // <-- factor 密文
}
if (TextUtils.isEmpty(factor) || TextUtils.isEmpty(sv)) {
    sv     = EnvSandBox.fetchStaticValue("play_url_sv");      // JS 版: play_js_url_sv
    factor = EnvSandBox.fetchStaticValue("play_url_factor");  // JS 版: play_js_url_factor
}
return encrypt(url, factor, sv);          // factor 进 CallInterface14 -> native AES 解密
```

native 侧（已在 Phase 1 分析过）：`CallInterface14(factor)` → base64 解码 + AES‑256‑CBC
解密（key=`1ed7f236e8eedfe1c90ccad475b3ba19`）→ 得到逗号分隔的 5 个整数 →
`CustomStructValue.getValue3()`（日志里 `decrypt factor value:`）→ `CallInterface7` 写入 →
派生 seed。

**因此 factor 有两个直接来源：**

| # | 来源表达式 | 说明 |
|---|-----------|------|
| A | `IPlayerConfig.getPlayUrlFactor().getSecond()` | 播放器配置服务（IoC `ServiceCenter` 注入） |
| B | `EnvSandBox.fetchStaticValue("play_url_factor")` | 全局静态配置沙盒（A 为空时兜底） |

`sv`（接口版本号，如 `10004`）同理来自 `getFirst()` / `play_url_sv`。

## 3. 静态分析的边界（为什么需要 Frida）

对提供的 7 个 dex 做了交叉引用与 class_def 核对（`baksmali list classes`）：

- 方法名字符串 `getPlayUrlFactor` / `getJSPlayUrlFactor`、类 `EnvSandBox`、descriptor
  `Lcom/cmvideo/.../IPlayerConfig;` 在全部 dex 中**仅出现在调用点**（`PlayUrlEncryptionUtil`）。
- `com.cmvideo.output.service.biz.player.IPlayerConfig`（声明 `getPlayUrlFactor`）和
  `com.cmvideo.capability.mgkit.sanbox.EnvSandBox` 这两个类的**定义都不在这 7 个 dex 里** ——
  没有任何 `getPlayUrlFactor` 的具体实现类，也没有任何地方写入键 `"play_url_factor"`。

结论：factor 的值由**另一个模块/分包 dex（未提供）下发**，最可能是 App 启动或播放前
拉取的**全局配置/远端配置响应**，以 `play_url_factor` / `play_url_sv`（及 JS 版）为键
写进 `EnvSandBox`，或由 `IPlayerConfig` 实现持有。仅凭这 7 个 dex 无法继续追到具体 URL，
所以用 Frida 在运行时定位。

## 4. Frida 方案

脚本：`frida_factor_trace.js`。运行：

```bash
# spawn 启动（推荐）
frida -U -f com.cmcc.cmvideo -l frida_factor_trace.js
# 或 attach
frida -U -n 咪咕视频 -l frida_factor_trace.js
```

进入 App 播放任意视频触发 `parsePlayUrlNative`。钩子会输出：

1. `[FACTOR]` —— `encrypt(url, factor, sv)` 的 factor 密文 + **Java 调用栈**（确认走的是
   native 还是 legacy）。
2. `[ENVBOX]` —— `EnvSandBox.fetchStaticValue("play_url_factor"/...)` 的返回值（来源 B）。
3. `[ENVSET]` —— 运行时枚举 `EnvSandBox` 的全部 `put/set/load/init...` 方法并挂钩，
   命中写入 factor 的那一刻打印 **key/value + 调用栈** —— 这一步用来定位 factor **最初是被
   哪段配置下发/网络响应代码写进来的**（即真正的源头）。
4. `[ICONF]` —— `IPlayerConfig.getPlayUrlFactor()/getJSPlayUrlFactor()` 返回的
   `Pair<sv,factor>` + 运行时**具体实现类名** + 调用栈（来源 A）。
5. `[NATIVE]` —— 真正喂给 `.so` 的 factor 字节，以及 native AES 解密后的明文（5 个整数）。

按 `[ENVSET]` / `[ICONF]` 打印的调用栈逐帧上溯，即可定位到发起网络请求、解析响应并写入
factor 的那个类/方法（多半是某个“全局配置 / unionSetting / 播放配置”接口的回调），
从而拿到下发 factor 的 URL。

## 5. 复现/分析所用工具
- jadx 1.5.0（反编译 dex → java）
- baksmali 2.5.2（smali 级核实，确认无 `getPlayUrlFactor` 实现、`EnvSandBox` 未定义）
- Frida（运行时钩子，见 `frida_factor_trace.js`）
