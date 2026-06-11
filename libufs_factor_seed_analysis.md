# libufs.so 逆向分析：factor 的来源 & 如何由 factor 推导 seed

## 0. 结论速览

- **factor 的来源**：不是写死在 so 里的常量，而是**由 Java 层经 JNI 传入的一个字符串**，存进 native 上下文结构 `ctx+0x2c0`。它的格式是**逗号分隔、且必须恰好是 5 个整数**（例如 `"3,1,4,2,87"`）。
- **seed 的推导**：把这 5 个整数解析出来（`atoi`），其中 `factor[0..3]` 当作 4 个输入字段里的**下标**，`factor[4]` 当作**运算密钥**；对每个字段算出一个小写字母，再把主数据字段按双指针交错拼接，最后（XOR 版本）追加后缀 `"_s001"`，得到的字符串就是 **seed**，并通过 JNI 回传给 Java。

---

## 1. 加固 / 混淆情况

这个 `libufs.so` 是 ARM64 (AArch64) 的 Android NDK 动态库，做了以下保护：

1. **运行时自解压壳**：磁盘上 `0x18ec–0x5100` 的代码段与只读数据是**加密/压缩的**（静态反汇编全是非法指令、`strings` 也搜不到任何明文）。库被加载时，`DT_INIT`(0x5100) 处的解压例程把真实代码/数据**在内存里解开**：
   - 位流解压（aPLib / LZSS 风格：1 比特标志位区分“字面量 / 回溯拷贝”）；
   - 字面量额外 `XOR 0xc`；
   - 通过返回地址 `LR` 自定位被压缩的数据块（位置无关）。
   - 解压完成后还把**原始代码段 `mprotect` 成 `PROT_NONE`**（反 dump），真实代码搬到一块匿名映射里执行。
2. **符号名混淆**：内部函数名是 10 位随机串（如 `gedSCacGnl`、`gutMpacQik`、`q1Cf2iJN2W`），导出符号只有 `CallInterface1`…`CallInterface14` 等 JNI 入口。
3. **字符串混淆**：报错信息里的关键词被替换成乱码词（如 `OMYipFwN`、`HFZfJxxm`、`WCqBuJTX myxErLpR %d`），但 `not / is / long / %d / %c / setValue1 / setValue2` 等保留下来。

### 我是怎么拿到明文代码的
静态没法看，于是做了运行时脱壳：
- 用 `aarch64-linux-gnu-gcc` 写了个 harness（`dlopen` 触发 INIT 解压），在 `qemu-aarch64-static` 下跑；
- 自建 `libc.so` 桩（按版本节点 `LIBC` 导出 `atoi/memcpy/...` 转发到 glibc）解决符号依赖；
- 装 `SIGSEGV` handler：解压结束时构造函数“返回到 0”会触发段错误，借此时机把所有可执行映射 dump 出来；
- 在 `libufs_base-0x9000` 的匿名映射里拿到**与文件偏移一致的解压镜像**，把 `[0x1000,0x5f3c)` 拼回原文件得到 `libufs_unpacked.so`；
- Ghidra 对它完整反编译（3692 行，0 个非法指令）。产物见 `decomp_unpacked.c`。

---

## 2. native 上下文结构 (ctx) 与“顺序令牌”

`acDupstOrt()` 申请一块 0x500 的上下文，初始化 `ctx+0x3c0 = "RESOT_"`。各字段：

| 偏移 | 含义 | 写入函数(setter) | 追加到 tag 的数字 |
|------|------|------------------|-------------------|
| `+0x80`  | 输入字段1 | `gyYudUijKl` | `1` |
| `+0x100` | 输入字段2 | `kdDuYuijyg` | `2` |
| `+0x140` | 输入字段3 | `mp6wzKtGGh` | `3` |
| `+0x1c0` | 输入字段4 | `hgykEgzpyU` | `4` |
| `+0x240` | **主数据**字段 | `tgORKRV0iK` | `5` |
| `+0x2c0` | **factor 字段** | `q1Cf2iJN2W` | `6` |
| (无字段) | 步骤标记 | `baMsCsXiWC` | `7` |
| (无字段) | 步骤标记 | `pfLAHssTYI` | `8` |
| `+0x340` | **输出/seed** 缓冲 | (seed 生成函数写) | — |
| `+0x3c0` | 顺序令牌 `RESOT_…` | — | — |
| `+0x4c0` | 错误信息缓冲 | — | — |

每个 setter 把一个数字追加到 `ctx+0x3c0` 的 tag 末尾。`cgSCuCiand()` 及 seed 生成函数都会校验完整 tag 必须等于：

```
RESOT_45632187
```

也就是要求这些 JNI 接口**按固定顺序调用**：`4,5,6,3,2,1,8,7`（即 字段4 → 主数据 → factor → 字段3 → 字段2 → 字段1 → 标记8 → 标记7）。这是一个防篡改 / 防乱序的“调用顺序令牌”。

---

## 3. factor 的来源（详细）

- factor 字符串由 `q1Cf2iJN2W()` 写入 `ctx+0x2c0`（长度上限 0x80）：
  ```c
  // q1Cf2iJN2W @ 0x20e8
  func_0x001017a0(param_1 + 0x2c0, param_2, param_3); // memcpy(ctx+0x2c0, input, len)
  *(ctx + 0x2c0 + len) = 0;
  // 并把 '6' 追加到 RESOT_ 令牌
  ```
- 这些 `CallInterfaceN` 都是标准 JNI 包装：用 `(*env)->GetStringUTFChars`(vtable+0x548) 取 Java 传来的字符串，处理后用 `ReleaseStringUTFChars`(vtable+0x550) 释放，部分还回调 Java 的 `setValue1/setValue2`。**所以 factor 的真正来源是上层 Java 代码通过 JNI 传进来的字符串参数**，so 本身不产生它。
- factor 字符串的语义是：**逗号分隔、必须恰好 5 个整数**。在 seed 生成函数里这样解析：
  ```c
  // 遍历 ctx+0x2c0，按 ',' 切分，atoi 每段，存入 nums[0..4]
  iVar = atoi(token);            // func_0x00101660 == atoi
  nums[count++] = iVar;
  ...
  if (count != 5) -> 报错 "…dGJVqHVA… %d" (0x1a0c) 直接失败
  ```
  解析出来的 5 个整数即 `factor[0..4]`：
  - `factor[0..3]` → 4 个输入字段里的**位置下标**（1-based，要求 `0 < factor[i] < 字段长度`）；
  - `factor[4]` → 推导字母用的**运算密钥**（代码里 `iVar6 = nums[4]`，并 `printf("…: %d", nums[4])` 打印）。

---

## 4. 如何由 factor 推导 seed（核心算法）

seed 的生成有两个**等价但运算不同**的实现：`gedSCacGnl @0x2548`（XOR 版）和 `gutMpacQik @0x2b20`（AND+移位版）。流程一致：

### 4.1 由 factor 算出 4 个派生字母
对 4 个输入字段分别取一个字节并与 `factor[4]` 运算，映射成小写字母 `a–z`：

```c
// 字段 i ∈ {0:+0x80, 1:+0x100, 2:+0x140, 3:+0x1c0}, key = factor[4]
if (0 < factor[i] && factor[i] < len(field_i))
    // gedSCacGnl（XOR 版）:
    ch[i] = ( key ^ field_i[factor[i]-1] ) % 26 + 'a';
    // gutMpacQik（AND+移位版）:
    ch[i] = ( (key & field_i[factor[i]-1]) >> 1 ) % 26 + 'a';
else
    ch[i] = 默认值;   // 4 个字段默认依次为 'e','t','c','n'
```
（`+0x7f + factor[i]` 等价于 `field_i[factor[i]-1]`，即 1-based 下标。每算出一个字母会 `printf("…: %c", ch[i])`。）

### 4.2 与主数据交错拼接 + 后缀
取主数据字段 `ctx+0x240`（由 `tgORKRV0iK` 写入，长度需 `1..0x74`），用一个**双指针状态机**（`iVar` 从尾部递减、另一指针从头递增）把主数据字节与上面 5 个位置的派生字符**交错**写入临时缓冲，得到一串字符串：

```c
// 伪代码（LAB_00102a18 状态机）
out = interleave(reverse-walk over field_0x240, [ch0, ch1, ch2, ch3, ...]);
// XOR 版（gedSCacGnl）末尾再拼接后缀:
strncpy(out + n, "_s00", 4); out[...] = '1';   // => 追加 "_s001"
```

### 4.3 输出 seed
```c
strcpy(ctx + 0x340, out);   // seed 存入 ctx 输出缓冲
strcpy(java_out, out);      // 同时写回 JNI 输出参数，回传给 Java
```

**即：seed = interleave(主数据字段, 由 factor 派生的字母序列) [+ "_s001"]**，再经 JNI 回传给 Java（`setValue1/setValue2`）。

---

## 5. 其它旁证（与 seed 无直接耦合，但属同一模块）

- **硬编码 AES-256 密钥**（在 `HnEZEQUA @0x3158` 中使用）：ASCII 字符串
  ```
  1ed7f236e8eedfe1c90ccad475b3ba19      (32 个 hex 字符 = 32 字节，疑似某 MD5)
  ```
  该函数做的是 `base64_decode → AES-CBC-decrypt(key=上面32字节, keylen=0x20)`，是**另一条解密链路**，用的是这个**写死的 key**，不是上面的 seed。也就是说 factor→seed 的产物是回给 Java 用的，AES 这条用的是固定 key。
- 库内有完整的 `aes_cbc_encrypt/decrypt`、`base64_encode/decode` 实现（典型咪咕 `PlayUrlEncryptionUtil` JNI 形态）。

---

## 6. 交付物
- `libufs_unpacked.so`：脱壳后可被 Ghidra/IDA 正常分析的版本。
- `decomp_unpacked.c`：Ghidra 全量反编译（3692 行）。
- 脱壳 harness：`dump_harness.c` + `libc_stub.c` + `libc.ver`（QEMU 下复现）。
