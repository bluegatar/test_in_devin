#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
decrypt_cenc.py — 验证 Frida 抓到的 AES key 能否解密 CENC(AES-CTR) MP4

用法:
    python decrypt_cenc.py <encrypted.mp4> <16字节hex的key> [输出.mp4]

它会:
  1. 解析 MP4 box：找到 moov/trak/mdia/minf/stbl 下的 sinf/schi/tenc（默认IV/KID）
  2. 找 stsz(stsz/co) 各 sample 大小，senc 各 sample 的 IV
  3. 找 mdat 的位置
  4. 按 CENC AES-CTR 规则逐 sample 解密：
       counter = sample_iv(8B) || default_iv(8B)
     用 AES-CTR 解密 sample 的字节
  5. 写出解密后的 MP4（原地替换加密 sample 的字节，box 结构不变，
     但保留 stbl/sinf 不动——播放器通常仍能解；若要彻底干净可再去掉 sinf）

依赖: pip install pycryptodome
"""
import sys, struct
from Crypto.Cipher import AES

# ---------- MP4 box 解析 ----------
def read_boxes(data, start=0, end=None):
    if end is None: end = len(data)
    boxes = []
    off = start
    while off + 8 <= end:
        size = struct.unpack(">I", data[off:off+4])[0]
        btype = bytes(data[off+4:off+8])
        hdr = 8
        if size == 1:
            if off+16 > end: break
            size = struct.unpack(">Q", data[off+8:off+16])[0]
            hdr = 16
        if size == 0: size = end - off
        if size < 8 or off+size > end: break
        boxes.append((off, size, hdr, btype, data[off+hdr:off+size]))
        off += size
    return boxes

CONTAINERS = {b"moov",b"trak",b"mdia",b"minf",b"stbl",b"sinf",b"schi",b"edts",b"udta",b"moof",b"traf",b"mvex"}

def walk(data, path=None):
    """递归遍历，path 是 box 类型路径列表。yield (full_path, offset, size, content)"""
    if path is None: path = []
    for (off,size,hdr,btype,content) in read_boxes(data):
        full = path + [btype]
        yield (full, off, size, content)
        if btype in CONTAINERS:
            yield from walk(content, full)

def find_box(data, want_path):
    """want_path: list of box types, e.g. [b'moov',b'trak',b'mdia',b'minf',b'stbl',b'sinf',b'schi',b'tenc']"""
    want = tuple(want_path)
    for (full, off, size, content) in walk(data):
        if tuple(full[-len(want):]) == want:
            return (off, size, content)
    return None

def find_all(data, want_type):
    """所有某类型 box（任意层级）"""
    res=[]
    for (full, off, size, content) in walk(data):
        if full[-1] == want_type:
            res.append((off, size, content))
    return res

def parse_tenc(content):
    # tenc: version(1) flags(3) reserved(2) is_protected(1) per_sample_iv_size(1) KID(16) default_iv?
    ver = content[0]
    # content[1:4] flags
    reserved = struct.unpack(">H", content[4:6])[0]
    is_protected = content[6]
    iv_size = content[7]
    kid = content[8:24]
    default_iv = None
    if iv_size > 0 and len(content) >= 24 + iv_size:
        default_iv = content[24:24+iv_size]
    return {"version":ver, "is_protected":is_protected, "per_sample_iv_size":iv_size,
            "kid":kid.hex(), "default_iv":default_iv}

def parse_senc(content):
    # senc: version(1) flags(3) sample_count(4) then per_sample: iv(per_sample_iv_size) [+subsample if flags&1]
    ver = content[0]
    flags = content[1]
    # 注意 content 已去掉 box header，但这里 content 是 box body（不含 size/type/version）
    # 实际 senc body: fullbox header(version+flags) 已经在 content[0:4]
    sample_count = struct.unpack(">I", content[4:8])[0]
    return ver, flags, sample_count

def parse_stsz(content):
    # stsz: ver(1) flags(3) sample_size(4) sample_count(4) [entries...]
    sample_size = struct.unpack(">I", content[4:8])[0]
    sample_count = struct.unpack(">I", content[8:12])[0]
    if sample_size != 0:
        return [sample_size]*sample_count
    sizes = []
    for i in range(sample_count):
        sizes.append(struct.unpack(">I", content[12+i*4:16+i*4])[0])
    return sizes

def parse_stco_or_co64(content, btype):
    # stco: entry_count(4) then entries(4 each)
    # co64: entry_count(4) then entries(8 each)
    cnt = struct.unpack(">I", content[4:8])[0]
    offs=[]
    if btype==b"stco":
        for i in range(cnt):
            offs.append(struct.unpack(">I", content[8+i*4:12+i*4])[0])
    else:
        for i in range(cnt):
            offs.append(struct.unpack(">Q", content[8+i*8:16+i*8])[0])
    return offs

def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    mp4 = sys.argv[1]
    key_hex = sys.argv[2].strip().replace(" ","")
    out = sys.argv[3] if len(sys.argv)>3 else "decrypted.mp4"
    key = bytes.fromhex(key_hex)
    if len(key)!=16:
        print("key 必须是 16 字节(32 hex 字符)，当前 %d 字节" % len(key)); sys.exit(1)

    data = bytearray(open(mp4,"rb").read())
    print("文件大小:", len(data))

    # 找 tenc —— CENC 里 tenc 在 stsd>sample_entry>sinf>schi>tenc，
    # 直接全文件搜所有 tenc（不依赖精确路径，因为 sample entry type 名可能是 encv/enca/空格）
    tenc_list = []
    for (full, off, size, content) in walk(data):
        if full[-1] == b"tenc":
            tenc_list.append((off, size, content))
    print("找到 tenc box 数:", len(tenc_list))
    if not tenc_list:
        # 兜底：原始字节搜索 tenc 签名
        idx = 0
        while True:
            i = data.find(b"tenc", idx)
            if i < 0: break
            if i >= 4:
                sz = struct.unpack(">I", data[i-4:i])[0]
                if 8 <= sz <= 64:
                    tenc_list.append((i-4, sz, bytes(data[i+4:i-4+sz])))
            idx = i + 4
        print("兜底字节搜索 tenc:", len(tenc_list))
    if not tenc_list:
        print("找不到 tenc box，可能不是标准 CENC"); sys.exit(1)
    tenc = tenc_list[0]
    tinfo = parse_tenc(tenc[2])
    print("=== tenc ===")
    print("  is_protected:", tinfo["is_protected"])
    print("  per_sample_iv_size:", tinfo["per_sample_iv_size"])
    print("  kid:", tinfo["kid"])
    print("  default_iv:", tinfo["default_iv"].hex() if tinfo["default_iv"] else None)

    per_iv = tinfo["per_sample_iv_size"]
    default_iv = tinfo["default_iv"]

    # 找 senc（所有）
    sencs = find_all(data, b"senc")
    print("找到 senc box 数:", len(sencs))

    # 找 stsz（所有 trak 下）
    stszs = find_all(data, b"stsz")
    print("找到 stsz box 数:", len(stszs))

    # 找 mdat
    mdats = find_all(data, b"mdat")
    print("找到 mdat box 数:", len(mdats))
    if not mdats:
        print("找不到 mdat"); sys.exit(1)

    # ---- 解密策略 ----
    # CENC AES-CTR: 每个 sample 的 counter = sample_iv(8B) || default_iv[?]
    # 标准做法(ISO/IEC 23001-7):
    #   - 若 per_sample_iv_size==8: 每个 sample IV 是 8 字节(高64位),
    #     低64位(block counter)从0开始。整个16字节 = sample_iv(8B) + 0x0000000000000000
    #   - default_iv 仅在 per_sample_iv_size==0 时作为所有 sample 的 IV 使用
    # 所以 counter(16B) = sample_iv + b'\x00'*8  (或 default_iv)

    key_obj = AES.new(key, AES.MODE_ECB)  # CTR 手动递增

    def ctr_crypt(key_obj, counter_16, data_buf):
        out = bytearray()
        for i in range(0, len(data_buf), 16):
            ks = key_obj.encrypt(counter_16)
            block = data_buf[i:i+16]
            out += bytes(a^b for a,b in zip(block, ks[:len(block)]))
            # increment counter (big-endian, +1)
            c = int.from_bytes(counter_16, 'big') + 1
            counter_16 = c.to_bytes(16, 'big')
        return bytes(out)

    # 每个 trak(stsz + senc + 一个对应的 sinf/tenc) 独立处理
    # 简化：逐个 senc 处理，配合同序的 stsz
    decrypted_count = 0
    for si, (soff, ssize, scontent) in enumerate(sencs):
        ver = scontent[0]; flags = scontent[1]
        sample_count = struct.unpack(">I", scontent[4:8])[0]
        # 解析每个 sample 的 IV（含可能的 subsample）
        p = 8
        samples_iv = []
        subsamples = []
        has_subsample = (flags & 1)
        for _ in range(sample_count):
            if per_iv == 0:
                iv = default_iv
            else:
                iv = scontent[p:p+per_iv]; p += per_iv
            clears=[]
            crypts=[]
            if has_subsample:
                n = struct.unpack(">H", scontent[p:p+2])[0]; p+=2
                for _ in range(n):
                    clear = struct.unpack(">H", scontent[p:p+2])[0]; p+=2
                    crypt = struct.unpack(">I", scontent[p:p+4])[0]; p+=4
                    clears.append(clear); crypts.append(crypt)
            samples_iv.append((iv, clears, crypts))

        # 对应的 stsz（按序）
        if si < len(stszs):
            sizes = parse_stsz(stszs[si][2])
        else:
            sizes = None

        # 找 sample 数据：需要 stco + stsc 重建 sample 偏移，太复杂。
        # 这里采用更稳的做法：mdat 内字节按 sample 顺序排列，解密时按 size 顺序切片。
        # （对单 mdat 顺序存放的文件成立）
        mdat_off, mdat_size, mdat_content_box = mdats[0]
        mdat_data_off = mdat_off + 8  # 去掉 size+type
        # 注意：多 trak(视频+音频) 交错存放，按 senc 顺序难以精确对齐。
        # 本验证脚本聚焦【能否解密】——用第一个 senc 对应 trak 的样本，
        # 在 mdat 内按 sizes 顺序定位。

        if sizes is None: continue
        cursor = mdat_data_off
        for idx, (iv, clears, crypts) in enumerate(samples_iv):
            if idx >= len(sizes): break
            slen = sizes[idx]
            counter = iv + b'\x00'*(16-len(iv))
            if has_subsample and crypts:
                # 有 subsample：clear 部分不动，crypt 部分解密
                pos = cursor
                for ci,(clr, cry) in enumerate(zip(clears, crypts)):
                    pos += clr  # skip clear
                    if cry>0:
                        buf = bytes(data[pos:pos+cry])
                        dec = ctr_crypt(key_obj, counter, buf)
                        data[pos:pos+cry] = dec
                        pos += cry
                cursor += slen
            else:
                buf = bytes(data[cursor:cursor+slen])
                dec = ctr_crypt(key_obj, counter, buf)
                data[cursor:cursor+slen] = dec
                cursor += slen
            decrypted_count += 1

    open(out,"wb").write(data)
    print("\n解密完成，处理 sample 数:", decrypted_count)
    print("输出:", out)
    print("\n验证: 用 ffprobe/播放器打开 %s 看能否播放" % out)

if __name__ == "__main__":
    main()
