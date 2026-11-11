#!/usr/bin/env python3
"""表盘 / 快应用安装的协议回归测试。

协议来源：小米穿戴 WearPacket + Mass 分块，与 AstroBox / minstall 一致
（minstall 在 Band 10 Pro 上真机验证过，2026-08）。

这里不连设备，只校验两件事：
  1. 源码里的协议常量没被改错（字段号 / 类型号 / 通道号）
  2. 用 Python 复刻的分片算法与参考实现逐字节一致

之所以要专门盯字段号：protobuf 的字段号写错不会报错，只会让设备静默
不理你，排查成本极高。
"""
import hashlib
import re
import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "main.cpp"

fails = []
oks = 0


def check(cond, msg):
    global oks
    if cond:
        oks += 1
        print(f"[ OK ] {msg}")
    else:
        fails.append(msg)
        print(f"[FAIL] {msg}")


# ---------------------------------------------------------------- 参考实现
def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)


def fv(num: int, v: int) -> bytes:
    return varint((num << 3) | 0) + varint(v)


def fb(num: int, d: bytes) -> bytes:
    return varint((num << 3) | 2) + varint(len(d)) + d


def ref_watchface_prepare(wid: str, size: int) -> bytes:
    info = fb(1, wid.encode()) + fv(2, size) + fv(3, 65536)
    return fv(1, 4) + fv(2, 4) + fb(6, fb(6, info))


def ref_mass_prepare(md5: bytes, size: int, data_type: int = 16) -> bytes:
    req = fv(1, data_type) + fb(2, md5) + fv(3, size)
    return fv(1, 22) + fv(2, 0) + fb(24, fb(1, req))


def build_frames(data: bytes, data_type: int, slice_len: int):
    md5 = hashlib.md5(data).digest()
    framed = b"\x00" + bytes([data_type]) + md5 + struct.pack("<I", len(data)) + data
    with_crc = framed + struct.pack("<I", zlib.crc32(framed) & 0xFFFFFFFF)
    frag = slice_len - 6
    total = (len(with_crc) + frag - 1) // frag
    frames = []
    for i in range(total):
        frames.append(bytes([2, 1]) + struct.pack("<HH", total, i + 1) + with_crc[i * frag:(i + 1) * frag])
    return frames, total, with_crc


def main() -> int:
    if not SRC.exists():
        print(f"找不到 {SRC}")
        return 1
    src = SRC.read_text(encoding="utf-8", errors="replace")

    print("== 协议常量 ==")
    consts = {
        "kWpTypeWatchFace": 4,
        "kWpTypeMass": 22,
        "kWpFieldWatchFace": 6,
        "kWpFieldMass": 24,
        "kWfIdPrepareInstall": 4,
        "kMassIdPrepare": 0,
        "kDataTypeWatchFace": 16,
        "kDataTypeThirdpartyApp": 64,
    }
    for name, want in consts.items():
        m = re.search(rf"constexpr\s+uint\w+_t\s+{name}\s*=\s*(\d+)", src)
        got = int(m.group(1)) if m else None
        check(got == want, f"{name} = {got}（应为 {want}）")

    print("\n== 参考编码 ==")
    wf = ref_watchface_prepare("167210067", 2492348)
    check(wf.hex() == "08041004321632140a0931363732313030363710bc8f980118808004",
          "表盘 prepare 编码与真机验证过的字节一致")
    mp = ref_mass_prepare(b"\x11" * 16, 2492348)
    check(mp[:2] == b"\x08\x16", "Mass prepare: type=22")
    check(mp[2:4] == b"\x10\x00", "Mass prepare: id=0")
    check(b"\xc2\x01" in mp[:8], "Mass prepare: payload oneof 用 field 24")

    print("\n== 分片算法 ==")
    payload = b"\x5a\xa5" + bytes(range(256)) * 20
    for slice_len in (2048, 4096, 512):
        frames, total, with_crc = build_frames(payload, 16, slice_len)
        check(total == len(frames) and total > 0, f"slice={slice_len}: 片数 {total} 自洽")
        check(all(f[0] == 2 and f[1] == 1 for f in frames),
              f"slice={slice_len}: 每片 channel=2(Mass) op=1(Write)")
        check(all(struct.unpack('<HH', f[2:6])[1] == i + 1 for i, f in enumerate(frames)),
              f"slice={slice_len}: 片号从 1 连续递增")
        check(b"".join(f[6:] for f in frames) == with_crc,
              f"slice={slice_len}: 重组后与源块逐字节一致")
        check(with_crc[-4:] == struct.pack("<I", zlib.crc32(with_crc[:-4]) & 0xFFFFFFFF),
              f"slice={slice_len}: crc32 覆盖 header+数据")

    print("\n== 数据块布局 ==")
    data = b"\x5a\xa5" + b"\x00" * 30
    md5 = hashlib.md5(data).digest()
    block = b"\x00" + bytes([16]) + md5 + struct.pack("<I", len(data)) + data
    check(block[0] == 0, "comp_data = 0（不压缩）")
    check(block[1] == 16, "data_type 紧跟在 comp 之后")
    check(block[2:18] == md5, "md5 位于偏移 2..18")
    check(struct.unpack("<I", block[18:22])[0] == len(data), "长度字段为小端 4 字节")

    print("\n== 表盘文件解析 ==")
    m = re.search(r"if \(head\[0\] != 0x5A \|\| head\[1\] != 0xA5\)", src)
    check(m is not None, "校验表盘 magic 5A A5")
    m = re.search(r"while \(0x28 \+ idLen < 0x68", src)
    check(m is not None, "表盘 id 从偏移 0x28 读取")
    m = re.search(r"head\[0x68\] == 0xFF", src)
    check(m is not None, "表盘名从 0x68 读取，并处理 i18n 表")

    print("\n== 安装状态机 ==")
    for token, desc in [
        (r"wfi::pump\(outgoingSequence, encKey\)", "读循环里每轮推进状态机"),
        (r"wfi::onAck\(frame\.sequence\)", "type=1 帧交给 ACK 处理"),
        (r"wfi::onProto\(pbType, pbId, pb, pbLength\)", "解密后的 protobuf 交给状态机"),
        (r"wfi::networkPaused\(\)", "安装期间暂停回程网络包"),
        (r"gJob\.sliceLength = slice", "采用设备回报的 slice_length"),
        (r"if \(gJob\.sentParts > gJob\.ackedParts\)", "按 ACK 节流，不无脑刷包"),
        (r"part_ack_timeout", "单片 ACK 有超时"),
    ]:
        check(re.search(token, src) is not None, desc)

    print("\n== 容量与安全 ==")
    check("SPIFFS.totalBytes() - SPIFFS.usedBytes()" in src, "上传前检查 SPIFFS 剩余空间")
    check("96 * 1024" in src, "给日志/录音预留 96 KB")
    m = re.search(r'if \(slot\.length\(\) != 2\)', src)
    check(m is not None, "安装/删除接口校验槽位格式")

    print()
    if fails:
        print(f"✗ {len(fails)} 项未通过：")
        for f in fails:
            print("   -", f)
        return 1
    print(f"✓ 全部通过（{oks} 项）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
