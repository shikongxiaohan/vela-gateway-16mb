#!/usr/bin/env python3
"""
读回设备 flash 的关键扇区，直接看清设备里到底躺着什么。

用途：刷完固件设备起不来时，用它分清是哪一种情况：
  a) 刷的是旧文件 / 文件本身有问题
  b) 刷了但没擦除，或地址填错，导致设备里的内容不对

用法：
    python3 tools/readback_check.py --port COM3
    python3 tools/readback_check.py --port /dev/ttyUSB0
    python3 tools/readback_check.py --port COM3 --json

只读不写，不动设备里的任何数据。
"""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# 关键地址（与 partitions_ota_16mb.csv 一致）
ADDR_BOOTLOADER = 0x1000
ADDR_PARTTABLE = 0x8000
ADDR_OTADATA = 0xE000
ADDR_APP = 0x20000

SIZE_BOOTLOADER = 0x1000
SIZE_PARTTABLE = 0x1000
SIZE_OTADATA = 0x2000
SIZE_APP_HEADER = 0x100


def find_esptool():
    """定位 esptool.py：先找 PATH 上的 esptool.py，再找 PlatformIO 的。"""
    p = shutil.which("esptool.py") or shutil.which("esptool")
    if p:
        return [p]
    pio = Path.home() / ".platformio" / "packages" / "tool-esptoolpy" / "esptool.py"
    if pio.exists():
        return [sys.executable, str(pio)]
    for py in (Path.home() / ".platformio" / "penv" / "bin" / "python",
               Path.home() / "pioenv" / "bin" / "python",
               Path("/usr/bin/python3")):
        cand = Path.home() / ".platformio" / "packages" / "tool-esptoolpy" / "esptool.py"
        if py.exists() and cand.exists():
            return [str(py), str(cand)]
    return None


def read_flash(cmd, port, offset, size, label):
    """读回一段 flash。返回 bytes 或 None。"""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        out = f.name
    try:
        r = subprocess.run(cmd + ["--chip", "esp32", "--port", port,
                                  "read_flash", hex(offset), hex(size), out],
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            print(f"  [读回 {label}] 失败：{r.stderr.strip().splitlines()[-1] if r.stderr.strip() else '未知错误'}")
            return None
        data = Path(out).read_bytes()
        print(f"  [读回 {label}] {len(data)} B @ 0x{offset:X}")
        return data
    except subprocess.TimeoutExpired:
        print(f"  [读回 {label}] 超时")
        return None
    finally:
        Path(out).unlink(missing_ok=True)


def _segments(data):
    """解析 ESP 镜像的段表，返回 [(addr, len), ...]。"""
    if len(data) < 32 or data[0] != 0xE9:
        return []
    out = []
    off = 24
    try:
        for _ in range(data[1]):
            addr = int.from_bytes(data[off:off + 4], "little")
            ln = int.from_bytes(data[off + 4:off + 8], "little")
            out.append((addr, ln))
            off += 8 + ln
    except Exception:
        pass
    return out


def _local_bootloader_entry():
    """本地 firmware/bootloader.bin 的入口地址（用来判断设备上是不是我们这份）。"""
    p = Path(__file__).resolve().parent.parent / "firmware" / "bootloader.bin"
    try:
        d = p.read_bytes()
    except OSError:
        return None
    if len(d) < 8 or d[0] != 0xE9:
        return None
    return int.from_bytes(d[4:8], "little")


def check(data, expect, label, report):
    """按期望值检查一段数据，产出 (ok, 描述)。"""
    if data is None:
        report.append((False, f"{label}: 读取失败"))
        return False
    if expect == "otadata":
        seq = int.from_bytes(data[0:4], "little")
        allff = all(b == 0xFF for b in data)
        crc = int.from_bytes(data[0x1C:0x20], "little")
        if allff:
            report.append((False, "otadata 全 0xFF，没初始化，bootloader 找不到可启动分区（每 2 秒复位就是这个原因）"))
            return False
        if seq not in (1, 2, 0xFFFFFFFF):
            report.append((False, f"otadata ota_seq={seq} 不是合法值"))
            return False
        ok = seq in (1, 2)
        report.append((ok, f"otadata ota_seq={seq}（启动 ota_{0 if seq == 1 else 1}） crc=0x{crc:08x}"))
        return ok
    if expect == "app":
        magic = data[0]
        if magic != 0xE9:
            report.append((False, f"app 镜像头 magic=0x{magic:02x} 不是 0xE9，0x{ADDR_APP:X} 处没有 app"))
            return False
        entry = int.from_bytes(data[4:8], "little")
        segc = data[1]          # 段数在偏移 1（偏移 23 是 hash_appended）
        segs = _segments(data)
        report.append((True, f"app 镜像头有效 magic=0xE9 entry=0x{entry:08x} 段数={segc}"))
        if segs:
            report.append((True, "app 段表：" + " / ".join(
                f"0x{a:08x}:{l}" for a, l in segs)))
        return True
    if expect == "bootloader":
        if data[0] != 0xE9:
            report.append((False, f"bootloader magic=0x{data[0]:02x} 不是 0xE9，0x{ADDR_BOOTLOADER:X} 处没有 bootloader"))
            return False
        entry = int.from_bytes(data[4:8], "little")
        segs = _segments(data)
        exp = _local_bootloader_entry()
        desc = f"bootloader 有效 entry=0x{entry:08x}"
        if segs:
            desc += " 段表：" + " / ".join(f"0x{a:08x}:{l}" for a, l in segs)
        if exp is not None and entry != exp:
            report.append((False, desc))
            report.append((False,
                f"  ↑ 设备里的 bootloader 不是我们这份（本地 firmware/bootloader.bin 的 "
                f"entry=0x{exp:08x}）。0x{ADDR_BOOTLOADER:X} 上装的是别的项目的二级 bootloader"))
            return False
        report.append((True, desc))
        return True
    if expect == "parttable":
        if data[0] != 0xAA:
            report.append((False, f"分区表 magic=0x{data[0]:02x} 不是 0xAA，0x{ADDR_PARTTABLE:X} 处没有分区表"))
            return False
        # ESP-IDF 分区表：条目从 offset 0 开始，每条 32 字节，magic = 0x50AA。
        # esp_partition_t 布局：magic[0:2] type[2] subtype[3] offset[4:8]
        #                       size[8:12] label[12:28] flags[28:32]
        # 0xC0 之后是 MD5 校验和，不是条目。
        off = 0
        found = None
        while off + 32 <= len(data):
            e = data[off:off + 32]
            if e[0] != 0xAA or e[1] != 0x50:
                break
            label = e[12:28].split(b"\x00")[0].decode(errors="replace")
            o = int.from_bytes(e[4:8], "little")
            sz = int.from_bytes(e[8:12], "little")
            if label == "ota_0":
                found = (o, sz)
            off += 32
        if not found:
            report.append((False, "分区表里没有 ota_0 分区"))
            return False
        ok = found[0] == ADDR_APP
        report.append((ok, f"分区表有效 ota_0 @0x{found[0]:X} size={found[1]}"))
        return ok
    return True


def main():
    ap = argparse.ArgumentParser(description="读回设备 flash 关键扇区并自检")
    ap.add_argument("--port", required=True, help="串口，如 COM3 或 /dev/ttyUSB0")
    ap.add_argument("--baud", default="921600")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出")
    args = ap.parse_args()

    cmd = find_esptool()
    if not cmd:
        print("找不到 esptool.py。请先 pip install esptool，或让 PlatformIO 提供。",
              file=sys.stderr)
        return 2

    print(f"=== 读回设备 flash 自检 ({args.port}) ===")
    print("只读，不会修改设备内容。\n")

    report = []
    checks = [
        (ADDR_BOOTLOADER, SIZE_BOOTLOADER, "bootloader", "bootloader"),
        (ADDR_PARTTABLE, SIZE_PARTTABLE, "parttable", "parttable"),
        (ADDR_OTADATA, SIZE_OTADATA, "otadata", "otadata"),
        (ADDR_APP, SIZE_APP_HEADER, "app", "app"),
    ]
    for addr, size, label, expect in checks:
        data = read_flash(cmd, args.port, addr, size, label)
        check(data, expect, label, report)

    print()
    ok = True
    for good, desc in report:
        print(f"  {'✓' if good else '✗'}   {desc}")
        ok = ok and good

    if args.json:
        print()
        print(json.dumps({"ok": ok,
                          "checks": [{"ok": g, "detail": d} for g, d in report]},
                         ensure_ascii=False, indent=2))

    print()
    if ok:
        print("✓ flash 内容全部正确。")
        print("  若设备仍起不来，问题不在 flash 内容，请把串口日志发出来。")
        return 0
    print("✗ 发现问题。对照上面的描述处理：")
    if any("全 0xFF" in d for _, d in report):
        print("  · otadata 是空的 → 刷写时没写进去，或刷的是旧文件")
        print("    重新用 factory 镜像、地址 0x0、并【勾选 ERASE】重刷一次")
    if any("0xE9 不是" in d or "没有 app" in d for _, d in report):
        print("  · app 镜像不在 0x20000 → 刷写地址可能填错了（应为 0x0 整包，"
              "或分体时 0x20000）")
    return 1


if __name__ == "__main__":
    sys.exit(main())
