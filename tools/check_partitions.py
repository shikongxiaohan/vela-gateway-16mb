#!/usr/bin/env python3
"""校验 ESP32 分区表 CSV：对齐、重叠、越界、app 槽数量。

用法: python3 tools/check_partitions.py partitions_ota_16mb.csv 16
"""
import sys
import struct


def parse(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 5:
                raise SystemExit(f"{path}:{lineno}: 字段不足: {line}")
            name, ptype, subtype, offset, size = parts[:5]
            if offset.lower() in ("", "offset"):
                offset = None
            else:
                offset = int(offset, 0)
            size = int(size, 0)
            rows.append((name, ptype, subtype, offset, size, lineno))
    return rows


def main():
    path = sys.argv[1]
    total = int(float(sys.argv[2]) * 1024 * 1024) if len(sys.argv) > 2 else 4 * 1024 * 1024
    rows = parse(path)

    cursor = 0x9000  # 分区表 + bootloader 之后
    ok = True
    print(f"{'name':<10}{'type':<6}{'subtype':<9}{'offset':>10}{'size':>10}{'end':>10}")
    for name, ptype, subtype, offset, size, lineno in rows:
        if offset is None:
            offset = cursor
        if offset % 0x1000:
            print(f"  ! {name}: offset 0x{offset:X} 未 4KB 对齐")
            ok = False
        if offset < cursor:
            print(f"  ! {name}: offset 0x{offset:X} 与上一个分区重叠（上一个结束于 0x{cursor:X}）")
            ok = False
        if offset + size > total:
            print(f"  ! {name}: 结束于 0x{offset + size:X}，超出 Flash 0x{total:X}")
            ok = False
        print(f"{name:<10}{ptype:<6}{subtype:<9}0x{offset:08X}0x{size:08X}0x{offset + size:08X}")
        cursor = offset + size

    apps = [r for r in rows if r[1].strip() == "app"]
    spiffs = [r for r in rows if r[2].strip() == "spiffs"]
    print()
    print(f"app 槽: {len(apps)} 个, spiffs: {len(spiffs)} 个, 末尾: 0x{cursor:X} / 0x{total:X}")
    if len(apps) == 2:
        print(f"OTA 单槽: {apps[0][4] / 1048576:.2f} MB")
        if apps[0][4] != apps[1][4]:
            print("  ! 两个 OTA 槽大小不一致，回滚时可能写不下")
            ok = False
    if not spiffs:
        print("  ! 没有 spiffs 分区：SPIFFS.begin() 会失败（音频导出/抓包落盘不可用）")
        ok = False
    print("RESULT:", "OK" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
