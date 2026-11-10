#!/usr/bin/env python3
"""校验 firmware/ 下的镜像是否真的可启动。

PlatformIO 在 espidf+arduino 双框架下生成的 ota_data_initial.bin 可能全 0xFF
（等于没初始化 otadata），而分区表里没有 factory 分区时，bootloader 会拒绝启动
并每 2 秒复位一次。这个脚本把这类"看起来刷成功了但起不来"的问题在烧录前拦住。

用法：python3 tools/verify_firmware.py [firmware目录]
退出码 0 = 全部通过，1 = 有问题
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import version_util as vu  # noqa: E402

APP_DESC_MAGIC = 0xABCD5432
PART_MAGIC = 0x50AA

ok = True


def fail(msg):
    global ok
    ok = False
    print(f"  ✗ {msg}")


def good(msg):
    print(f"  ✓ {msg}")


def parse_partitions(blob):
    parts = {}
    for i in range(16):
        p = blob[i * 32:(i + 1) * 32]
        if len(p) < 32 or struct.unpack_from("<H", p, 0)[0] != PART_MAGIC:
            break
        label = p[12:28].split(b"\x00")[0].decode()
        parts[label] = {
            "type": p[2],
            "sub": p[3],
            "addr": struct.unpack_from("<I", p, 4)[0],
            "size": struct.unpack_from("<I", p, 8)[0],
        }
    return parts


def check_otadata(od, parts):
    """otadata 必须含至少一条合法记录，否则 bootloader 找不到可启动分区。"""
    if all(x == 0xFF for x in od):
        fail("otadata 全 0xFF（未初始化）——设备会每 2 秒复位一次")
        print("     修复：cp $ARDUINO/tools/partitions/boot_app0.bin firmware/ota_data_initial.bin")
        return
    # 两个 4KB 扇区，各含一条记录
    for base in (0, 0x1000):
        rec = od[base:base + 32]
        seq = struct.unpack_from("<I", rec, 0)[0]
        crc = struct.unpack_from("<I", rec, 28)[0]
        if seq in (0, 0xFFFFFFFF):
            continue
        good(f"otadata 扇区 {base:#06x}: ota_seq={seq} crc={crc:#010x} "
             f"→ 启动 ota_{(seq - 1) % 2}")
        if not parts:
            return
        target = f"ota_{(seq - 1) % 2}"
        if target not in parts:
            fail(f"otadata 指向 {target}，但分区表里没有这个分区")
        return
    fail("otadata 两条记录都无效")


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "firmware")
    print(f"检查目录: {root}\n")

    # 分体文件
    print("[分体文件]")
    boot_p = root / "bootloader.bin"
    part_p = root / "partitions.bin"
    ota_p = root / "ota_data_initial.bin"

    parts = {}
    if boot_p.exists():
        b = boot_p.read_bytes()
        good(f"bootloader.bin  {len(b):>8,} B  magic={b[0]:#04x} entry={struct.unpack_from('<I', b, 4)[0]:#010x}")
        if b[0] != 0xE9:
            fail("bootloader.bin 首字节不是 0xE9")
    else:
        fail("缺少 bootloader.bin")

    if part_p.exists():
        b = part_p.read_bytes()
        parts = parse_partitions(b)
        good(f"partitions.bin  {len(b):>8,} B  {len(parts)} 个分区: {', '.join(parts)}")
        if "factory" not in parts and "ota_0" not in parts:
            fail("分区表里既没有 factory 也没有 ota_0，bootloader 无处可启动")
    else:
        fail("缺少 partitions.bin")

    if ota_p.exists():
        b = ota_p.read_bytes()
        check_otadata(b, parts)
    else:
        fail("缺少 ota_data_initial.bin")

    # 整包
    print("\n[整包镜像]")
    factory = next(root.glob("*factory.bin"), None)
    if factory:
        b = factory.read_bytes()
        good(f"{factory.name}  {len(b):>10,} B")
        for off, name, magic in [(0x1000, "bootloader", 0xE9),
                                 (0x8000, "parttable", 0xAA),
                                 (0x20000, "app", 0xE9)]:
            if off + 4 > len(b):
                fail(f"{name} 偏移 {off:#x} 超出文件末尾")
                continue
            actual = b[off]
            if actual == magic:
                good(f"  {off:#08x} {name:<10} magic={actual:#04x}")
            else:
                fail(f"  {off:#08x} {name:<10} magic={actual:#04x}，期望 {magic:#04x}")
        od = b[0xE000:0xE000 + 0x2000]
        check_otadata(od, parts)
    else:
        fail("找不到 *factory.bin")

    # app 镜像
    print("\n[OTA / app 镜像]")
    ota_img = next(root.glob("*ota.bin"), None)
    desc_ver = None
    if ota_img:
        b = ota_img.read_bytes()
        good(f"{ota_img.name}  {len(b):>10,} B")
        if b[0] != 0xE9:
            fail("首字节 {:#04x}，不是 0xE9".format(b[0]))
        if len(b) >= 0x24:
            magic = struct.unpack_from("<I", b, 0x20)[0]
            if magic == APP_DESC_MAGIC:
                ver = b[0x30:0x50].split(b"\x00")[0].decode(errors="replace")
                desc_ver = ver
                good(f"  app 描述符 magic={magic:#010x} 版本={ver or '<空>'}")
                if not ver:
                    fail("app 描述符里版本为空（检查 version.txt 并 clean 重编译）")
            else:
                fail(f"  app 描述符 magic={magic:#010x}，期望 {APP_DESC_MAGIC:#010x}")
    else:
        fail("找不到 *ota.bin")

    # 版本号一致性：version.txt / 产物文件名 / app 描述符 三者必须一致
    print("\n[版本号一致性]")
    try:
        expect = vu.format_version(vu.read_version())
        good(f"version.txt = {expect}")
    except Exception as e:
        fail(f"读 version.txt 失败：{e}")
        expect = None

    if expect:
        base = vu.artifact_basename()
        for f in (factory, ota_img):
            if f is None:
                continue
            if f.name.startswith(base):
                good(f"  {f.name} 文件名版本号一致")
            else:
                fail(f"  {f.name} 文件名版本号与 {expect} 不符（应为 {base}-*.bin）")
        if desc_ver:
            if desc_ver == expect:
                good(f"  app 描述符版本 {desc_ver} 与 version.txt 一致")
            else:
                fail(f"  app 描述符版本 {desc_ver} 与 version.txt 的 {expect} 不一致"
                     "（改了 version.txt 后需要重新 cmake 配置：pio run -t clean 或删 .pio/build）")

    print()
    if ok:
        print("全部通过 ✓")
        return 0
    print("存在问题 ✗ —— 请先修复再烧录")
    return 1


if __name__ == "__main__":
    sys.exit(main())
