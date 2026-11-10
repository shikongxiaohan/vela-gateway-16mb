#!/usr/bin/env python3
"""生成带版本号的固件产物：factory 整包 + ota app 镜像。

产物文件名跟着版本号走：
    firmware/vela-gateway-v0.0.0.0002-esp32-16mb-factory.bin
    firmware/vela-gateway-v0.0.0.0002-esp32-16mb-ota.bin

factory 整包的构成（偏移固定，别改）：
    0x1000  bootloader.bin
    0x8000  partitions.bin
    0xe000  ota_data_initial.bin
    0x20000 firmware.bin (app)

用法：
    python3 tools/make_artifacts.py                # 用当前版本号
    python3 tools/make_artifacts.py --version v0.0.0.0007
退出码 0 = 成功
"""
import argparse
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import version_util as vu  # noqa: E402

BUILD_DIR = Path(".pio/build/yd_esp32_16mb")
FW_DIR = Path("firmware")
HARDWARE = "esp32-16mb"

# esptool 需要 pyserial，只有 PlatformIO 自带的那个 python 环境里有，
# 所以这里优先用它。
PY_CANDIDATES = ["/root/pioenv/bin/python", sys.executable]


def find_esptool() -> Path:
    for base in Path.home().glob(".platformio/packages/tool-esptoolpy"):
        cand = base / "esptool.py"
        if cand.exists():
            return cand
    raise FileNotFoundError("找不到 esptool.py")


def pick_python() -> str:
    for p in PY_CANDIDATES:
        if p and Path(p).exists():
            r = subprocess.run([p, "-c", "import serial"], capture_output=True)
            if r.returncode == 0:
                return p
    return sys.executable


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", help="显式指定版本号，默认取 version.txt")
    args = ap.parse_args()

    root = vu.project_dir()
    build_dir = root / BUILD_DIR
    fw_dir = root / FW_DIR
    fw_dir.mkdir(exist_ok=True)

    if args.version:
        t = vu.parse_version(args.version)
    else:
        t = vu.read_version()

    base = vu.artifact_basename(t, HARDWARE)
    archive_dir = root / "firmware-history"

    # 0) 同版本号已经归档过 → 直接复用归档那份，不重新生成。
    #    原因：同一份源码编译两次，字节会因为编译时间戳不同而不一样。
    #    如果版本号没变（源码没改），却重新编译并覆盖 firmware/，
    #    就会出现「firmware/ 里的 v0.0.0.3 和 Release / 归档里的 v0.0.0.3
    #    不是同一份字节」的情况，刷机时无法用 md5 核对，非常坑。
    #    所以：版本号已存在就认归档那份为准。
    archived = (archive_dir / f"{base}-factory.bin", archive_dir / f"{base}-ota.bin")
    if all(p.exists() for p in archived):
        for src in archived:
            dst = fw_dir / src.name
            if not dst.exists() or dst.read_bytes() != src.read_bytes():
                shutil.copyfile(src, dst)
                print(f"✓ {src.name}  （复用归档版本，字节与已发布产物一致）")
            else:
                print(f"✓ {src.name}  （已是最新）")
        return 0

    # 1) app 镜像 → ota
    app = build_dir / "firmware.bin"
    if not app.exists():
        print(f"✗ 找不到 {app}，先构建固件")
        return 1
    ota_out = fw_dir / f"{base}-ota.bin"
    shutil.copyfile(app, ota_out)

    # 2) 合并 factory 整包
    esptool = find_esptool()
    py = pick_python()
    parts = [
        ("0x1000", build_dir / "bootloader.bin"),
        ("0x8000", build_dir / "partitions.bin"),
        ("0xe000", build_dir / "ota_data_initial.bin"),
        ("0x20000", app),
    ]
    missing = [str(p) for _, p in parts if not p.exists()]
    if missing:
        print("✗ 缺少合并所需文件：")
        for m in missing:
            print(f"    {m}")
        return 1

    factory_out = fw_dir / f"{base}-factory.bin"
    cmd = [py, str(esptool), "--chip", "esp32", "merge_bin",
           "-o", str(factory_out), "--flash_mode", "dio",
           "--flash_freq", "40m", "--flash_size", "16MB"]
    for off, path in parts:
        cmd += [off, str(path)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("✗ merge_bin 失败：")
        print(r.stdout[-2000:])
        print(r.stderr[-2000:])
        return 1

    print(f"✓ {ota_out.name}  {ota_out.stat().st_size:>10,} B")
    print(f"✓ {factory_out.name}  {factory_out.stat().st_size:>10,} B")

    # 3) 归档：每个版本都留一份到 firmware-history/
    #    早期实现是"删掉旧版本产物"，结果回滚时发现历史固件没了 ——
    #    固件是二进制、不可重建（同样的源码在不同工具链/依赖下出的字节不同），
    #    所以必须每个版本都留着，宁可多占几 MB。
    archive_dir.mkdir(exist_ok=True)
    for src, dst in ((factory_out, archive_dir / factory_out.name),
                     (ota_out, archive_dir / ota_out.name)):
        if not dst.exists():
            shutil.copyfile(src, dst)
            print(f"  归档 {dst.name}")
    # MD5 清单也跟着更新，方便核对刷的是不是想要的版本
    sums = sorted(archive_dir.glob("vela-gateway-*.bin"))
    if sums:
        lines = []
        for f in sums:
            h = hashlib.md5(f.read_bytes()).hexdigest()
            lines.append(f"{h}  {f.name}")
        (archive_dir / "MD5SUMS.txt").write_text("\n".join(lines) + "\n",
                                                 encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
