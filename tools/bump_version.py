#!/usr/bin/env python3
"""递进固件版本号（修订号 +1），并同步 version.txt 与 src/vela_version.h。

用法：
    python3 tools/bump_version.py            # 递进一次并打印
    python3 tools/bump_version.py --show     # 只看当前版本
    python3 tools/bump_version.py --set v0.0.0.0007

递进语义：修订号 +1（4 位零填充），到 9999 后进位到构建号。
构建流程本身也会自动递进（见 tools/pio_verify.py），这个脚本用于手动提前占号。
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import version_util as vu  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--show", action="store_true", help="只显示当前版本，不修改")
    ap.add_argument("--set", dest="set_to", help="显式指定目标版本，如 v0.0.0.0007")
    args = ap.parse_args()

    if args.show:
        t = vu.read_version()
        print(f"当前版本 {vu.format_version(t)}  产物名 {vu.artifact_basename(t)}")
        return 0

    if args.set_to:
        t = vu.parse_version(args.set_to)
        vu.write_version(t)
        print(f"版本已设为 {vu.format_version(t)}")
        return 0

    old = vu.format_version(vu.read_version())
    t = vu.bump_revision()
    new = vu.format_version(t)
    print(f"版本递进 {old} → {new}")
    print(f"产物文件名 {vu.artifact_basename(t)}-factory.bin / -ota.bin")
    return 0


if __name__ == "__main__":
    sys.exit(main())
