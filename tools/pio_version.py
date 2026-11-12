# PlatformIO 构建前钩子：自动递进固件版本号。
#
# 为什么单独一个文件：
#   版本号必须在**编译之前**定下来（src/vela_version.h 要被 main.cpp 包含），
#   而 PlatformIO 的 extra_scripts 是 pre: 阶段加载的，正好在编译之前跑。
#   放在 pio_verify.py 的 AddPreAction 里就晚了，那时 .o 可能已经编完。
#
# 递进规则（详见 tools/version_util.py）：
#   * 唯一真源是根目录 version.txt（v0.0.0.0002 这种四位修订号）
#   * 源码指纹和上次一致 → 版本号不动（重复编译不浪费修订号）
#   * 源码变了 → 修订号 +1，并同步写回 version.txt + src/vela_version.h
#   * 这样网页徽章、串口横幅、app 描述符、产物文件名里的版本号永远一致
#
# 只对主环境 yd_esp32_16mb 递进：其它环境（legacy_4mb 等）复用同一份
# 版本号，否则一次 pio run -e a -e b 会白白多跳一位。

import os
import sys
from pathlib import Path

Import("env")  # noqa: F821  (PlatformIO 注入)

sys.path.insert(0, str(Path(env.subst("$PROJECT_DIR")) / "tools"))
import version_util as vu  # noqa: E402

PRIMARY_ENV = "yd_esp32_16mb"


def _is_real_build() -> bool:
    """排除 `pio run -t check-images` 这类只跑校验、不出固件的目标。"""
    try:
        from SCons.Script import COMMAND_LINE_TARGETS
        targets = set(COMMAND_LINE_TARGETS or [])
    except Exception:
        return True
    if targets and targets.issubset({"check-images"}):
        return False
    return True


def bump_version_for_build():
    if env.subst("$PIOENV") != PRIMARY_ENV:
        return
    if not _is_real_build():
        return
    try:
        t, bumped = vu.prepare_for_build(Path(env.subst("$PROJECT_DIR")))
    except Exception as e:      # 版本机制出问题不该拖垮整个构建
        print(f"[version] 警告：版本自动递进失败（{e}），沿用现有版本号")
        return
    if bumped:
        print(f"[version] 版本已自动递进 → {vu.format_version(t)}")
        # app 描述符里的版本是 IDF 在 **cmake configure 阶段**从 version.txt
        # 读进去的（PROJECT_VER），增量构建不会自动重跑 configure，
        # 于是镜像里的描述符会停在旧版本号。
        # 摸一下根 CMakeLists.txt 的 mtime，强制 cmake 重新 configure，
        # 这样描述符版本、文件名、version.txt 三者才对得上。
        _touch_cmake()
    else:
        print(f"[version] 版本沿用（源码未变）→ {vu.format_version(t)}")
    print(f"[version] 产物文件名 {vu.artifact_basename(t)}-factory.bin / -ota.bin")


def _touch_cmake():
    root = Path(env.subst("$PROJECT_DIR"))
    for rel in ("CMakeLists.txt", "src/CMakeLists.txt"):
        p = root / rel
        if p.exists():
            try:
                os.utime(p, None)
            except OSError:
                pass


bump_version_for_build()
