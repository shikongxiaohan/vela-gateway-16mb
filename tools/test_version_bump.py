#!/usr/bin/env python3
"""版本号自动递进机制的回归测试。

覆盖这几条不变量：
  1. 修订号最多 4 位、前导 0 省略：v0.0.0.2 / v0.0.0.10 / v0.0.0.9999
  2. 源码没变 → 版本号不动（重复编译不浪费修订号）
  3. 源码变了 → 修订号 +1
  4. 首次启用 → 递进一次
  5. 递进到 9999 后进位到构建号，修订号归零
  6. version.txt 与 src/vela_version.h 始终一致
  7. version.txt 是 IDF 标准文件，内容会进 app 描述符，格式必须是 vX.Y.Z.NNNN

用法：python3 tools/test_version_bump.py
退出码 0 = 全过
"""
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import version_util as vu  # noqa: E402

fails = []


def check(cond, msg):
    if cond:
        print(f"[ OK ] {msg}")
    else:
        print(f"[FAIL] {msg}")
        fails.append(msg)


def make_sandbox():
    """造一个临时项目目录，含 version.txt / src/ / tools/。"""
    tmp = Path(tempfile.mkdtemp(prefix="vela-ver-"))
    (tmp / "src").mkdir()
    (tmp / "tools").mkdir()
    (tmp / "src" / "main.cpp").write_text("int a=0;\n")
    # 用真实的 version_util 模块，但把 project_dir 指向 sandbox
    return tmp


def with_root(root, fn):
    """临时把 vu.project_dir() 指到 root。"""
    orig = vu.project_dir
    vu.project_dir = lambda: root
    try:
        return fn()
    finally:
        vu.project_dir = orig


def main() -> int:
    tmp = make_sandbox()

    def body():
        # ---- 1. 不补零，最多 4 位 ----
        t = (0, 0, 0, 2)
        check(vu.format_version(t) == "v0.0.0.2",
              "修订号 2 → v0.0.0.2（前导 0 不补）")
        check(vu.format_version((0, 0, 0, 10)) == "v0.0.0.10",
              "修订号 10 → v0.0.0.10（不是 0010）")
        check(vu.format_version((0, 0, 0, 1)) == "v0.0.0.1",
              "修订号 1 → v0.0.0.1")
        check(vu.format_version((1, 2, 3, 9999)) == "v1.2.3.9999",
              "高位不动：v1.2.3.9999（4 位上限）")
        check(vu.MAX_REVISION == 9999, "修订号上限是 4 位 = 9999")
        check(vu.parse_version("v0.0.0.2") == (0, 0, 0, 2),
              "能解析回整数元组")
        try:
            vu.parse_version("v0.0.0.10000")
            check(False, "超过 4 位的修订号应该报错")
        except ValueError:
            check(True, "超过 4 位（10000）会报错")
        try:
            vu.parse_version("0.0.0")
            check(False, "非法版本号应该报错")
        except ValueError:
            check(True, "非法版本号会报错")

        # ---- 初始状态：v0.0.0.1 ----
        vu.write_version((0, 0, 0, 1))
        check(vu.read_version() == (0, 0, 0, 1), "version.txt 初始为 v0.0.0.1")

        # ---- 4. 首次启用 → 递进一次 ----
        (tmp / "src" / "main.cpp").write_text("int a=1;\n")
        t, bumped = vu.prepare_for_build(tmp)
        check(bumped and t == (0, 0, 0, 2),
              "首次启用自动递进：0.0.0.1 → 0.0.0.2")
        check(vu.read_version() == t, "version.txt 已同步到 0.0.0.2")

        # ---- 6. 头文件与 version.txt 一致 ----
        hdr = (tmp / "src" / "vela_version.h").read_text()
        check('VELA_FW_REVISION_STR      "2"' in hdr,
              "vela_version.h 里的修订号字符串 = \"2\"（不补零）")
        check("#define VELA_FW_VERSION_REVISION  2" in hdr,
              "vela_version.h 里的整数修订号 = 2")
        check("// 版本号：v0.0.0.2" in hdr, "vela_version.h 注释里带完整版本号")

        # ---- 2. 源码没变 → 不递进 ----
        t2, bumped2 = vu.prepare_for_build(tmp)
        check(not bumped2 and t2 == (0, 0, 0, 2),
              "源码没变 → 版本号不动（重复编译不跳号）")

        # ---- 3. 源码变了 → 递进 ----
        vu.mark_built(tmp)          # 上一版视为已出包
        (tmp / "src" / "main.cpp").write_text("int a=2;\n")
        t3, bumped3 = vu.prepare_for_build(tmp)
        check(bumped3 and t3 == (0, 0, 0, 3),
              "源码变了 → 修订号 +1（0.0.0.2 → 0.0.0.3）")

        # ---- 3b. 源码变了但编译失败 → 不吃号 ----
        # 这条是为了堵住"版本号虚高、中间一串空号"的老毛病：
        # 只有 built=true（上一次真出了包）才允许占用新号。
        (tmp / "src" / "main.cpp").write_text("int a=3_broken;\n")
        t3b, bumped3b = vu.prepare_for_build(tmp)
        check(not bumped3b and t3b == (0, 0, 0, 3),
              "上次没出包（编译失败）→ 源码再变也不跳号，沿用 0.0.0.3")

        # 再连续失败两次，仍然不该动
        (tmp / "src" / "main.cpp").write_text("int a=4_broken;\n")
        t3c, _ = vu.prepare_for_build(tmp)
        (tmp / "src" / "main.cpp").write_text("int a=5_broken;\n")
        t3d, bumped3d = vu.prepare_for_build(tmp)
        check(not bumped3d and t3c == t3d == (0, 0, 0, 3),
              "连续多次编译失败也只占用一个号")

        # 一旦真的出包了，下一次源码变化才继续 +1
        vu.mark_built(tmp)
        (tmp / "src" / "main.cpp").write_text("int a=6;\n")
        t3e, bumped3e = vu.prepare_for_build(tmp)
        check(bumped3e and t3e == (0, 0, 0, 4),
              "出包后源码再变 → 正常 +1（0.0.0.3 → 0.0.0.4）")

        # ---- 7. version.txt 格式必须是 IDF 认的 ----
        txt = vu.version_txt_path().read_text().strip()
        check(txt.startswith("v") and len(txt.split(".")) == 4,
              f"version.txt 格式为 vX.Y.Z.N（当前 {txt}，修订号不补零）")
        check(vu.VERSION_RE.match(txt) is not None,
              "version.txt 能被自己的正则解析")

        # ---- 5. 9999 进位 ----
        # 进位发生在"递进"路径上，所以要先出过包、再改源码触发递进
        vu.write_version((0, 0, 0, vu.MAX_REVISION))
        vu.mark_built(tmp)
        (tmp / "src" / "main.cpp").write_text("int a=1000;\n")
        t4, bumped4 = vu.prepare_for_build(tmp)
        check(bumped4 and t4 == (0, 0, 1, 0),
              "修订号 9999 之后进位到构建号：v0.0.1.0")

        # ---- 产物名跟着版本走 ----
        vu.write_version((0, 0, 0, 42))
        check(vu.artifact_basename((0, 0, 0, 42)) ==
              "vela-gateway-v0.0.0.42-esp32-16mb",
              "产物文件名 = vela-gateway-v0.0.0.42-esp32-16mb")

        # ---- 指纹必须排除自动生成的文件 ----
        before = vu.source_fingerprint(tmp)
        vu.write_version((0, 0, 0, 43))      # 只改版本，不改源码
        after = vu.source_fingerprint(tmp)
        check(before == after,
              "只改版本号不会改变源码指纹（否则每次构建都跳号）")

        # ---- 指纹要能反映源码变化 ----
        (tmp / "src" / "main.cpp").write_text("int a=99;\n")
        code_only = vu.source_fingerprint(tmp)
        check(code_only != after,
              "源码变化会改变源码指纹")

        # ---- 改注释不该占版本号 ----
        # 注释不产生机器码。以前指纹按原始字节算，通篇整理一遍注释
        # 就会白跳十几个号，中间还留下一串从没出过包的版本。
        (tmp / "src" / "main.cpp").write_text(
            "int a=99;   // 只是加个注释\n")
        check(vu.source_fingerprint(tmp) == code_only,
              "只加行注释不改变指纹")

        (tmp / "src" / "main.cpp").write_text(
            "/* 块注释\n   多行 */\nint a=99;\n")
        check(vu.source_fingerprint(tmp) == code_only,
              "只加块注释不改变指纹")

        (tmp / "src" / "main.cpp").write_text(
            "\n\n\nint a=99;\n\n\n")
        check(vu.source_fingerprint(tmp) == code_only,
              "多几个空行也不改变指纹")

        (tmp / "src" / "main.cpp").write_text(
            "const char* u=\"http://x//y\";\nint a=99;\n")
        check(vu.source_fingerprint(tmp) != code_only,
              "字符串里的 // 算代码，改了就要变指纹")

        (tmp / "src" / "main.cpp").write_text(
            "auto h=R\"HTML(<a href=\"//x\">)HTML\";\nint a=99;\n")
        check(vu.source_fingerprint(tmp) != code_only,
              "raw string 里的 // 算内容，改了就要变指纹")

    try:
        with_root(tmp, body)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    if fails:
        print(f"[FAIL] {len(fails)} 项未通过：")
        for f in fails:
            print(f"    {f}")
        return 1
    print("全部通过：修订号最多 4 位不补零、源码不变不跳号、编译失败不占号、出包后源码变了才 +1、9999 正确进位")
    return 0


if __name__ == "__main__":
    sys.exit(main())
