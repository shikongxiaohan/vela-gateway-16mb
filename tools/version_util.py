#!/usr/bin/env python3
"""固件版本号的唯一真源（single source of truth）。

设计
----
版本号四段：主.次.构建.修订  →  展示为  v0.0.0.1

* 前三位语义不变（见 src/main.cpp 里的说明注释）。
* 修订号最多 4 位，前导 0 省略：`v0.0.0.1` / `v0.0.0.9` / `v0.0.0.10`
  …… 一直到 `v0.0.0.9999`（上限 4 位），再往上就进位到构建号。
  也就是说这是"整数，最多 4 位"，不是零填充的定长字段。
  所以修订号直接用整数拼字符串就行，不需要额外的补零字符串。
* `version.txt` 是根目录的 IDF 标准文件，内容会被写进镜像的 app 描述符
  （偏移 0x30），`tools/verify_firmware.py` 从那里读回来校验。
  所以它和 `src/vela_version.h` 必须始终一致，由本模块统一读写。

对外接口
--------
    read_version()            -> (major, minor, build, revision)
    format_version(t)         -> "v0.0.0.2"
    write_version(t)          写 version.txt + 同步生成 src/vela_version.h
    bump_revision()           修订号 +1（不越界到 BUILD），返回新版本元组
"""
import hashlib
import json
import re
from datetime import date
from pathlib import Path

VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)\.(\d{1,4})$")
MAX_REVISION = 9999          # 修订号最多 4 位：1 ~ 9999，前导 0 省略


def project_dir() -> Path:
    return Path(__file__).resolve().parent.parent


def version_txt_path() -> Path:
    return project_dir() / "version.txt"


def header_path() -> Path:
    return project_dir() / "src" / "vela_version.h"


def parse_version(text: str):
    """解析 'v0.0.0.1' → (0, 0, 0, 1)"""
    m = VERSION_RE.match(text.strip())
    if not m:
        raise ValueError(f"版本号格式不对（要 v主.次.构建.修订，修订最多 4 位）：{text!r}")
    return tuple(int(x) for x in m.groups())


def format_version(t) -> str:
    """(0,0,0,1) → 'v0.0.0.1'；修订号是整数，前导 0 不补。"""
    major, minor, build, revision = t
    return f"v{major}.{minor}.{build}.{revision}"


def format_revision(revision: int) -> str:
    return str(revision)


def read_version():
    p = version_txt_path()
    if not p.exists():
        raise FileNotFoundError(f"缺少 {p}")
    return parse_version(p.read_text(encoding="utf-8"))


def render_header(t, build_date: str) -> str:
    major, minor, build, revision = t
    return f"""// 由 tools/version_util.py 自动生成，别手工改。
//
// 生成来源：version.txt（根目录） + 生成时的日期
// 版本号：{format_version(t)}
//
// 想改版本号，改 version.txt 后重新构建即可；构建流程会重新生成本文件。
// 版本语义（主.次.构建.修订）见 src/main.cpp 的说明注释。
#pragma once

#define VELA_FW_VERSION_MAJOR     {major}
#define VELA_FW_VERSION_MINOR     {minor}
#define VELA_FW_VERSION_BUILD     {build}
#define VELA_FW_VERSION_REVISION  {revision}
// 修订号的字符串形式（最多 4 位，前导 0 不补），用于版本展示和产物文件名
#define VELA_FW_REVISION_STR      "{format_revision(revision)}"
// 实际构建日期 YYYYMMDD
#define VELA_FW_BUILD_DATE        "{build_date}"
"""


def write_version(t, build_date: str = None):
    """写 version.txt + 重新生成 src/vela_version.h"""
    t = tuple(t)
    if build_date is None:
        build_date = date.today().strftime("%Y%m%d")
    version_txt_path().write_text(format_version(t) + "\n", encoding="utf-8")
    header_path().write_text(render_header(t, build_date), encoding="utf-8")
    return t


def bump_revision():
    """修订号 +1。到上限后进位到 BUILD，修订号归零。"""
    major, minor, build, revision = read_version()
    revision += 1
    if revision > MAX_REVISION:
        revision = 0
        build += 1
    t = (major, minor, build, revision)
    write_version(t)
    return t


def artifact_basename(t=None, hardware: str = "esp32-16mb") -> str:
    """产物文件名主干：vela-gateway-v0.0.0.0002-esp32-16mb"""
    if t is None:
        t = read_version()
    return f"vela-gateway-{format_version(t)}-{hardware}"


# ---------------------------------------------------------------------------
# 源码指纹：用来判断"这次构建的内容和上次是否一样"
# ---------------------------------------------------------------------------

# 参与指纹的文件（相对项目根）。注意不要把 version.txt 和
# src/vela_version.h 算进去，它们每次构建都会被改写，算进去就永远"变了"，
# 结果是每编译一次就多跳一个修订号（实测跳到了 0004）。
FINGERPRINT_GLOBS = [
    "src/*.cpp",
    "src/*.c",
    "src/*.hpp",
    "src/*.h",
    "src/CMakeLists.txt",
    "CMakeLists.txt",
    "platformio.ini",
]

# 明确排除：这些文件由版本机制自己生成，不能参与指纹
FINGERPRINT_EXCLUDE = {
    "src/vela_version.h",
    "version.txt",
}

STATE_FILE = ".pio/.vela_version_state.json"


def strip_comments(src: str) -> str:
    """去掉 C/C++ 源里的注释，供计算指纹用。

    为什么需要：注释不产生机器码，改注释不该占一个发布号。
    但直接正则删 `//` 会误伤字符串里的内容（`"http://..."`、
    内嵌 HTML 里的 `//`、`/*` 都在字符串里），所以必须按词法走一遍。

    也要处理 raw string（R"TAG(...)TAG"），否则内嵌的整页 HTML
    会被当成代码扫描，里面随便一个引号就把状态机带偏。

    剥完之后还会压掉行尾空白和多余空行。这一步不是为了好看：
    指纹只用来判断"代码有没有变"，跟行号无关。如果保留注释留下的空行，
    那么"多加一行注释"依然会改变指纹，等于白做。
    """
    out = []
    i = 0
    n = len(src)
    # 状态：0=代码 1=普通字符串 2=字符常量
    state = 0
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        if state == 0:
            # 行注释：整段丢掉，连同它前面的行尾空白
            if ch == "/" and nxt == "/":
                while out and out[-1] in (" ", "\t"):
                    out.pop()
                j = src.find("\n", i)
                i = n if j < 0 else j          # 换行留着，但不影响指纹
                continue
            # 块注释
            if ch == "/" and nxt == "*":
                while out and out[-1] in (" ", "\t"):
                    out.pop()
                j = src.find("*/", i + 2)
                i = n if j < 0 else j + 2
                continue
            # raw string：R"tag( ... )tag"
            if ch == "R" and nxt == '"':
                k = src.find("(", i + 2)
                if k < 0:
                    out.append(ch); i += 1; continue
                tag = src[i + 2:k]
                close = ")" + tag + '"'
                j = src.find(close, k + 1)
                if j < 0:
                    out.append(src[i:]); i = n; continue
                out.append(src[i:j + len(close)])
                i = j + len(close)
                continue
            if ch == '"':
                state = 1
                out.append(ch); i += 1; continue
            if ch == "'":
                state = 2
                out.append(ch); i += 1; continue
            out.append(ch); i += 1
            continue

        # 字符串 / 字符常量内部：只认转义和结束引号
        if ch == "\\" and i + 1 < n:
            out.append(src[i:i + 2]); i += 2; continue
        if (state == 1 and ch == '"') or (state == 2 and ch == "'"):
            state = 0
        out.append(ch); i += 1

    # 压掉行尾空白和多余空行：指纹只关心代码长什么样，不关心占了几行
    lines = [ln.rstrip() for ln in "".join(out).split("\n")]
    squeezed = []
    for ln in lines:
        if ln or (squeezed and squeezed[-1]):
            squeezed.append(ln)
    return "\n".join(squeezed).strip()


def source_fingerprint(root: Path = None) -> str:
    """源码指纹（sha256）。用于判断两次构建的内容是否相同。

    C/C++ 源先剥掉注释再算，所以改注释不会改变指纹，也就不会白占一个版本号。
    非源码文件（platformio.ini / CMakeLists.txt）原样参与，那几个文件
    改了就是真的会改变构建结果。
    """
    if root is None:
        root = project_dir()
    h = hashlib.sha256()
    code_suffix = {".cpp", ".c", ".hpp", ".h"}
    for pattern in FINGERPRINT_GLOBS:
        for p in sorted(root.glob(pattern)):
            if not p.is_file():
                continue
            rel = str(p.relative_to(root))
            if rel in FINGERPRINT_EXCLUDE:
                continue
            h.update(rel.encode())
            h.update(b"\0")
            if p.suffix in code_suffix:
                body = strip_comments(p.read_text("utf-8", "replace"))
                h.update(body.encode("utf-8"))
            else:
                h.update(p.read_bytes())
            h.update(b"\0")
    return h.hexdigest()


def state_path(root: Path = None) -> Path:
    if root is None:
        root = project_dir()
    return root / STATE_FILE


def read_state(root: Path = None) -> dict:
    p = state_path(root)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {}


def write_state(state: dict, root: Path = None):
    p = state_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def prepare_for_build(root: Path = None, force_bump: bool = False):
    """构建前调用：决定这次构建用哪个版本号，并写好 version.txt + 头文件。

    规则：
      * 源码指纹和上次一致 → 版本号不变（重复编译不浪费修订号）
      * 源码变了，但上一次的号还没出过包 → 沿用原号（编译失败不该吃号）
      * 源码变了，且上一次已出过包 → 修订号 +1
      * 首次构建（没有状态文件）→ 沿用 version.txt 里的当前版本作为基线

    返回 (版本元组, 是否发生了递进)。
    """
    if root is None:
        root = project_dir()
    fp = source_fingerprint(root)
    st = read_state(root)
    cur = read_version()

    bumped = False
    if force_bump:
        t = (cur[0], cur[1], cur[2], cur[3] + 1)
        bumped = True
    elif not st.get("fingerprint"):
        # 第一次用这套自动版本机制 → 内容肯定和上一个已发布固件不同，递进一次
        t = (cur[0], cur[1], cur[2], cur[3] + 1)
        bumped = True
    elif st["fingerprint"] != fp and st.get("built"):
        # 源码变了，且上一次的号确实出过包 → 这个号已被占用，换下一个
        t = (cur[0], cur[1], cur[2], cur[3] + 1)
        bumped = True
    else:
        # 两种情况共用这一支：
        #   1) 源码没变，重复编译；
        #   2) 源码变了，但上一次编译没走到最后（built=false）。
        # 第 2 种是关键：编译失败不该白吃一个修订号，否则版本号虚高，
        # 而且会留出一串从没出过包的空号，发版时自己也说不清。
        t = cur

    if bumped and t[3] > MAX_REVISION:
        t = (t[0], t[1], t[2] + 1, 0)

    write_version(t)
    write_state({"version": format_version(t), "fingerprint": fp,
                 "built": False}, root)
    return t, bumped


def mark_built(root: Path = None):
    """构建成功后调用：标记这次版本已经出包。"""
    if root is None:
        root = project_dir()
    st = read_state(root)
    if st:
        st["built"] = True
        write_state(st, root)


if __name__ == "__main__":
    t = read_version()
    print(format_version(t), "->", artifact_basename(t))
