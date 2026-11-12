#!/usr/bin/env python3
"""两个网页的内嵌 JS 语法检查。

为什么要有这个：管理台的 JS 是写在 main.cpp 的 R"HTML(...)" 里的一整段字符串，
改文案时很容易少删一个引号，编译照样通过，页面却在真机上白屏。
改文案时想删掉提示前面的对勾，结果连引号一起删了，
变成 innerHTML='+name+...'，整个 script 块语法错误。

做法：把 <script> 里的内容抽出来交给 node --check，只做语法校验，不执行。
node 不在的话跳过（不阻断构建）。
"""
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "main.cpp"

failures = []
checks = 0


def check(ok, msg):
    global checks
    checks += 1
    print(f"[ {'OK' if ok else 'FAIL'} ] {msg}")
    if not ok:
        failures.append(msg)


def extract_pages(text):
    """取出所有 PROGMEM 的 HTML 页面，返回 {变量名: 内容}。"""
    pages = {}
    for m in re.finditer(
        r'const char (\w+)\[\] PROGMEM = R"(\w+)\((.*?)\)\2";', text, re.S
    ):
        pages[m.group(1)] = m.group(3)
    return pages


def scripts_of(html):
    return re.findall(r"<script[^>]*>(.*?)</script>", html, re.S)


def main():
    if not SRC.exists():
        print(f"找不到 {SRC}")
        return 1

    text = SRC.read_text(encoding="utf-8")
    pages = extract_pages(text)
    check(len(pages) >= 2, f"找到 {len(pages)} 个页面（{'、'.join(pages)}）")

    node = shutil.which("node")
    if not node:
        print("[SKIP] 没装 node，跳过 JS 语法检查")
        return 0 if not failures else 1

    total_blocks = 0
    for name, html in pages.items():
        blocks = scripts_of(html)
        total_blocks += len(blocks)
        check(len(blocks) > 0, f"{name} 里有 {len(blocks)} 段 script")
        for i, code in enumerate(blocks):
            # 占位符在真机上会被替换成实际值，换成合法字面量再验
            code = re.sub(r"__PH_[A-Z_]+__", "PLACEHOLDER", code)
            with tempfile.NamedTemporaryFile(
                "w", suffix=".js", delete=False, encoding="utf-8"
            ) as fh:
                fh.write(code)
                path = fh.name
            r = subprocess.run([node, "--check", path],
                               capture_output=True, text=True)
            Path(path).unlink(missing_ok=True)
            ok = r.returncode == 0
            check(ok, f"{name} 第 {i + 1} 段 script 语法正确")
            if not ok:
                # 只打前几行，node 的报错很长
                err = (r.stderr or "").strip().splitlines()
                for line in err[:6]:
                    print("      " + line)

    check(total_blocks >= 2, f"共检查 {total_blocks} 段 script")

    # 顺手挡一下别的页面里残留的整页 malloc 复制
    for name, html in pages.items():
        if name == "kWebUi":
            check("malloc(total" not in html,
                  "页面字符串里没有整页 malloc 的痕迹")

    print()
    if failures:
        print(f"[FAIL] {len(failures)} 项未通过")
        return 1
    print(f"全部通过（{checks} 项）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
