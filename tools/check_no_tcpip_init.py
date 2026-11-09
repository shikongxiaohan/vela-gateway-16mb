#!/usr/bin/env python3
"""静态检查：源码里不得直接调用 tcpip_init()。

为什么需要这个检查（2026-11-09 第十五章）：
    IDF 的 esp_netif_init() 内部已经会调一次 tcpip_init()，而 lwip_init()
    **没有幂等保护** —— 它每次都会再跑一遍 sys_init()，于是
    esp_vfs_lwip_sockets_register() 被调用两次。socket 的 fd 区间
    [FD_SETSIZE-N .. FD_SETSIZE-1) 在 esp_vfs 里是「永久占用」的，
    第二次注册必然返回 ESP_ERR_INVALID_ARG (0x102)，撞上 vfs_lwip.c 里的
    ESP_ERROR_CHECK → abort() → 设备每 2.6 秒重启一次，永远进不了配网模式。

    正确做法：用 esp_netif_init()（自带 tcpip_initialized 保护，重复调用安全）。

用法：
    python3 tools/check_no_tcpip_init.py [源码目录]     # 默认 src/
退出码：0 = 通过；1 = 发现违规调用。
"""

import re
import sys
from pathlib import Path

# 注释里的 tcpip_init（比如"绝对不要直接调 tcpip_init()"）不算违规，
# 所以先把注释剥掉再匹配。
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"//[^\n]*")
_CALL = re.compile(r"\btcpip_init\s*\(")
# 允许出现的形式：esp_netif_init( / lwip_tcpip_init( 之类的前缀不算
_ALLOWED_PREFIX = re.compile(r"\b(\w+_)?tcpip_init\s*\(")


def strip_comments(text: str) -> str:
    text = _BLOCK_COMMENT.sub(" ", text)
    return _LINE_COMMENT.sub(" ", text)


def scan_file(path: Path):
    """返回该文件里违规调用的行号列表（1 基）。"""
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    hits = []
    for lineno, line in enumerate(strip_comments(raw).splitlines(), start=1):
        for m in _CALL.finditer(line):
            # 前面紧挨着的标识符字符（字母/数字/下划线）说明是别的函数名的一部分
            prefix = line[: m.start()]
            if prefix and (prefix[-1].isalnum() or prefix[-1] == "_"):
                continue
            hits.append(lineno)
            break
    return hits


def main(argv):
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent.parent / "src"
    files = sorted(p for p in root.rglob("*")
                   if p.suffix in (".c", ".cpp", ".cc") and p.is_file())

    bad = []
    for f in files:
        for lineno in scan_file(f):
            bad.append((f, lineno))

    if not bad:
        print("[tcpip-init] ✓ 未发现直接调用 tcpip_init()（应使用 esp_netif_init()）")
        return 0

    print("[tcpip-init] ✗ 发现直接调用 tcpip_init() —— 这会导致 abort 无限重启！")
    for f, lineno in bad:
        print(f"    {f}:{lineno}")
    print("    改用 esp_netif_init()（自带 tcpip_initialized 保护，重复调用安全）。")
    print("    背景见 变更说明.md 第十五章。")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
