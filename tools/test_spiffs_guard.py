#!/usr/bin/env python3
"""检查 SPIFFS 挂载前提。

背景：SPIFFS 曾是懒挂载，只在录音路径（beginWatchStreamCapture）里
SPIFFS.begin()。结果是没录过音的设备上，固件库和表盘上传必然失败：
SPIFFS.open() 返回 false，写入全被跳过，最后误报成「不是 app 镜像」。
这个 bug 编译期查不出来，只能靠静态检查钉住。

检查项：
  1. SPIFFS.begin 只出现在 ensureSpiffs() 内部
  2. 所有操作文件系统的路由入口都先调 ensureSpiffs()
  3. 上传处理器里 END 分支不能无条件清失败标志
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "main.cpp"

checks = []
fails = []


def check(ok: bool, msg: str):
    checks.append((ok, msg))
    if not ok:
        fails.append(msg)


def main() -> int:
    if not SRC.exists():
        print(f"[FAIL] 找不到 {SRC}")
        return 1
    text = SRC.read_text("utf-8", errors="replace")

    # ---- 1. SPIFFS.begin 只允许出现在 ensureSpiffs 里 ----
    begin_sites = [m.start() for m in re.finditer(r"SPIFFS\.begin\s*\(", text)]
    check(len(begin_sites) >= 1, "存在 SPIFFS.begin 调用")

    # 找到 ensureSpiffs 函数体范围
    m = re.search(r"bool ensureSpiffs\(\)\s*\{", text)
    check(m is not None, "定义了 ensureSpiffs()")
    if m:
        depth = 0
        start = m.end() - 1
        end = start
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        body = text[start:end + 1]
        check("SPIFFS.begin" in body, "ensureSpiffs() 内部调用 SPIFFS.begin")
        outside = [p for p in begin_sites if not (start <= p <= end)]
        check(not outside,
              f"SPIFFS.begin 只出现在 ensureSpiffs 内（发现 {len(outside)} 处越界调用）")

    # ---- 2. 文件系统路由入口都要先挂载 ----
    routes = [
        "/api/v1/firmware/upload",
        "/api/v1/firmware/list",
        "/api/v1/firmware/install",
        "/api/v1/firmware/delete",
        "/api/v1/resource/list",
        "/api/v1/resource/upload",
        "/api/v1/resource/install",
        "/api/v1/resource/delete",
    ]
    for route in routes:
        idx = text.find(f'server.on("{route}"')
        if idx < 0:
            check(False, f"路由 {route} 存在")
            continue
        # 取该路由后 900 字符内的代码，确认有 ensureSpiffs
        window = text[idx:idx + 900]
        check("ensureSpiffs()" in window, f"路由 {route} 在入口处调用 ensureSpiffs()")

    # ---- 3. 上传 END 分支行为 ----
    # 固件库上传：END 里必须保留失败状态，不能再出现「无条件 gUploadFailed = false」
    fw_idx = text.find('server.on("/api/v1/firmware/upload"')
    check(fw_idx > 0, "找到固件上传路由")
    if fw_idx > 0:
        seg = text[fw_idx:fw_idx + 6000]
        end_idx = seg.find("UPLOAD_FILE_END")
        check(end_idx > 0, "固件上传处理 UPLOAD_FILE_END 分支")
        if end_idx > 0:
            end_seg = seg[end_idx:end_idx + 700]
            # 允许 gUploadFailed = true，不允许直接写 false
            bad = re.search(r"gUploadFailed\s*=\s*false", end_seg)
            check(bad is None,
                  "UPLOAD_FILE_END 不会无条件清除上传失败标志")
        check("gUploadWritten" in seg, "固件上传统计实际写入字节数")

    # ---- 4. 错误码要能区分三类失败 ----
    for code in ("storage_unavailable", "write_incomplete", "not_app_image"):
        check(code in text, f"存在错误码 {code}")

    # ---- 输出 ----
    for ok, msg in checks:
        print(f"[{'OK' if ok else 'FAIL'}] {msg}")

    if fails:
        print(f"\n[FAIL] {len(fails)} 项未通过：")
        for f in fails:
            print(f"  - {f}")
        return 1
    print(f"\n全部通过（{len(checks)} 项）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
