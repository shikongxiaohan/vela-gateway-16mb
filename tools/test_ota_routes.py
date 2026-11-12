#!/usr/bin/env python3
"""检查 OTA 路由的上传回调是否注册完整。

背景：/ota/upload2 是手机升级页实际调用的接口，注册时只写了三个参数，漏掉了
上传回调。ESP32WebServer 的 FunctionRequestHandler::canUpload() 在回调为空时
直接返回 false，于是 multipart 数据被静默丢弃，但响应处理函数照样读到空的
s_otaTotalWritten 并回 ok=true。表现是：页面显示「刷写完成」，设备重启，版本号
一位没变。这个 bug 在浏览器侧完全看不出来，只能靠静态检查钉住。

检查项：
  1. /ota/upload 与 /ota/upload2 都注册了上传回调
  2. 回调函数存在且处理了 START / WRITE / END
  3. 两个响应处理都在零字节写入时报错，不再回成功
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

    # ---- 1. 两个路由都要带第 4 个参数 ----
    for route in ("/ota/upload", "/ota/upload2"):
        pattern = re.compile(
            r'server\.on\(\s*"' + re.escape(route) + r'"\s*,\s*HTTP_POST\s*,.*?\}\s*,\s*([A-Za-z_]\w*)\s*\)\s*;',
            re.S,
        )
        m = pattern.search(text)
        check(m is not None, f"{route} 注册了上传回调")
        if m:
            check(m.group(1) == "otaUploadCallback",
                  f"{route} 的上传回调是 otaUploadCallback（实际 {m.group(1)}）")

    # ---- 2. 回调函数实现 ----
    m = re.search(r"void otaUploadCallback\(\)\s*\{", text)
    check(m is not None, "定义了 otaUploadCallback()")
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
        for stage in ("UPLOAD_FILE_START", "UPLOAD_FILE_WRITE", "UPLOAD_FILE_END"):
            check(stage in body, f"回调处理 {stage}")
        check("Update.write" in body, "回调把数据交给 Update 写入分区")

    # ---- 3. 零字节写入不能回成功 ----
    zeros = re.findall(r"if\s*\(\s*s_otaTotalWritten\s*==\s*0\s*\)", text)
    check(len(zeros) >= 2, f"两个响应处理都检查零字节写入（找到 {len(zeros)} 处）")

    print()
    for ok, msg in checks:
        print(("[OK] " if ok else "[FAIL] ") + msg)
    print()
    if fails:
        print(f"[FAIL] {len(fails)} 项未通过：")
        for f in fails:
            print("  - " + f)
        print("\n[ota] OTA 路由检查未通过")
        return 1
    print(f"全部通过（{len(checks)} 项）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
