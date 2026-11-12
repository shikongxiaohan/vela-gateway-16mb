#!/usr/bin/env python3
"""检查系统页「固件升级」与「向手表推一条消息」两个功能不会假装成功。

背景（两个真实的坑）：
  1. 系统页上传走 /api/v1/ota/upload。只要路由注册漏掉上传回调，或者前端
     用 FormData 字段名对不上 server.upload().filename，文件就会被静默丢弃。
     更麻烦的是页面此时没有任何反馈，看起来像「按钮坏了」。
     现在要求：路由带回调、前端带镜像头自检、失败分支必须有提示文本。
  2. 推送接口以前只要入队就回 ok=true，页面弹「已加入队列」，而真正发没发
     出去只有会话线程知道。现在必须做到「接口只负责入队，结果由
     /api/v1/watch/push/result 查询」，并且会话线程要在每条投递后记录
     成功/失败原因。

检查项：
  1. /api/v1/ota/upload 注册了上传回调 otaDirectUploadCallback
  2. 回调覆盖 START / WRITE / END / ABORTED 四个阶段，并写阶段名
  3. 前端上传前读镜像头校验 0xE9 + 0xABCD5432
  4. 上传失败 / 中断都有可见文案（不允许静默）
  5. /api/v1/watch/push 不再返回「入队即成功」的成功语义
  6. 存在 /api/v1/watch/push/result 且返回 state
  7. 投递函数在成功与失败两条路径上都写结果
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

    # ---- 1. 直传路由必须带上传回调 ----
    m = re.search(
        r'server\.on\(\s*"/api/v1/ota/upload"\s*,\s*HTTP_POST\s*,.*?\}\s*,\s*([A-Za-z_]\w*)\s*\)\s*;',
        text, re.S,
    )
    check(m is not None, "/api/v1/ota/upload 注册了上传回调")
    if m:
        check(m.group(1) == "otaDirectUploadCallback",
              f"回调是 otaDirectUploadCallback（实际 {m.group(1)}）")

    # ---- 2. 回调阶段 ----
    m = re.search(r"void otaDirectUploadCallback\(\)\s*\{", text)
    check(m is not None, "定义了 otaDirectUploadCallback()")
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
        for stage in ("UPLOAD_FILE_START", "UPLOAD_FILE_WRITE", "UPLOAD_FILE_END",
                      "UPLOAD_FILE_ABORTED"):
            check(stage in body, f"直传回调处理 {stage}")
        check("Update.write" in body, "直传回调把数据交给 Update 写入分区")
        check("sPhase" in body, "直传回调记录上传阶段（便于定位卡在哪一步）")

    # ---- 3. 前端镜像头自检 ----
    check("checkFwHeader" in text, "前端上传前做镜像头自检")
    check("0xABCD5432" in text, "自检校验 esp_app_desc_t 魔数 0xABCD5432")
    check("0xE9" in text, "自检校验镜像首字节 0xE9")
    check("readAsArrayBuffer" in text, "自检用 FileReader 读文件头")

    # ---- 4. 失败必须有可见文案 ----
    seg = text[text.find("function startFwUpload"):]
    seg = seg[:seg.find("\n// 统一事件委托")]
    check("xhr.onerror" in seg, "上传中断有 onerror 处理")
    check("写入失败" in seg, "写入失败有页面提示")
    check("xhr.upload.onprogress" in seg, "上传有进度反馈")

    # ---- 5/6. 推送不再「入队即成功」，结果单独查询 ----
    mp = re.search(r'server\.on\("/api/v1/watch/push",\s*HTTP_POST.*?\n  \}\);', text, re.S)
    check(mp is not None, "存在 /api/v1/watch/push")
    if mp:
        body = mp.group(0)
        check("queued" in body, "推送接口只报告是否入队")
        check("sendEncryptedWatchPb" not in body, "推送接口不在 HTTP 线程里直接发蓝牙帧")
    check('"/api/v1/watch/push/result"' in text, "存在 /api/v1/watch/push/result 结果查询")
    check("gPushTaskState" in text, "推送结果用 gPushTaskState 记录")

    # ---- 7. 投递函数两条路径都写结果 ----
    mf = re.search(r"bool flushPendingWatchText\(.*?\n\}", text, re.S)
    check(mf is not None, "存在 flushPendingWatchText()")
    if mf:
        body = mf.group(0)
        check("pushWatchSuccess" in body, "投递成功写入结果")
        check("pushWatchFail" in body, "投递失败写入原因")
        check("gPendingWatchTextReady = true" in body, "投递失败保留在队列里重试")

    print()
    for ok, msg in checks:
        print(("[OK] " if ok else "[FAIL] ") + msg)
    print()
    if fails:
        print(f"[FAIL] {len(fails)} 项未通过：")
        for f in fails:
            print("  - " + f)
        print("\n[ota-push] 检查未通过")
        return 1
    print(f"全部通过（{len(checks)} 项）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
