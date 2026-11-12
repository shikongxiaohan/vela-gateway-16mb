#!/usr/bin/env python3
"""检查「固件升级」与「向手表推一条消息」两个功能不会假装成功。

背景（两个真实踩过的坑）：
  1. 网页升级出现过「页面说刷写完成，设备重启后版本没变」。原因分两层：
     路由注册漏掉上传回调时 multipart 数据被静默丢弃；页面在传输结束后立刻
     显示完成，而设备侧根本没写进去。现在的约定是：镜像头不合格在前端就拦住，
     中断要报出落在第几个百分点，设备端把上传阶段记下来备查。
  2. 推送接口以前只要入队就回 ok=true，页面弹「已加入队列」，真正发没发出去
     只有会话线程知道。现在接口只负责入队，结果由 /api/v1/watch/push/result
     查询。

页面结构在 v0.0.0.31 调整过：系统页的直写升级入口已删除，网页升级统一走
「设置 → 固件升级 → 进入空中升级」，刷写页面是 kOtaWebUi（POST /ota/upload2）。
因此前端的镜像头校验、进度、中断提示要在这份页面里检查。

检查项：
  1. /ota/upload2 与 /api/v1/ota/upload 都注册了上传回调
  2. 两个回调覆盖 START / WRITE / END / ABORTED
  3. 升级页刷写前读镜像头校验 0xE9 + 0xABCD5432
  4. 升级页的中断 / 失败 / 进度都有可见文案
  5. 主页面不再有第二条未经校验的固件上传路径
  6. 主页面「重启设备」与升级卡片分开，不随升级入口一起失效
  7. /api/v1/watch/push 不再返回「入队即成功」，结果单独查询
  8. 投递函数在成功与失败两条路径上都写结果
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


def balanced_body(text: str, header_pattern: str):
    """从 header_pattern 匹配到的 '{' 起，按花括号配对取出函数体。"""
    m = re.search(header_pattern, text)
    if not m:
        return None
    start = text.index("{", m.end() - 1)
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def route_callbacks(text: str):
    """返回 {路由: 上传回调名}。"""
    found = {}
    for m in re.finditer(
        r'server\.on\(\s*"([^"]+)"\s*,\s*HTTP_POST\s*,',
        text,
    ):
        tail = text[m.end():m.end() + 20000]
        cb = re.search(r'\}\s*,\s*([A-Za-z_]\w*)\s*\)\s*;', tail)
        if cb:
            found[m.group(1)] = cb.group(1)
    return found


def html_block(text: str, name: str):
    """取 C++ 里的 HTML 原始字符串，例如 kOtaWebUi = R"HTML(...)HTML"。"""
    m = re.search(rf'\b{name}\[\]\s*\w*\s*=\s*R"HTML', text)
    if not m:
        return ""
    start = m.end()
    # 主页面用 )HTML"; 收尾，升级页用 )HTMLOTA";。按「)HTML + 标签 + ";」找：
    # 标签允许是空或一串大写字母，这样两者都能取到，又不会把主页面截到下一个页面里。
    close = re.compile(r'\)HTML[A-Z]*";')
    mc = close.search(text, start)
    return text[start:mc.start()] if mc else ""


def main() -> int:
    if not SRC.exists():
        print(f"[FAIL] 找不到 {SRC}")
        return 1
    text = SRC.read_text("utf-8", errors="replace")

    # ---- 1. 两个升级路由都要带上传回调 ----
    cbs = route_callbacks(text)
    check(cbs.get("/ota/upload2") == "otaUploadCallback",
          f"/ota/upload2 注册了上传回调 otaUploadCallback（实际 {cbs.get('/ota/upload2')}）")
    check(cbs.get("/api/v1/ota/upload") == "otaDirectUploadCallback",
          "/api/v1/ota/upload 注册了上传回调 otaDirectUploadCallback"
          f"（实际 {cbs.get('/api/v1/ota/upload')}）")

    # ---- 2. 回调阶段 ----
    for fn in ("otaDirectUploadCallback", "otaUploadCallback"):
        body = balanced_body(text, rf"void {fn}\(\)\s*\{{")
        check(body is not None, f"定义了 {fn}()")
        if not body:
            continue
        for stage in ("UPLOAD_FILE_START", "UPLOAD_FILE_WRITE", "UPLOAD_FILE_END",
                      "UPLOAD_FILE_ABORTED"):
            check(stage in body, f"{fn} 处理 {stage}")
        check("Update.write" in body, f"{fn} 把数据交给 Update 写入分区")
    dbody = balanced_body(text, r"void otaDirectUploadCallback\(\)\s*\{")
    if dbody:
        check("otadirect::sPhase" in dbody, "直传回调记录上传阶段")

    # ---- 3/4. 升级页（kOtaWebUi）的镜像头自检与提示 ----
    ota_ui = html_block(text, "kOtaWebUi")
    check(bool(ota_ui), "取到升级页 kOtaWebUi")
    if ota_ui:
        check("/ota/upload2" in ota_ui, "升级页调用 /ota/upload2")
        check("0xE9" in ota_ui, "升级页自检镜像首字节 0xE9")
        check("0xABCD5432" in ota_ui, "升级页自检 esp_app_desc_t 魔数 0xABCD5432")
        check("upload.onprogress" in ota_ui, "升级页有上传进度")
        check("xhr.onerror" in ota_ui, "升级页有中断处理")
        check("设备状态未改变" in ota_ui, "中断时说明设备未被改动")
        check("responseText" in ota_ui, "升级页读取设备返回的成败结果")

    # ---- 5. 主页面不再有第二条未经校验的上传路径 ----
    main_ui = html_block(text, "kWebUi")
    check(bool(main_ui), "取到主页面 kWebUi")
    if main_ui:
        check('id="fwFile"' not in main_ui, "主页面不再直接挂载固件上传控件")
        check("uploadFw" not in main_ui, "主页面不再包含直传上传脚本")
        check("'/api/v1/ota/upload'" not in main_ui
              and '"/api/v1/ota/upload"' not in main_ui,
              "主页面不再直接调用 /api/v1/ota/upload")

    # ---- 6. 重启入口与升级入口分开 ----
    if main_ui:
        reboot = re.search(r"<h2>设备动作</h2>(.*?)</div>", main_ui, re.S)
        check(reboot is not None and 'data-act="reboot"' in reboot.group(1),
              "「重启设备」在独立卡片里，不随升级卡片一起消失")
        upgrade = re.search(r"<h2>固件升级</h2>(.*?)</div>\s*</div>", main_ui, re.S)
        check(upgrade is not None and 'data-arg="6"' in upgrade.group(1),
              "「设置」页保留进入空中升级的入口")

    # ---- 7. 推送不再「入队即成功」 ----
    mp = re.search(r'server\.on\("/api/v1/watch/push",\s*HTTP_POST.*?\n  \}\);', text, re.S)
    check(mp is not None, "存在 /api/v1/watch/push")
    if mp:
        body = mp.group(0)
        check("queued" in body, "推送接口只报告是否入队")
        check("sendEncryptedWatchPb" not in body, "推送接口不在 HTTP 线程里直接发蓝牙帧")
    check('"/api/v1/watch/push/result"' in text, "存在 /api/v1/watch/push/result 结果查询")
    check("gPushTaskState" in text, "推送结果用 gPushTaskState 记录")

    # ---- 8. 投递函数两条路径都写结果 ----
    fbody = balanced_body(text, r"bool flushPendingWatchText\([^)]*\)\s*\{")
    check(fbody is not None, "存在 flushPendingWatchText()")
    if fbody:
        check("pushWatchSuccess" in fbody, "投递成功写入结果")
        check("pushWatchFail" in fbody, "投递失败写入原因")
        check("gPendingWatchTextReady = true" in fbody, "投递失败保留在队列里重试")

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
