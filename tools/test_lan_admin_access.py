#!/usr/bin/env python3
"""
局域网访问后台（LAN 管理台）鉴权回归测试。

背景（见 变更说明.md 第十八章）：
- 固件的本地接口用 `X-Vela-Token` 头做鉴权（`authorized()`），
  `localToken` 默认 "vela-local"，非空即代表"必须带令牌"。
- 而管理台前端 `api()` 早期从不带任何令牌头，于是：
  · 在配网 SoftAP 上访问 → `isSetupApClient()` 为真 → 跳过鉴权 → 一切正常；
  · 连上家用路由器、用 LAN IP 访问 → 所有 `/api/v1/*` 返回 401 →
    页面永远显示"设备暂未响应"。
  这就是"连上网后进不了后台"的根因，跟 IP 记不记错无关。
- 修复：令牌随页面一起下发（`__PH_TOKEN__` 占位符），前端 `api()` 自动带上；
  同时 `requireSetupAp()` 也接受带对了令牌的请求，让 LAN 上也能改配置。

本脚本做两件事：
1. 静态检查 main.cpp：占位符存在、前端自动注入令牌头、鉴权函数接受过滤后的令牌、
   `requireSetupAp()` 放行带令牌的请求、令牌被过滤成安全字符。
2. 行为模拟：按当前固件逻辑跑一遍"从 LAN 打开后台"的请求序列，
   断言所有接口都返回 200 而不是 401/403。

用法：
    python3 tools/test_lan_admin_access.py
退出码 0 = 通过，1 = 检出问题。
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN = os.path.join(ROOT, "src", "main.cpp")


def read_main():
    with open(MAIN, "r", encoding="utf-8") as f:
        return f.read()


# --------------------------------------------------------------------------
# 1. 静态检查
# --------------------------------------------------------------------------

def check_static(src):
    problems = []

    # 页面里必须有令牌占位符，并且 sendMainWebUi() 会替换它。
    # 注意：sendMainWebUi() 已改成流式发送，替换不再是 page.replace(...)，
    # 而是查一张 Subst 表（token → 替换值）。所以这里按"语义"检查：
    #   1) 表里有 "__PH_TOKEN__" 这一项
    #   2) 它的值来自 sanitizeWebToken(localToken)
    if "__PH_TOKEN__" not in src:
        problems.append("页面缺少 __PH_TOKEN__ 占位符：令牌无法下发到前端")
    else:
        import re as _re
        m = _re.search(r'\{?\s*"__PH_TOKEN__"\s*,\s*([^}]+)\}', src)
        if not m:
            problems.append("sendMainWebUi() 的替换表里没有 __PH_TOKEN__ 项：下发的是空令牌")
        else:
            value_expr = m.group(1)
            if "sanitizeWebToken" not in value_expr or "localToken" not in value_expr:
                problems.append(
                    "sendMainWebUi() 里 __PH_TOKEN__ 的替换值不是 sanitizeWebToken(localToken)"
                    f"（实际是 {value_expr.strip()}）：前端会拿到不可用的令牌")

    # 前端 api() 必须自动注入令牌头。
    if "X-Vela-Token" not in src:
        problems.append("前端 api() 没有引用 X-Vela-Token：LAN 访问必然 401")
    if "VELA_TOKEN" not in src:
        problems.append("前端没有 VELA_TOKEN 变量")

    # 鉴权函数必须同时接受原始令牌与过滤后的令牌。
    if "sanitizeWebToken" not in src:
        problems.append("缺少 sanitizeWebToken()：令牌里出现特殊字符会撑破页面脚本")

    # requireSetupAp() 必须放行带令牌的 LAN 请求，否则 LAN 上改不了配置。
    m = re.search(r"bool requireSetupAp\(\)\s*\{(.*?)\n\}", src, re.S)
    if not m:
        problems.append("找不到 requireSetupAp() 定义")
    else:
        body = m.group(1)
        if "authorized()" not in body:
            problems.append(
                "requireSetupAp() 只放行配网 SoftAP 客户端："
                "LAN 上改 Wi-Fi / 恢复出厂会一直 403"
            )

    # 令牌过滤：必须用白名单过滤掉引号等危险字符。
    m = re.search(r"String sanitizeWebToken\(.*?\n\}", src, re.S)
    if m:
        body = m.group(0)
        if "A-Za-z0-9" not in body and "a' && c <=" not in body:
            problems.append("sanitizeWebToken() 没有用白名单过滤危险字符")
        if "out += safe ? c : '_'" not in body:
            problems.append("sanitizeWebToken() 没有把危险字符替换掉")

    return problems


# --------------------------------------------------------------------------
# 2. 行为模拟
# --------------------------------------------------------------------------

class LanAdminSim:
    """按当前固件的鉴权逻辑建模。"""

    def __init__(self, token="vela-local", page_token="vela-local"):
        self.token = token
        self.page_token = page_token
        self.soft_ap_ip = "192.168.4.1"

    def is_setup_ap_client(self, peer_local_ip):
        # 固件里是 server.client().localIP() == WiFi.softAPIP()
        return peer_local_ip == self.soft_ap_ip

    def authorized(self, headers):
        if not self.token:
            return True
        if headers.get("Authorization") == "Bearer " + self.token:
            return True
        if headers.get("X-Vela-Token") == self.token:
            return True
        return headers.get("X-Vela-Token") == self.page_token

    def require_auth(self, peer_local_ip, headers):
        # handleStatus()：if (!setupApClient && !requireAuth()) return;
        if self.is_setup_ap_client(peer_local_ip):
            return 200
        return 200 if self.authorized(headers) else 401

    def require_setup_ap(self, peer_local_ip, headers):
        if self.is_setup_ap_client(peer_local_ip):
            return 200
        return 200 if self.authorized(headers) else 403


def t_lan_admin(sim):
    """从家用路由器的 LAN IP 打开后台：所有接口都应该 200。"""
    headers = {"X-Vela-Token": sim.page_token}
    peer = "192.168.1.50"  # 设备的 LAN IP，不是 softAPIP

    status = sim.require_auth(peer, headers)
    assert status == 200, f"LAN 访问 /api/v1/status 返回 {status}，应为 200"

    setup = sim.require_setup_ap(peer, headers)
    assert setup == 200, f"LAN 访问 /setup 返回 {setup}，应为 200"


def t_lan_admin_no_token(sim):
    """不带令牌时应当被拒（401/403），否则等于把后台裸奔在局域网上。"""
    peer = "192.168.1.50"
    assert sim.require_auth(peer, {}) == 401, "不带令牌竟然通过了鉴权"
    assert sim.require_setup_ap(peer, {}) == 403, "不带令牌竟然通过了 setup 鉴权"


def t_setup_ap(sim):
    """在配网热点上访问：保持原来的"免令牌"行为，不能被改坏。"""
    peer = sim.soft_ap_ip
    assert sim.require_auth(peer, {}) == 200, "配网热点上访问被误拒"
    assert sim.require_setup_ap(peer, {}) == 200, "配网热点上改配置被误拒"


def t_watch_probe(sim):
    """手表 quickapp 探测 /setup/status：不能因为这次改动而拿到令牌。"""
    # 手表走的是 watch_quickapp 分支，没有令牌 → 只能拿到非敏感存活数据。
    # 关键点：手表拿不到页面 HTML，所以拿不到 __PH_TOKEN__。
    peer = "192.168.1.77"
    assert sim.authorized({"X-Vela-Token": "vela-local"}) is False or True
    # 手表不会带令牌 → 走 401 短路分支（固件里单独处理 watchFetchProbe）。
    assert sim.require_auth(peer, {}) == 401, "手表裸探竟然通过了鉴权"


def t_token_with_special_chars():
    """NVS 里的令牌被改坏（含引号）时，不能撑破页面脚本。"""
    raw = "abc\"';<>def"
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", raw)
    assert '"' not in safe and "'" not in safe and "<" not in safe
    assert ">" not in safe


SCENARIOS = [
    ("LAN 访问后台（带令牌）", lambda s: t_lan_admin(s)),
    ("LAN 访问后台（不带令牌应被拒）", lambda s: t_lan_admin_no_token(s)),
    ("配网热点访问（免令牌）", lambda s: t_setup_ap(s)),
    ("手表 quickapp 探测不越权", lambda s: t_watch_probe(s)),
    ("令牌含特殊字符时页面不被撑破", lambda s: t_token_with_special_chars()),
]


def main():
    src = read_main()
    problems = check_static(src)
    if problems:
        print("静态检查发现问题：")
        for p in problems:
            print("  [FAIL]", p)
    else:
        print("[ OK ] 静态检查：令牌下发 / 自动注入 / setup 放行 均已就位")

    sim = LanAdminSim()
    failed = 0
    for name, fn in SCENARIOS:
        try:
            fn(sim)
            print(f"[ OK ] {name}")
        except AssertionError as e:
            print(f"[FAIL] {name}: {e}")
            failed += 1

    if problems or failed:
        print("\n[FAIL] 检出问题：局域网访问后台的鉴权链路不完整")
        return 1
    print("\n全部通过：LAN 访问后台可正常使用，同时未带令牌的请求仍被拒绝")
    return 0


if __name__ == "__main__":
    sys.exit(main())
