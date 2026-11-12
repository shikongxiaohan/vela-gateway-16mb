#!/usr/bin/env python3
"""
恢复出厂 / 自动配网降级 状态机回归测试。

背景（见 变更说明.md 第十二~十五章）：
- 主动恢复出厂（FACT）：写 arm 标志 → 清业务 NVS → 重写标志 → ESP.restart()。
  arm 标志存放在独立命名空间 "vela-fac"，factoryClearNvs() 只清 "vela"，
  所以标志能活过重启。早期实现里 setup() 看到标志就再次调用
  factoryResetApply()，于是"看到标志 → 再清一遍 → 再重启"形成无限复位环。
  三个主动入口（BOOT 长按 / 网页恢复出厂）全部中招。
- 自动配网降级（SEPU）：连不上 Wi-Fi 时**只写标志后重启进配网，
  不动任何用户配置**。开机看到 SEPU 标志只进配网、不清配置，随后解绑。

本脚本把这两条状态机抽出来跑一遍，用"复位次数 / 是否进入配网 /
NVS 是否被清"三个指标卡住回归：不修复的话复位次数会发散，或者
自动降级会误清用户配置。

用法：
    python3 tools/test_factory_reset.py
退出码 0 = 通过，1 = 检出问题。
"""

import sys

FACT_MAGIC = 0x46414354  # "FACT": 主动恢复出厂，清空全部用户配置
SEPU_MAGIC = 0x53455055  # "SEPU": 自动降级，只进配网，不清配置


class FactoryResetSim:
    """按当前 main.cpp 的逻辑建模：arm 标志在 "vela-fac"，业务键在 "vela"。"""

    def __init__(self, fixed: bool):
        self.fixed = fixed
        self.nvs_vela = {"ssid": "HomeWiFi", "watch_mac": "AA:BB:CC:DD:EE:FF"}
        self.arm_magic = 0
        self.reboots = 0
        self.in_setup_mode = False
        self.keep_config = False

    # ---- NVS 层 ----
    def _write_arm(self, magic):
        self.arm_magic = magic

    def _clear_vela(self):
        self.nvs_vela = {}

    def _disarm(self):
        self.arm_magic = 0

    def _pending(self):
        return self.arm_magic in (FACT_MAGIC, SEPU_MAGIC)

    # ---- 固件层 ----
    def factory_reset_apply(self, reason):
        """主动恢复出厂：写 FACT 标志 → 清业务 NVS → 重写标志 → 重启。"""
        self._write_arm(FACT_MAGIC)
        self._clear_vela()
        self._write_arm(FACT_MAGIC)
        self.reboots += 1
        return "reboot"

    def auto_setup_fallback_apply(self, reason):
        """自动降级：只写 SEPU 标志 → 重启，不动任何用户配置。"""
        self._write_arm(SEPU_MAGIC)
        self.reboots += 1
        return "reboot"

    def boot(self):
        """模拟一次上电，跑 setup() 开头的标志前置处理。"""
        if self._pending():
            magic = self.arm_magic
            if self.fixed:
                # FACT → factoryResetCompleteOnBoot(): 补清空 → 解绑 → 不重启
                # SEPU → autoSetupCompleteOnBoot(): 不清配置 → 解绑 → 不重启
                if magic == FACT_MAGIC:
                    self._clear_vela()
                elif magic == SEPU_MAGIC:
                    self.keep_config = True
                self._disarm()
            else:
                # 旧实现：看到 FACT 标志再次调用 factoryResetApply() → 再重启
                self.factory_reset_apply("boot_pending_flag")
                return False
        # loadConfig 之后的 needSetup 判定
        need_setup = (
            self.nvs_vela.get("ssid", "") == ""
            or len(self.nvs_vela.get("watch_mac", "")) != 17
            or self.keep_config            # SEPU 强制进配网
        )
        if need_setup:
            self.in_setup_mode = True
            if self._pending():
                self._disarm()
        return True

    def run(self, trigger):
        self.reboots = 0
        self.in_setup_mode = False
        self.keep_config = False
        trigger(self)
        for _ in range(8):          # 最多模拟 8 次上电
            if not self.boot():
                continue
            break
        return {
            "reboots": self.reboots,
            "in_setup": self.in_setup_mode,
            "nvs": dict(self.nvs_vela),
            "arm": self.arm_magic,
            "keep_config": self.keep_config,
        }


def t_long_press(s):
    s.factory_reset_apply("boot_long_press")


def t_http_api(s):
    s.factory_reset_apply("http_api")


def t_auto_fallback(s):
    s.auto_setup_fallback_apply("auto_wifi_failed")


SCENARIOS = [
    ("BOOT 长按 10 秒", t_long_press),
    ("网页恢复出厂", t_http_api),
    ("自动配网降级（连不上 Wi-Fi）", t_auto_fallback),
]


def check(name, r, expect_clear):
    problems = []
    if r["reboots"] > 2:
        problems.append(f"复位 {r['reboots']} 次（疑似无限复位环）")
    if not r["in_setup"]:
        problems.append("没有进入配网模式")
    if expect_clear:
        if r["nvs"]:
            problems.append(f"业务 NVS 未清空：残留 {r['nvs']}")
    else:
        if not r["nvs"]:
            problems.append("自动降级误清了用户配置（应全部保留）")
    if r["arm"] != 0:
        problems.append("arm 标志未解绑（下次开机还会再处理一遍）")
    return problems


def main():
    failures = []

    print("=" * 64)
    print("恢复出厂 / 自动配网降级 状态机回归测试")
    print("=" * 64)

    for name, trigger in SCENARIOS:
        sim = FactoryResetSim(fixed=True)
        r = sim.run(trigger)
        expect_clear = (name != "自动配网降级（连不上 Wi-Fi）")
        problems = check(name, r, expect_clear)

        if problems:
            failures.append((name, problems))
            print(f"[FAIL] {name}")
            for p in problems:
                print(f"         - {p}")
        else:
            nvs_state = "NVS 已清空" if expect_clear else "NVS 已保留（配置未清）"
            print(f"[ OK ] {name}: 复位 {r['reboots']} 次 → 进配网 → {nvs_state} → arm 已解绑")

    print("-" * 64)
    if failures:
        print(f"[FAIL] 检出 {len(failures)} 个问题")
        return 1
    print("全部通过：主动恢复出厂会清配置、自动降级不清配置，且都不会陷入无限复位环")
    return 0


if __name__ == "__main__":
    sys.exit(main())
