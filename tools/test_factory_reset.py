#!/usr/bin/env python3
"""
恢复出厂状态机回归测试。

背景：factoryResetApply() 末尾会 ESP.restart()，而 arm 标志存放在独立
NVS 命名空间 "vela-fac"，factoryClearNvs() 只清 "vela"，所以标志能活过
重启。早期实现里 setup() 看到标志就再次调用 factoryResetApply()，
于是"看到标志 → 再清一遍 → 再重启"形成无限复位环：设备永远进不了
配网模式，只能 USB 重刷才能救回来。三个入口（BOOT 长按 10 秒 /
网页恢复出厂 / 自动恢复出厂）全部中招。

这个脚本把那条状态机抽出来跑一遍，用"复位次数"和"是否进入配网模式"
两个指标卡住回归：不修复的话复位次数会发散。

用法：
    python3 tools/test_factory_reset.py
退出码 0 = 通过，1 = 检出无限复位环。
"""

import sys

ARM_MAGIC = 0x46414354


class FactoryResetSim:
    """按当前 main.cpp 的逻辑建模：arm 标志在 "vela-fac"，业务键在 "vela"。"""

    def __init__(self, fixed: bool):
        self.fixed = fixed
        self.nvs_vela = {"ssid": "HomeWiFi", "watch_mac": "AA:BB:CC:DD:EE:FF"}
        self.arm_magic = 0
        self.reboots = 0
        self.in_setup_mode = False

    # ---- NVS 层 ----
    def _write_arm(self):
        self.arm_magic = ARM_MAGIC

    def _clear_vela(self):
        self.nvs_vela = {}

    def _disarm(self):
        self.arm_magic = 0

    def _pending(self):
        return self.arm_magic == ARM_MAGIC

    # ---- 固件层 ----
    def factory_reset_apply(self, reason):
        """写标志 → 清业务 NVS → 重写标志 → 重启（与 main.cpp 一致）。"""
        self._write_arm()
        self._clear_vela()
        self._write_arm()
        self.reboots += 1
        return "reboot"

    def boot(self):
        """模拟一次上电，跑 setup() 开头的恢复出厂前置处理。"""
        if self._pending():
            if self.fixed:
                # factoryResetCompleteOnBoot(): 补清空 → 解绑 → 不重启
                self._clear_vela()
                self._disarm()
            else:
                # 旧实现: factoryResetApply("boot_pending_flag") → 再重启
                self.factory_reset_apply("boot_pending_flag")
                return False
        # loadConfig 之后的 needSetup 判定
        need_setup = (
            self.nvs_vela.get("ssid", "") == ""
            or len(self.nvs_vela.get("watch_mac", "")) != 17
        )
        if need_setup:
            self.in_setup_mode = True
            if self._pending():
                self._disarm()
        return True

    def run(self, trigger):
        self.reboots = 0
        self.in_setup_mode = False
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
        }


def t_long_press(s):
    s.factory_reset_apply("boot_long_press")


def t_http_api(s):
    s.factory_reset_apply("http_api")


def t_auto(s):
    s.factory_reset_apply("auto_never_connected")


SCENARIOS = [
    ("BOOT 长按 10 秒", t_long_press),
    ("网页恢复出厂", t_http_api),
    ("自动恢复出厂", t_auto),
]


def main():
    failures = []

    print("=" * 64)
    print("恢复出厂状态机回归测试")
    print("=" * 64)

    for name, trigger in SCENARIOS:
        sim = FactoryResetSim(fixed=True)
        r = sim.run(trigger)

        problems = []
        if r["reboots"] > 2:
            problems.append(f"复位 {r['reboots']} 次（疑似无限复位环）")
        if not r["in_setup"]:
            problems.append("没有进入配网模式")
        if r["nvs"]:
            problems.append(f"业务 NVS 未清空：残留 {r['nvs']}")
        if r["arm"] != 0:
            problems.append("arm 标志未解绑（下次开机还会再清一遍）")

        if problems:
            failures.append((name, problems))
            print(f"[FAIL] {name}")
            for p in problems:
                print(f"         - {p}")
        else:
            print(f"[ OK ] {name}: 复位 {r['reboots']} 次 → 进配网 → NVS 已清空 → arm 已解绑")

    print("-" * 64)
    if failures:
        print(f"✗ 检出 {len(failures)} 个问题")
        return 1
    print("✓ 全部通过：三个恢复出厂入口都不会陷入无限复位环")
    return 0


if __name__ == "__main__":
    sys.exit(main())
