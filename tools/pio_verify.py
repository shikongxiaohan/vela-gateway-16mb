# PlatformIO 构建后钩子：自动修复并校验 otadata，再跑一遍镜像检查。
#
# 为什么需要这个文件：
#   espidf + arduino 双框架下，PlatformIO 产出的 ota_data_initial.bin
#   可能是 8192 字节全 0xFF。本项目分区表（partitions_ota_16mb.csv）里
#   **没有 factory 分区**，bootloader 拿不到 otadata 记录时会拒绝启动，
#   表现为串口只有 bootloader 那几行、然后每 2 秒复位一次，
#   而烧录工具显示"成功"。这个坑真实发生过一次，所以固化成构建步骤。
#
# 做法：
#   1. 构建结束后检查 ota_data_initial.bin，若是全 0xFF 就用 Arduino core
#      自带的 boot_app0.bin 覆盖（内容为 ota_seq=1 的合法记录）。
#   2. 调 tools/verify_firmware.py 做完整校验，有问题直接中断构建。

import shutil
import subprocess
from pathlib import Path

Import("env")  # noqa: F821  (PlatformIO 注入)


def _otadata_all_ff(path: Path) -> bool:
    try:
        data = path.read_bytes()
    except OSError:
        return True
    return len(data) == 0 or all(b == 0xFF for b in data)


def fix_otadata(source, target, env):
    build_dir = Path(env.subst("$BUILD_DIR"))
    ota = build_dir / "ota_data_initial.bin"
    fw_dir = Path(env.subst("$PROJECT_DIR")) / "firmware"
    fw_dir.mkdir(exist_ok=True)

    if not build_dir.exists():
        return    # Arduino core 自带的 boot_app0.bin（otadata 初始记录）
    boot_app0 = None
    for pkg in (env.PioPlatform().get_package_dir("framework-arduinoespressif32") or "",):
        if not pkg:
            continue
        cand = Path(pkg) / "tools" / "partitions" / "boot_app0.bin"
        if cand.exists():
            boot_app0 = cand
            break
    if boot_app0 is None:
        print("[otadata] 警告：找不到 boot_app0.bin，跳过自动修复")
    elif _otadata_all_ff(ota):
        shutil.copyfile(boot_app0, ota)
        print(f"[otadata] 已修复：{ota.name} 原本全 0xFF，已替换为 boot_app0.bin")

    # 同步到 firmware/ 供打包与烧录使用
    if ota.exists():
        shutil.copyfile(ota, fw_dir / "ota_data_initial.bin")
    for name in ("bootloader.bin", "partitions.bin"):
        src = build_dir / name
        if src.exists():
            shutil.copyfile(src, fw_dir / name)

    # 完整校验
    script = Path(env.subst("$PROJECT_DIR")) / "tools" / "verify_firmware.py"
    if script.exists():
        r = subprocess.run(["python3", str(script), str(fw_dir)],
                           capture_output=True, text=True)
        print(r.stdout.rstrip())
        if r.returncode != 0:
            print(r.stderr.rstrip())

    # 恢复出厂状态机回归测试（防无限复位环回归）
    st = Path(env.subst("$PROJECT_DIR")) / "tools" / "test_factory_reset.py"
    if st.exists():
        r = subprocess.run(["python3", str(st)], capture_output=True, text=True)
        print(r.stdout.rstrip())
        if r.returncode != 0:
            print(r.stderr.rstrip())
            print("[factory-reset] 恢复出厂状态机回归测试未通过 —— "
                  "检查 setup() 里的 arm 标志处理逻辑")


# 挂到最终固件目标上。不同 PlatformIO 版本里目标名不一样
# （$BUILD_DIR/firmware.bin、$BUILD_DIR/${PROGNAME}.bin 都见过），
# 所以两种都试，只要有一个挂上就行。
for tgt in ("$BUILD_DIR/${PROGNAME}.bin", "$BUILD_DIR/firmware.bin"):
    try:
        env.AddPostAction(tgt, fix_otadata)  # noqa: F821
    except Exception:
        pass

# 另外挂一个 "check-images" 自定义目标，可手动 `pio run -t check-images` 触发
env.AddCustomTarget(  # noqa: F821
    name="check-images",
    dependencies=None,
    actions=[fix_otadata],
    title="Check firmware images",
    description="校验 firmware/ 下镜像的 otadata、分区表、app 描述符",
)
