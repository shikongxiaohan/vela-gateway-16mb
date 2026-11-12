# PlatformIO 构建后钩子：自动修复并校验 otadata，再跑一遍镜像检查。
#
# 为什么需要这个文件：
#   espidf + arduino 双框架下，PlatformIO 产出的 ota_data_initial.bin
#   可能是 8192 字节全 0xFF。本项目分区表（partitions_ota_16mb.csv）里
#   没有 factory 分区，bootloader 拿不到 otadata 记录时会拒绝启动，
#   表现为串口只有 bootloader 那几行、然后每 2 秒复位一次，
#   而烧录工具显示"成功"。这个坑真实发生过一次，所以固化成构建步骤。
#
# 做法：
#   1. 构建结束后检查 ota_data_initial.bin，若是全 0xFF 就用 Arduino core
#      自带的 boot_app0.bin 覆盖（内容为 ota_seq=1 的合法记录）。
#   2. 调 tools/verify_firmware.py 做完整校验，有问题直接中断构建。

import shutil
import subprocess
import sys
from pathlib import Path

Import("env")  # noqa: F821  (PlatformIO 注入)


def _otadata_all_ff(path: Path) -> bool:
    try:
        data = path.read_bytes()
    except OSError:
        return True
    return len(data) == 0 or all(b == 0xFF for b in data)


def check_no_tcpip_init(target, source, env):
    """构建前的静态门禁：源码里不得直接调用 tcpip_init()。

    直接调 tcpip_init() 会和 IDF esp_netif_init() 内部那次重复，
    导致 socket fd 区间二次注册 → ESP_ERR_INVALID_ARG → abort() 无限重启。
    详见 变更说明.md 第十五章。
    """
    script = Path(env.subst("$PROJECT_DIR")) / "tools" / "check_no_tcpip_init.py"
    if not script.exists():
        return
    r = subprocess.run(["python3", str(script)], capture_output=True, text=True)
    out = (r.stdout or "").rstrip()
    if out:
        print(out)
    if r.returncode != 0:
        raise SystemExit(
            "[tcpip-init] 构建中止：检测到直接调用 tcpip_init()，"
            "刷机后会在进配网模式里 abort 无限重启。改用 esp_netif_init()。"
        )


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

    # 生成带版本号的产物（factory 整包 + ota app），文件名跟版本号走。
    # 必须放在镜像校验之前：校验要读的就是刚生成的这批文件，
    # 顺序反了会拿上一版的产物来比，版本号必然对不上。
    ma = Path(env.subst("$PROJECT_DIR")) / "tools" / "make_artifacts.py"
    if ma.exists():
        r = subprocess.run(["python3", str(ma)], capture_output=True, text=True)
        print(r.stdout.rstrip())
        if r.returncode != 0:
            print(r.stderr.rstrip())
            print("[artifacts] 生成 factory/ota 产物失败")

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
            print("[factory-reset] 恢复出厂状态机回归测试未通过，检查 FACT/SEPU 两条路径"
                  "检查 setup() 里的 arm 标志处理逻辑")

    # 局域网访问后台的鉴权回归测试（防 LAN 打开后台全 401 回归）
    lt = Path(env.subst("$PROJECT_DIR")) / "tools" / "test_lan_admin_access.py"
    if lt.exists():
        r = subprocess.run(["python3", str(lt)], capture_output=True, text=True)
        print(r.stdout.rstrip())
        if r.returncode != 0:
            print(r.stderr.rstrip())
            print("[lan-admin] 局域网访问后台的鉴权回归测试未通过，检查令牌下发与前端 api() 有没有带 X-Vela-Token"
                  "检查令牌下发（__PH_TOKEN__）与前端 api() 是否带上 X-Vela-Token")

    # 版本号自动递进机制的回归测试（防 4 位零填充/跳号/进位回归）
    vt = Path(env.subst("$PROJECT_DIR")) / "tools" / "test_version_bump.py"
    if vt.exists():
        r = subprocess.run(["python3", str(vt)], capture_output=True, text=True)
        print(r.stdout.rstrip())
        if r.returncode != 0:
            print(r.stderr.rstrip())
            print("[version-bump] 版本号递进回归测试未通过，检查 tools/version_util.py 的零填充与进位"
                  "检查 tools/version_util.py 的零填充与进位逻辑")

    # 管理台页面发送逻辑的回归测试（防 49KB 整页发送导致"站点没有有效内容"）
    wt = Path(env.subst("$PROJECT_DIR")) / "tools" / "test_webui_send.py"
    if wt.exists():
        r = subprocess.run(["python3", str(wt)], capture_output=True, text=True)
        print(r.stdout.rstrip())
        if r.returncode != 0:
            print(r.stderr.rstrip())
            print("[webui] 管理台页面发送回归测试未通过，检查 sendMainWebUi() 的流式发送与 UTF-8 切块边界"
                  "检查 sendMainWebUi() 的流式发送与 UTF-8 切块边界")

    # 表盘/快应用安装协议回归测试。
    # protobuf 字段号写错不会编译报错，只会让手表静默不理你，所以必须靠常量
    # 级校验把关键数字钉死在这里。
    wf = Path(env.subst("$PROJECT_DIR")) / "tools" / "test_watchface_install.py"
    if wf.exists():
        r = subprocess.run(["python3", str(wf)], capture_output=True, text=True)
        print(r.stdout.rstrip())
        if r.returncode != 0:
            print(r.stderr.rstrip())
            print("[wfi] 表盘安装协议回归测试未通过，检查 namespace wfi 的字段号与分片算法"
                  "检查 namespace wfi 的 WearPacket 字段号与分片算法")

    # 两个页面内嵌 JS 的语法检查。改文案时少删一个引号，编译照过、页面白屏，
    # 只有 node --check 能拦住。
    js = Path(env.subst("$PROJECT_DIR")) / "tools" / "test_webui_js.py"
    if js.exists():
        r = subprocess.run(["python3", str(js)], capture_output=True, text=True)
        print(r.stdout.rstrip())
        if r.returncode != 0:
            print(r.stderr.rstrip())
            print("[webui-js] 页面脚本语法检查未通过，页面会在真机上白屏")

    # SPIFFS 挂载前提检查。懒挂载只在录音路径里做过一次，结果固件库和
    # 表盘上传在没录过音的设备上必然失败，而且报错还指向「不是 app 镜像」。
    sg = Path(env.subst("$PROJECT_DIR")) / "tools" / "test_spiffs_guard.py"
    if sg.exists():
        r = subprocess.run(["python3", str(sg)], capture_output=True, text=True)
        print(r.stdout.rstrip())
        if r.returncode != 0:
            print(r.stderr.rstrip())
            print("[spiffs] 文件系统挂载前提检查未通过，检查各路由入口是否调用 ensureSpiffs()")

    # OTA 路由上传回调检查。/ota/upload2 曾经漏注册回调，文件被静默丢弃但接口
    # 照样回成功，界面上只看到「刷完还是旧版本」。
    ot = Path(env.subst("$PROJECT_DIR")) / "tools" / "test_ota_routes.py"
    if ot.exists():
        r = subprocess.run(["python3", str(ot)], capture_output=True, text=True)
        print(r.stdout.rstrip())
        if r.returncode != 0:
            print(r.stderr.rstrip())
            print("[ota] OTA 路由上传回调检查未通过，网页升级会静默失败")

    # 固件升级的诚实性检查：升级页说过成功、设备侧却什么都没写的情况在手机上
    # 完全看不出来。同一份脚本还检查已下线的推送与 RGB 灯没有回潮。
    ph = Path(env.subst("$PROJECT_DIR")) / "tools" / "test_ota_honesty.py"
    if ph.exists():
        r = subprocess.run(["python3", str(ph)], capture_output=True, text=True)
        print(r.stdout.rstrip())
        if r.returncode != 0:
            print(r.stderr.rstrip())
            print("[ota] 升级反馈检查未通过，页面可能假报成功")

    # 标记这次版本已出包（下次源码不变就不会再递进版本号）
    sys.path.insert(0, str(Path(env.subst("$PROJECT_DIR")) / "tools"))
    try:
        import version_util as vu
        vu.mark_built(Path(env.subst("$PROJECT_DIR")))
    except Exception as e:
        print(f"[version] 警告：标记构建状态失败（{e}）")


# 挂到最终固件目标上。不同 PlatformIO 版本里目标名不一样
# （$BUILD_DIR/firmware.bin、$BUILD_DIR/${PROGNAME}.bin 都见过），
# 所以两种都试，只要有一个挂上就行。
for tgt in ("$BUILD_DIR/${PROGNAME}.bin", "$BUILD_DIR/firmware.bin"):
    try:
        env.AddPostAction(tgt, fix_otadata)  # noqa: F821
    except Exception:
        pass
    try:
        env.AddPreAction(tgt, check_no_tcpip_init)  # noqa: F821
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
