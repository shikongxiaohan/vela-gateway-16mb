# Vela Gateway — ESP32 手表上网网关（16MB Flash 版）

**v0.0.0.1 · tech-preview**

把 ESP32 变成手表 / 手环的 Wi-Fi 上网桥：蓝牙 SPP 连手表，Wi-Fi 连家里路由，
用 lwIP NAPT 把两者桥起来。本版面向 **16MB Flash** 板子
（ESP32-WROVER-E N16R8 / YD-ESP32-B），同时修掉了一批会导致"连不上 / 刷不进去 /
升级后变砖"的逻辑错误。早期 4MB 板子的构建配置仍保留在工程里，便于回退。

| 项 | 值 |
|----|----|
| 固件版本 | `v0.0.0.1` |
| 发布通道 | `tech-preview`（早期技术预览，协议可能随时变） |
| 占用 | RAM 22.5%（73,696 / 327,680 B）· Flash 25.0%（1,569,785 / 6,291,456 B） |
| 管理台 | `http://192.168.4.1`（AP 模式）或设备 IP（STA 模式） |

> **本仓库已带编译好的固件**，不用装 PlatformIO 也能刷，**乐鑫官方 Flash Download Tool 也能直接用**：
>
> | 文件 | 用途 |
> |------|------|
> | `firmware/vela-gateway-v0.0.0.1-esp32-16mb-factory.bin` | 整片刷写（地址 `0x0`），首次刷这个 |
> | `firmware/vela-gateway-v0.0.0.1-esp32-16mb-ota.bin` | 网页 OTA 升级用 |
> | `firmware/bootloader.bin` / `partitions.bin` / `ota_data_initial.bin` | 分步刷写用 |
>
> 详见 [`烧录说明-乐鑫工具.md`](烧录说明-乐鑫工具.md)。
> 实测大小 1.57MB（分区 6MB，占用 25%），已链接 lwIP NAPT（`ip_napt_enable`）
> 与 Bluedroid 蓝牙栈。

## 版本号规则

采用 **`主.次.构建.修订`** 四段式（Windows 文件版本风格），四段全部对外可见：

```
主版本   MAJOR      0
次版本   MINOR      0
构建     BUILD      0
修订     REVISION   1
──────────────────────
完整标识             v0.0.0.1
```

| 段 | 含义 | 什么时候动 | 当前 |
|----|------|------------|------|
| **主** MAJOR | 架构 / 协议不兼容变更（SPP 帧格式、配置项语义） | 手表侧要跟着改 | `0` |
| **次** MINOR | 向前兼容的新功能（新接口、新面板） | 加功能 | `0` |
| **构建** BUILD | 每次对外发布的源码构建 | 打一次发布包 +1 | `0` |
| **修订** REVISION | 同一构建上的缺陷修复 | 只修 bug +1，前三位不动 | `1` |

前三段都是 `0` 的含义很直白：**协议还没冻结**。这不代表"不能发布"——
`v0.0.0.1` 就是技术预览版的第一份修订。

和 semver 的区别：semver 用 `-test.4` 这种预发布标识挂在版本号尾巴上，
而四段式把构建和修订作为**正式段位**，任何工具（含 Windows 文件属性、OTA
差分、脚本排序）都能直接读懂，不用额外解析连字符。

升级路径举例：

| 场景 | 版本变化 |
|------|----------|
| 修个 bug | `v0.0.0.1` → `v0.0.0.2` |
| 又攒一批修复要发版 | `v0.0.0.2` → `v0.0.1.0`（构建 +1，修订归零） |
| 加了新面板 | `v0.0.1.0` → `v0.1.0.0`（次版本 +1，后面归零） |
| 手表协议改成不兼容的 | `v0.1.0.0` → `v1.0.0.0`（主版本 +1，彻底归零） |

* 网页右上角徽章显示 `v0.0.0.1`，通道标记为 `tech-preview`（黄色）
* 系统页「版本构成」一行拆开显示：`主 0 · 次 0 · 构建 0 · 修订 1`
* 设备页「主.次.构建.修订」显示纯数字 `0.0.0.1`
* 串口横幅会打印完整标识，便于按场确认刷的是哪一版

版本号定义在两处，改版本要一起动：

| 位置 | 作用 |
|------|------|
| `src/main.cpp` 顶部宏（`VELA_FW_VERSION_MAJOR` / `_MINOR` / `_BUILD` / `_REVISION`） | 网页徽章、状态接口、串口横幅 |
| 项目根 `version.txt`（内容 `v0.0.0.1`） | ESP-IDF 编译期把它写进镜像里的 **app 描述符**，镜像头里的版本才能被 esptool / OTA 工具读到 |

`version.txt` 是 IDF 的标准机制：根目录有它就自动读取其中的字符串作为
`PROJECT_VER`。改完这两处后必须 **clean 后全量重编译**，app 描述符才会更新
（增量编译会保留旧值）。

文件名规则：`vela-gateway-v<主>.<次>.<构建>.<修订>-<硬件>-<类型>.bin`
例：`vela-gateway-v0.0.0.1-esp32-16mb-ota.bin`

---

## 1. 从 4MB 到 16MB 到底改了什么

### 1.1 分区表

| 项目 | 4MB 版 `partitions_ota.csv` | 16MB 版 `partitions_ota_16mb.csv` |
|------|------------------------------|-------------------------------------|
| nvs | 0x9000 / 16KB | 0x9000 / 20KB |
| otadata | 0xD000 / 8KB | 0xE000 / 8KB |
| phy_init | 0xF000 / 4KB | 0x10000 / 4KB |
| ota_0 | 0x10000 / **1.9375MB** | 0x20000 / **6MB** |
| ota_1 | 0x200000 / **1.9375MB** | 0x620000 / **6MB** |
| spiffs | **不存在** | 0xC20000 / **3.875MB** |

两点关键差异：

1. **应用分区从 1.9375MB 变成 6MB。** 4MB 版的固件约 1.66–2.0MB，占用 81.7%，
   每次改一点代码就顶到天花板；现在余量约 3 倍，A/B 两个槽都能放完整镜像，
   OTA 回滚才真正可用。
2. **补上了 SPIFFS 分区。** 原 OTA 分区表里没有 `spiffs`，而代码里
   `SPIFFS.begin(true)` 在录音导出时会用到它；没有分区就只能静默失败。
   `huge_app.csv`（Arduino 单 app 表）本来有 0xE0000 的 spiffs，OTA 表却漏了，
   这是 4MB 版的一处配置不一致。

### 1.2 编译环境

```ini
[env:yd_esp32_16mb]
board = upesy_wroom                    ; 引脚定义与 ESP32-WROOM / WROVER 模块一致
framework = espidf, arduino            ; 必须用 IDF 框架，sdkconfig 才生效
platform = espressif32@6.1.0
platform_packages = platformio/framework-espidf @ 3.40404.0   ; ← 必须锁 IDF 4.4.4
board_build.partitions = partitions_ota_16mb.csv
board_upload.flash_size = 16MB
board_upload.maximum_size = 6291456    ; 单个 OTA 槽 6MB
```

> **为什么必须写 `platform_packages`**：`espressif32@6.1.0` 默认拉 ESP-IDF **5.0.1**，
> 但 Arduino core 2.0.7 的 `CMakeLists.txt` 里写着
> `set(max_supported_idf_version "4.4.99")`，版本不匹配会在 CMake 配置阶段直接
> `FATAL_ERROR`。`3.40404.0` 就是 IDF **v4.4.4**，属于该平台的 `optionalVersions`。

对应的 `sdkconfig.yd_esp32_16mb` 由 `sdkconfig.legacy_4mb` 生成，
只改了三处：

```
CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y
CONFIG_ESPTOOLPY_FLASHSIZE="16MB"
CONFIG_PARTITION_TABLE_CUSTOM=y
CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions_ota_16mb.csv"
```

蓝牙 / Wi-Fi / lwIP 的低内存参数（`CONFIG_L2_TO_L3_COPY`、`CONFIG_LWIP_IP_FORWARD`
等）原样保留，所以 16MB 版在内存行为上和 4MB 版一致，**不是**换了个更吃内存的配置。

---

## 2. 修掉的逻辑错误

按影响从大到小排列，详细代码位置见 `变更说明.md`。

### 2.1 自动重连把 Wi-Fi 和手表绑在同一个计时器上（严重）

`loop()` 里早期实现的写法：

```cpp
if (!wifiConnected && ... ) {
  WiFi.disconnect(); WiFi.mode(WIFI_STA); WiFi.begin(...);
  gLastConnectAttemptMs = now;          // ← 每 3 秒清零
}
if (... (now - gLastConnectAttemptMs) >= 3000 ...) {
  startWatchBridge(...);                // ← 永远轮不到
}
```

两个问题叠加：

* **Wi-Fi 永远连不上。** 每 3 秒就 `disconnect()` 再 `begin()`，而一次 STA 关联
  正常要 4–10 秒，等于每次都在握手中途把连接掐掉。
* **手表重连永远不触发。** Wi-Fi 分支每 3 秒把共享计时器清零，手表分支算出来的
  `attemptAge` 永远是 0。

修复：拆成 `gLastWifiAttemptMs` / `gLastWatchAttemptMs` 两个独立计时器；
Wi-Fi 用 25 秒窗口（正是代码里定义了却从未使用的 `kReconnectTimeoutMs`），
手表失败后 60 秒再试，避免高频重连把蓝牙控制器搞乱。

### 2.2 OTA 上传把 bootloader / 分区表误判成固件

```cpp
// 旧代码
s_otaFlashAddr = addrStr.isEmpty() ? 0x10000 : ...;
s_otaIsFirmware = (fnameLower.indexOf("firmware") >= 0 || s_otaFlashAddr == 0x10000);
```

`addr` 的缺省值恰好就是 `0x10000`，所以任何不传 `addr` 的文件（`bootloader.bin`、
`partitions.bin`）都被当成固件塞进 OTA 槽，既没写到目标地址，又把当前固件槽覆盖了。

修复：以"是否显式传了 `addr` 参数"为准，只有不传 `addr` 或文件名含 `firmware`
才走 OTA 分区；原始写入额外做 4KB 对齐、Flash 边界、分区表保护（`0x8000`
需要 `allow_partition=1`）三项校验。

### 2.3 OTA 回滚保护形同虚设

`setup()` 一进来就 `esp_ota_mark_app_valid_cancel_rollback()`——固件只要跑到第一行
就算"验证通过"，之后哪怕立刻崩溃，bootloader 也不会回滚。

修复：setup 里只置"待确认"标志，主循环稳定运行 **30 秒** 后再确认。真的起不来
（崩溃 / 看门狗）才会自动回滚。

### 2.4 升级完停留在 OTA 模式

OTA 模式只是一个纯热点网页，没有桥接功能。升级完成后原逻辑直接重启，设备仍停在
项目 6，用户看到热点在但手表上不了网，容易误判"刷坏了"。

修复：固件升级成功后写回 `project=1` 再重启（要留在 OTA 模式可加 `keep_ota=1`）。

### 2.5 `connectWifi()` 同步阻塞 60 秒

```cpp
uint32_t start=millis(); while(WiFi.status()!=WL_CONNECTED && millis()-start<60000){delay(250);}
```

这段在 SPP 桥接任务里执行，等待期间完全不读蓝牙，手表侧的发送窗口会被打满，
表现为"Wi-Fi 连上了，手表反而卡住/掉线"。

修复：改为非阻塞 `WiFi.begin()`，立即返回；后续由 `loop()` 的 25 秒重试接管。

### 2.6 网络热路径逐包打印，拖垮转发

`watchNetworkOutput`、`injectWatchNetworkPacket`、`drainWatchNetworkTx` 和主循环里
每一帧都 `Serial.printf`（部分还带 `hexBytes()` 堆分配）。这些回调运行在 lwIP
tcpip 线程，串口输出会阻塞数毫秒，直接造成 TCP 重传、吞吐下降。

修复：加编译开关 `VELA_NET_TRACE`（默认 0），逐帧日志全部关掉；关键状态变更
（DHCP、路由就绪、认证阶段）的日志保留。

### 2.7 其它

| 问题 | 修复 |
|------|------|
| `Serial.printf("...\\n")` 双反斜杠，日志里真的印出 `\n` | 改为 `\n`（2 处） |
| `/setup` 不填 AP 密码时会写死一个旧默认值，与实际热点密码 `12345678` 不一致 | 统一为 `12345678` |
| SPIFFS 挂载失败无任何提示，录音功能静默失效 | 打印 `SPIFFS_MOUNT_FAILED` + 分区是否存在 + 大小 |
| 状态接口看不到 Flash / 分区信息，无法确认刷的是不是 16MB 版 | `/api/v1/status` 增加 `flashSize`、`appPartitionSize`、`spiffsPartitionSize` 等 |
| 启动无版本横幅 | 启动打印芯片型号、Flash 大小、app 分区地址/大小、SPIFFS 大小 |
| 自动恢复出厂只要 10 分钟没连上就清空，停电/路由器重启也会触发 | 重写为带 5 道健康门槛的倒数窗口，见 §6 |
| 管理网页是桌面 720px 布局，手机上要横向滚动 | 重写为移动优先布局，见 §6 |
| 版本号硬编码在网页和状态接口两处，容易不一致 | 统一到 `main.cpp` 顶部一处宏，见"版本号规则" |

---

## 3. 编译

```bash
pip install platformio          # 或 pipx install platformio
cd vela-gateway-16mb

# 16MB 版本（默认）
pio run -e yd_esp32_16mb

# 输出
.pio/build/yd_esp32_16mb/bootloader.bin
.pio/build/yd_esp32_16mb/partitions.bin
.pio/build/yd_esp32_16mb/ota_data_initial.bin   ← 刷到 0xE000，内容应等同 boot_app0.bin
                                                （构建后由 tools/pio_verify.py 自动校正）
.pio/build/yd_esp32_16mb/firmware.bin           ← app 镜像，刷到 0x20000，也是网页 OTA 用的那个
```

⚠️ **不要相信 `flasher_args.json`**：本工程是 `espidf + arduino` 双框架，
PlatformIO 生成的 `flasher_args.json` 里写的是 `source.bin`（工程名 `project(source)`
带来的），但实际产物叫 `firmware.bin`，按 json 刷会报文件不存在。手工刷请按上表
文件名对照。

生成 0x0 整包镜像（和 `firmware/*-factory.bin` 等价）：

```bash
cd .pio/build/yd_esp32_16mb
python ~/.platformio/packages/tool-esptoolpy/esptool.py --chip esp32 merge_bin \
  -o merged_factory.bin --flash_mode dio --flash_freq 80m --flash_size 16MB \
  0x1000 bootloader.bin 0x8000 partitions.bin 0xe000 ota_data_initial.bin 0x20000 firmware.bin
```

需要还原 4MB 版本时：

```bash
pio run -e legacy_4mb
```

### 实测编译结果

本工程已在 **ESP-IDF v4.4.4 + Arduino core 2.0.7 + espressif32@6.1.0** 下完整编译通过：

```
RAM:   [==        ]  22.5% (used 73696 bytes from 327680 bytes)
Flash: [==        ]  25.0% (used 1569785 bytes from 6291456 bytes)
SUCCESS 00:01:09
```

* 静态 RAM 占 22.5%，剩下约 248KB 堆给蓝牙 + lwIP + SPP 缓冲；
* 固件 1.57MB，6MB 槽占用 25%，两个 OTA 槽都能容纳完整镜像；
* 裸机跑只剩网关这一条业务线后，RAM 比多项目共存时少 11,536 B（-13.5%）；
* 链接结果已确认包含 `ip_napt_enable`（NAPT 真正编进去了，不是只在 sdkconfig 里写着）。

---

## 附录 A：设备标识与改名指引

固件对外暴露的标识集中在这里，改品牌只需要动这几处：

| 标识 | 值 | 定义位置 |
|------|-----|---------|
| 配网热点 SSID | `Vela-Bridge` | `src/main.cpp` → `kApSsid` |
| 热点默认密码 | `12345678` | `setup()` / `/setup` 保存逻辑 |
| 蓝牙 SPP 本地名 | `Vela-Gateway` | `src/main.cpp` → `kBtLocalName` |
| mDNS 主机名 | `vela-gateway.local` | `setupMdns()` |
| 非敏感接口 token 头 | `X-Vela-Token` | `requireLocalToken()` |
| NVS 命名空间 | `vela`（业务）/ `vela-fac`（恢复出厂标志） | 各处 `prefs.begin()` |
| 固件版本 | `v0.0.0.1` | `VELA_FW_*` 宏 |

> **手表端协议常量不要改**：包名、manifest 格式标识、能力上报里的 buildTag
> 属于设备间通信契约（手表上的快应用按固定值匹配），固件只负责按约定生成和
> 校验。改动后的典型症状是「蓝牙连上了但一直没有数据」。这些值不参与品牌展示。
>
> **从早期构建升级**：NVS 命名空间和蓝牙设备名有调整，刷入后读不到旧配置，
> 设备会直接进配网模式，需要重新配一次网。

---

## 4. 首次刷写（必须用 USB）

> **重要：从 4MB 固件换成 16MB 分区表，必须整片擦除一次。**
> 旧的 `otadata` 在 0xD000，新表在 0xE000，不擦会读到垃圾数据，表现为
> 反复重启或启动到不存在的分区。

Windows（COM3 换成你的端口）：

```bat
flash_16mb.bat COM3
```

Linux / macOS：

```bash
./flash_16mb.sh /dev/ttyUSB0
```

脚本内部只有一条命令：

```bash
esptool.py --chip esp32 -p /dev/ttyUSB0 -b 921600 write_flash --erase-all -z \
  --flash_mode dio --flash_freq 80m --flash_size 16MB \
  0x0 firmware/vela-gateway-v0.0.0.1-esp32-16mb-factory.bin
```

`--erase-all` 先整片擦除（换分区表必须），`0x0` 是官方 Factory 镜像写法。
合并镜像内部已经排好：

| 偏移 | 内容 | 大小 |
|------|------|------|
| 0x1000 | `bootloader.bin` | 17 KB |
| 0x8000 | `partitions.bin` | 3 KB |
| 0xE000 | `ota_data_initial.bin`（otadata，**必须是含 ota_seq=1 记录的文件，不能是全 0xFF**） | 8 KB |
| 0x20000 | `firmware.bin` | 1.6 MB |

如果只想分步刷，注意 **固件偏移是 0x20000**（4MB 版是 0x10000），写错会启动到空白分区。
`firmware/` 下的四个分体 bin 与合并 bin 内容完全一致，可任选。

### 刷完怎么确认

串口（**921600** 波特）应看到：

```
=== Vela Gateway boot ===
BOOT chip=ESP32-D0WD-V3 rev=3 cores=2 flash=16777216 bytes (16.0 MB) heap=...
BOOT app_partition=ota_0 addr=0x00020000 size=6291456 next_ota=ota_1 spiffs=spiffs size=4063232
```

> 波特率定在 921600 是因为**网页版串口监视器最高只到这一档**（之前的 2000000
> 在那些工具里选不出来，日志全是乱码）。要用满速就加 `-DVELA_SERIAL_BAUD=2000000`
> 重新编译，同时把 `platformio.ini` 的 `monitor_speed` 一起改掉。

### 刷完只会在 2 秒内反复复位？

先跑一遍镜像校验：

```bash
python3 tools/verify_firmware.py firmware
# 或
pio run -e yd_esp32_16mb -t check-images
```

如果提示 **`otadata 全 0xFF（未初始化）`**，说明 `ota_data_initial.bin` 是空的。
本项目的分区表没有 factory 分区，bootloader 读不到 otadata 记录就会拒绝启动，
表现就是串口只有 bootloader 那几行、然后每 2 秒 `rst:0xc` 一次。

修复：

```bash
cp ~/.platformio/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin \
   firmware/ota_data_initial.bin
# 然后用它重新合并整包（见上面的 merge_bin 命令）
```

正常构建时这个修复由 `tools/pio_verify.py` 自动完成，`flash_16mb.sh` 也会
在烧录前校验，不通过直接中止。

* `flash=16777216` → Flash 识别为 16MB
* `app_partition_size=6291456` → 6MB 的 OTA 槽生效

如果只看到 `flash=4194304`，说明刷进去的还是 4MB 的 bootloader/分区表。

### 串口日志只有 bootloader 阶段、停在 `entry 0x400d0524`？

**那不是我们的固件在跑**（2026-11-09 实测，见 `变更说明.md` 第十六章）。

我们 bootloader.bin 的段表是 `0x3fff0030 / 0x40078000 / 0x40080400`，入口 `0x400805e4`。
如果日志里是 `load:0x3f400020 / 0x3ffbcf60 / 0x400d0020` + `entry 0x400d0524`，
说明这块板子上刷的是**别的项目的二级 bootloader**（另一套工具链构建的），
我们的 app 根本没被加载 —— 所以也不会有任何 app 输出。

先跑读回验证，30 秒出结论：

```bash
python3 tools/readback_check.py --port COM3
```

它会直接告诉你设备里的 bootloader 是不是我们这份（比对 entry），
并打印 bootloader / app 的完整段表可以和串口日志逐项对照。

### 刷完还是每 2.26 秒复位？（2026-11-09 实测）

**先读回验证，别猜**：

```bash
python3 tools/readback_check.py --port COM3          # Windows
python3 tools/readback_check.py --port /dev/ttyUSB0   # Linux/macOS
```

它把设备里的 bootloader / 分区表 / otadata / app 四个关键扇区读回来对照，
只读不写，30 秒出结果。四项全绿说明 flash 内容没问题，那就要往别的方向查
（波特率、接线、设备本身）；报出具体哪一项不对，就按提示处理。

诊断细节见 `变更说明.md` 第十四章。

### 恢复出厂之后一直重启，进不去配网？

**2026-11-09 已修复**（见 `变更说明.md` 第十三章）。旧版本有个致命缺陷：
恢复出厂的 arm 标志存在独立 NVS 命名空间里，重启后仍然有效，
而 `setup()` 看到标志就再执行一次恢复出厂——于是"清空 → 重启 → 再清空
→ 再重启"变成无限循环，设备永远起不了配网热点，只能用 USB 重刷才能救。

判断方法（看串口）：

```
FACTORY_RESET_BEGIN reason=boot_pending_flag     ← 这个 reason 反复出现 = 无限环
FACTORY_RESET_DONE rebooting_into_setup_mode
```

修复后只会出现一次 `reason=boot_pending_flag`，紧接着就打印
`SETUP_MODE_REASON factory_reset_completed` 和 `SETUP_MODE_ACTIVE`。

回归测试：

```bash
python3 tools/test_factory_reset.py
```

这个测试已经挂进构建钩子，每次 `pio run` 都会自动跑。

### 进配网热点时每 2.6 秒重启一次？（2026-11-09 实测）

**2026-11-09 已修复**（见 `变更说明.md` 第十五章）。旧版本有个致命缺陷：
`setup()` 里手写了一次 `tcpip_init()`，而 IDF 的 `esp_netif_init()` 内部还会再调一次，
`lwip_init()` 没有幂等保护 → socket 的 fd 区间被注册两次 → 第二次撞车
`ESP_ERR_INVALID_ARG (0x102)` → `ESP_ERROR_CHECK` → `abort()` → 无限重启。

判断方法（看串口）：

```
SETUP_MODE_REASON first_boot_no_config
ESP_ERROR_CHECK failed: esp_err_t 0x102 (ESP_ERR_INVALID_ARG)
file: "IDF/components/lwip/port/esp32/vfs_lwip.c" line 108
func: esp_vfs_lwip_sockets_register
```

修复后 `setup()` 里改用 `esp_netif_init()`（自带幂等保护）。

**怎么确认设备上跑的是新固件**：串口日志里会打印 app 镜像的 ELF 指纹，

```
ELF file SHA256: 716ad3ffd8e9232a     ← 新固件
ELF file SHA256: 7d1c587dc0562e5b     ← 修复前那一版
```

对照不上就是刷了旧镜像。

---

## 5. 后续升级（手机就能刷）

1. 手机连热点 `Vela-Bridge`（密码默认 `12345678`）
2. 浏览器打开 `http://192.168.4.1` → 系统页 → 「进入空中升级」
3. 升级页先看「刷写前自检」，确认 `Flash：16.00 MB ✅`
4. 点「选择固件并升级」，选 `firmware/*-ota.bin`
5. 进度条走完，设备自动重启并回到手表网关模式

OTA 模式下刷新固件走 A/B 分区：写入另一个槽，重启后新固件要稳定运行 30 秒
才会被标记为有效，否则 bootloader 自动回滚。

**手机端做了三层保护**，传错文件不会变砖：

| 层 | 时机 | 行为 |
|---|---|---|
| 前端 | 选完文件、还没上传 | 读文件头 36 字节，魔数不是 `0xABCD5432` 直接拒 |
| 首包 | ESP32 收到第一个数据块 | 同样校验，不过就置错并丢弃后续 |
| 提交 | 全部收完 | 有错时**不调用** `Update.end()`，不切分区 |

因此整包 `*-factory.bin`（第 0 字节是 0xFF，含二级引导）无法被网页误刷。

> 分区表和 bootloader 不能用网页 OTA 改（代码里已加保护：写 `0x8000` 必须显式
> `allow_partition=1`）。换分区布局请用 USB。详见 [`手机刷写说明.md`](手机刷写说明.md)。

---

## 6. 使用

1. 上电后 ESP32 开热点 `Vela-Bridge` / `12345678`
2. 手机连热点，浏览器打开 `http://192.168.4.1`
3. 选家里 Wi-Fi、填密码；填手表 MAC 和 AuthKey
4. 保存后自动重启，进入手表网关模式

### 管理台（本次重写）

旧页面是 720px 宽的桌面式单页，手机上要横向滚动、状态只有一行原始日志。
新页面按手机优先重做：

| 区块 | 内容 |
|------|------|
| 运行状态 | Wi-Fi / 手表 / 转发 / IP / 空闲内存 / 上下行包，3 秒自动刷新 |
| 分区占用 | 固件实际大小 vs 6MB 槽，带进度条和百分比 |
| 自动重置倒计时 | 只在真的要触发时出现，秒级倒数，可一键取消 |
| 家庭 Wi-Fi | 扫描列表点击填入，或手动填 SSID |
| 手表蓝牙 | 扫描 + 连接测试，MAC 自动填 |
| 热点与安全 | 当前热点名 / 改密码 |
| 运行模式 | 单个「进入空中升级」按钮（其余模式已剥离） |
| 恢复出厂 | 说明三种触发方式 + 带 `RESET` 二次确认的弹窗 |
| 设备信息 | 固件版本 / 通道 / 主.次.构建.修订 / 构建日期 / Flash / 分区 / SPIFFS |

七个标签（运行 / 性能 / 网络 / 手表 / 设备 / 工具 / 系统）横向可滑，
390px 宽下不会换行挤压。

实现要点：

* 版本号不写死两份：HTML 里放 `__PH_VERFULL__` / `__PH_VER__` / `__PH_HW__` 占位符，
  发送时用 `String::replace` 注入，改版本只改 `main.cpp` 顶部宏 + `version.txt`
* 所有按钮改成 `data-act` + 事件委托，避免内联 `onclick` 的引号嵌套问题
  （C++ 原始字符串 `R"HTML(...)HTML"` 遇到 `)"` 会提前截断，这是个真实踩过的坑）
* 状态卡用 `repeat(auto-fit, minmax(min(132px,100%),1fr))`，390px → 2 列、360px → 2 列，
  数字再长也不会把页面顶出屏幕（实测 `scrollWidth == innerWidth`）
* 页面总量约 55KB（管理台 47.5KB + 升级页 13.9KB），走 `PROGMEM` 不占 RAM；
  打开网页时用 `String + replace` 生成一份副本，峰值临时多占约 60KB 堆，
  页面关掉即释放，不影响转发路径

### 恢复出厂设置（本次重写）

旧逻辑是「10 分钟内没有连接就清空配置」。这在家里停电、路由器重启、出差拔电源时
都会误触发 —— 回家发现手表连不上、配置也没了。

新逻辑分三个入口，**只在确实配错的情况下才会自动清**：

| 触发 | 行为 |
|------|------|
| 长按 BOOT **3 秒**（松手时判定） | 只清 Wi-Fi 名称/密码，保留手表密钥 |
| 长按 BOOT **10 秒**（按住时执行） | 全部清空 → 重启 → 直接进配网热点 |
| 网页「恢复出厂设置」 | 需输入 `RESET` 确认，清空后重启 |
| 自动（A：配网后从没连上） | 10 分钟窗口，多半是密码填错 |
| 自动（B：曾经连过、长时间失联） | 30 分钟窗口 |

自动触发的**五道健康门槛**：

1. 开机后 **3 分钟**内不判定（给路由器重启/DHCP 留时间）
2. 至少重试失败 **5 次**才进入候选
3. 期间只要成功连上一次，倒计时**立即清零**
4. SoftAP 上还有浏览器连着 → 倒计时**冻结**（正在调试，不能清）
5. 长按超过 3 分钟视为下载模式/IO 故障，**放弃**该次长按

清空范围（`factoryClearNvs()` 里逐项列出，不是 `nvs_flash_erase` 全抹）：

* 清：ssid / wifi_pass / watch_mac / watch_auth / ap_pass / local_token / 运行模式
* 留：固件、分区表、SPIFFS 文件、eFuse、启动计数

串口可以完整追踪决策过程：

```
AUTO_RESET_WINDOW reason=never_connected budget_ms=600000
AUTO_RESET_PAUSED ap_client_present
AUTO_RESET_COUNTDOWN reason=never_connected remain_ms=240000
FACTORY_RESET_REASON auto_never_connected elapsed_ms=600120 failures=12
FACTORY_RESET_BEGIN reason=auto_never_connected
FACTORY_RESET_DONE rebooting_into_setup_mode
```

### 运行模式

只剩两个模式。早期版本的 BLE 广播 / Wi-Fi 抓包 / 手环上网 / 网络测速四个
项目已从固件里删除（见 `变更说明.md`），NVS 里的旧值在启动时自动归一化。

| 模式 | 功能 |
|------|------|
| 1 | 手表网关（蓝牙 SPP + Wi-Fi NAPT）—— 默认且唯一的业务模式 |
| 6 | 空中升级（只做固件刷写，不做业务转发） |

---

## 7. 关于 PSRAM

YD-ESP32-B 用的是 ESP32-WROVER-E，模组自带 PSRAM。本工程**默认不开 PSRAM**：

* 固件的关键缓冲（SPP 收发、lwIP 队列、蓝牙栈）都必须在内部 RAM，PSRAM 帮不上；
* 打开 PSRAM 会改变 `malloc` 行为，对这个时序敏感的 SPP 桥接没有收益，反而增加变量。

确实需要额外堆时：

```bash
pio run -e yd_esp32_16mb -t menuconfig
# Component config → ESP32-specific → Support for external, SPI-connected RAM
```

注意：如果板子实际没有 PSRAM，打开后会在启动阶段报错，请改回默认配置。

---

## 8. 已知限制

* 首次从 4MB 换到 16MB 必须 USB 整片擦除，OTA 无法完成分区布局迁移。
* 当前是 **技术预览版 `v0.0.0.1`**，自动恢复出厂的判定阈值（3 分钟宽限 / 10 分钟 / 30 分钟）
  是经验值，实际用下来如果觉得太激进或太保守，改 `kAutoReset*` 常量重新编译即可。
* 长按 BOOT 超过 180 秒视为「想进下载模式」，固件会主动放弃重置，避免误清配置。
* 语音 ASR 链路在早期版本里已被硬编码关闭（`ch3` 音频直接忽略），
  本次保留该行为，SPIFFS 分区只为后续恢复/导出预留。

---

## 9. 许可与第三方组件

本工程代码可自由用于个人设备。随固件一起分发的第三方组件各自遵循其原有许可：

| 组件 | 许可 |
|------|------|
| ESP-IDF | Apache-2.0 |
| Arduino-ESP32 core | LGPL-2.1 |
| ArduinoJson | MIT |
| U8g2 | BSD-2-Clause |
| esp32_opus / libopus | BSD-3-Clause |
| lwIP | BSD-3-Clause |

发布二进制时请一并保留上述组件的许可声明。

---

## 附录 B：管理台功能区与新增接口

首页从「一屏到底」改成 **6 个分区 + 顶部横向标签**，手机上不用再滚半米找重启按钮。

| 分区 | 内容 |
|------|------|
| **运行** | 运行状态、实时流量迷你图、① Wi-Fi / ② 手表 / ③ 热点配置、固件升级入口、恢复出厂、运行日志 |
| **性能** | 内存占用（空闲/历史最低/片段化/SPIFFS）、转发统计、硬件健康（芯片/主频/温度/运行时长/SDK） |
| **网络** | 家庭 Wi-Fi 现状、链路质量评分、时钟与校时（NTP） |
| **手表** | 桥接状态、SDP 通道、认证状态、重连、清上下文、**向手表推一条消息** |
| **工具** | LED 灯效（关闭/常亮/呼吸/心跳/流量联动 + 点亮测试）、界面偏好、**一键健康检查** |
| **系统** | 固件版本与构建、进入空中升级、重启设备 |

### 新增接口

| 方法 | 路径 | 作用 |
|------|------|------|
| GET | `/api/v1/hal` | 芯片型号/核数/主频/Flash/温度/运行时长/复位原因 |
| GET | `/api/v1/linkscore` | RSSI、信道频率、同信道邻居数、0-100 链路评分 |
| GET | `/api/v1/traffic` | 累计收发字节/包数、丢包、最近 30 格流量历史 |
| GET/POST | `/api/v1/prefs` | 灯效、日志开关、紧凑模式、自动连表、跳过 TLS 校验 |
| POST | `/api/v1/led/test` | 点亮板载 LED 1.5 秒做自检 |
| GET/POST | `/clock` `/clock/sync` | 读取本地时间 / 触发 NTP 校时（可改时区） |
| POST | `/api/v1/watch/push` | 把一段文本投递到已连接的手表（走已认证的 SPP 会话） |
| GET | `/api/v1/logs` | 最近 24 条关键事件（连接/认证/推送/恢复出厂） |
| POST | `/api/v1/reboot` | 软重启 |

### 链路评分怎么算

```
RSSI（权重 5）：-50dBm 满分，-90dBm 归零，中间线性
内存（权重 3）：80KB 满分，20KB 归零
丢包（权重 2）：0% 满分，5% 归零
score = (R*5 + M*3 + Q*2) / 10
```

低于 50 分页面会提示「建议换信道或靠近路由器」，这个阈值是经验值，但比单看 RSSI 靠谱 ——
内存不足 20KB 时蓝牙栈会开始丢帧，那时 RSSI 再好也没用。

### 向手表推消息的实现方式

没有新造协议。复用了已有的「转写文本」消息体（`buildXiaoAiTranscript`，final=1），
只是内容来自你在网页上输入的字。投递时机在桥接会话的收包间隙，此时会话已认证、
密钥可用、快应用已定位 —— 这是唯一安全的发送窗口。流程：

```
网页 POST /api/v1/watch/push
  → 写入 420 字节待发缓冲（只存一条，重入直接拒绝，不覆盖用户输入）
  → 桥接循环每轮 flushPendingWatchText()
  → 查缓存的手表 app 指纹 → 编码 → AES 加密 → 写入 SPP
  → 结果写进运行日志（PUSH_OK / PUSH_FAIL reason=...）
```

限制：只在桥接会话进行中才会真正发出，离线时排队最多保留一条；文本上限 400 字节。
