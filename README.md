# Vela Gateway

把 ESP32 变成手表 / 手环的 Wi-Fi 上网桥。蓝牙 SPP 连手表，Wi-Fi 连路由器，用 lwIP NAPT 把两者桥起来，手表通过它上网。

面向 **16MB Flash** 的 ESP32（ESP32-WROVER-E N16R8 / YD-ESP32-B）。管理台是手机能直接用的网页，连上就能配置 Wi-Fi、刷固件、看状态。

**当前版本 `v0.0.0.5`** · 技术预览 · RAM 22.5%（73,720 / 327,680 B）· Flash 25.1%（1,578,448 / 6,291,456 B）

---

## 刷固件

不用装编译环境，直接用 [乐鑫 Flash Download Tool](https://www.espressif.com/en/support/download/other-tools)。

| 场景 | 文件 | 地址 |
|---|---|---|
| **首次 / 救砖** | [`firmware/vela-gateway-v0.0.0.5-esp32-16mb-factory.bin`](firmware/) | `0x0` |
| 网页 OTA 升级 | [`firmware/vela-gateway-v0.0.0.5-esp32-16mb-ota.bin`](firmware/) | `0x20000` |

factory 是整包（bootloader + 分区表 + otadata + app），**只刷这一个、地址填 `0x0`**，分区表不用管。

历史版本在 [Releases](https://github.com/shikongxiaohan/vela-gateway-16mb/releases)，每个都带 MD5。详细步骤见 [docs/刷写.md](docs/刷写.md)。

## 使用

1. 刷完自动进配网热点 **`Vela-Setup`**，密码 `12345678`
2. 手机连上，浏览器打开 `http://192.168.4.1`
3. 选 Wi-Fi、输密码，保存
4. 连上后改用路由器分配的 IP 打开同一个管理台（路由器后台能查到）

热点名和密码都能在管理台里改。

> 连不上 Wi-Fi 时会自动开热点让你重配，**不会清空已有配置**。要清空得手动点「恢复出厂」。

## 编译

```bash
pio run -e yd_esp32_16mb
```

产物在 `firmware/`。需要 PlatformIO，平台锁在 `espressif32@6.1.0` + ESP-IDF `4.4.4`（见 `platformio.ini`，版本不能随便升）。

构建时自动完成：版本号递进 → 编译 → 修 otadata → 生成 factory/ota → 校验镜像 → 跑回归测试。

## 版本号

`主.次.构建.修订` 四段，如 `v0.0.0.3`。修订号最多 4 位、前导 0 省略，到 9999 进位到构建号。

**不用手改**。改源码后构建会自动 +1，源码没动则沿用。唯一真源是 `version.txt`，`src/vela_version.h` 由它自动生成。手动调整用：

```bash
python3 tools/bump_version.py --show
python3 tools/bump_version.py --set v0.0.0.7
```

## 分区

| 分区 | 大小 | 用途 |
|---|---|---|
| nvs | 20 KB | 配置 |
| otadata | 8 KB | OTA 启动记录 |
| ota_0 / ota_1 | 各 6 MB | 双 app 槽，支持回滚 |
| spiffs | 3.875 MB | 数据 |

固件约 1.5 MB，6 MB 槽位有 4 倍余量。

## 目录

```
src/          固件源码
tools/        构建钩子、校验、回归测试、版本工具
firmware/     当前版本固件
docs/         刷写说明、管理台截图
partitions_ota_16mb.csv
platformio.ini
version.txt   版本号唯一真源
```

## 许可

MIT
