# Vela Gateway

让 ESP32 给手表当上网的桥。手表侧走蓝牙 SPP，家里走 Wi-Fi，中间用 lwIP NAPT 把两层接起来。手表不用知道 Wi-Fi 密码，换路由器也只改网关这边。

硬件是 16MB Flash 的 ESP32（ESP32-WROVER-E N16R8 / YD-ESP32-B）。管理台是个手机浏览器能直接开的网页，配 Wi-Fi、刷固件、看状态都在里面。

当前版本 v0.0.0.18，RAM 用 22.6%，Flash 用 25.5%。

---

## 刷固件

不用装编译环境，用[乐鑫 Flash Download Tool](https://www.espressif.com/en/support/download/other-tools)就够。

| 场景 | 文件 | 地址 |
|---|---|---|
| 首次刷 / 救砖 | [`firmware/vela-gateway-v0.0.0.18-esp32-16mb-factory.bin`](firmware/) | `0x0` |
| 网页 OTA 升级 | [`firmware/vela-gateway-v0.0.0.18-esp32-16mb-ota.bin`](firmware/) | `0x20000` |

factory 是整包，bootloader、分区表、otadata、app 都在里面，只刷这一个文件、地址填 `0x0`，不用另外管分区表。

旧版本在 [Releases](https://github.com/shikongxiaohan/vela-gateway-16mb/releases)，都带 MD5。具体步骤见 [docs/刷写.md](docs/刷写.md)。

## 用起来

1. 刷完自动开热点 `Vela-Setup`，密码 `12345678`
2. 手机连上，浏览器开 `http://192.168.4.1`
3. 选 Wi-Fi、输密码、保存
4. 连上以后改用路由器分的 IP 开同一个管理台。IP 在路由器后台能查到

热点名和密码都能在管理台改。

连接失败的时候会自动开热点让你重配，已有的配置不会被清掉。想彻底清空得手动点「恢复出厂」。

### 升级固件

在系统页。选 `-ota.bin` 传进设备，列表里点一行选中，再点「升级到选中版本」。镜像会先校验一遍，通过了才写进备用分区，写完重启切过去。新固件如果起不来，会自动退回旧版。

整包 `-factory.bin` 不能在网页上刷，它的第一个字节是空白 Flash，不是 app 镜像。整包只能走数据线。

### 装表盘 / 快应用

在「资源」页。表盘是 `.bin` / `.face`，快应用是 `.rpk`。文件先传到网关存着，再由网关通过蓝牙 Mass 通道分片推给手表。

装的过程中网关会暂停回程网络，因为 Mass 通道要独占蓝牙。手表那边的 TCP 会自己重传，装完就恢复。

详见 [docs/表盘安装.md](docs/表盘安装.md)。

## 编译

```bash
pio run -e yd_esp32_16mb
```

产物落在 `firmware/`。需要 PlatformIO，平台锁在 `espressif32@6.1.0` + ESP-IDF `4.4.4`，见 `platformio.ini`。这组版本不能随便升，升级会踩一堆坑。

一次构建会自动做完这些：递进版本号、编译、修 otadata、生成 factory 和 ota、校验镜像、跑回归测试。

## 版本号

四段，主.次.构建.修订，比如 `v0.0.0.3`。修订号最多四位，前导零不补，到 9999 进位到构建号。

平时不用手工改。改了源码，构建时自动 +1；源码没动就沿用。真源是根目录的 `version.txt`，`src/vela_version.h` 从它生成。

要手动调：

```bash
python3 tools/bump_version.py --show
python3 tools/bump_version.py --set v0.0.0.7
```

修订号只在「源码变了，并且上一次真的出过包」时才 +1。中途编译失败不吃号。

> v0.0.0.6 到 v0.0.0.10 这几个号从来没出过包。那是旧逻辑的遗留问题：后来改成现在这条规则了，老号已经发出去，就不回头改了。

## 分区

| 分区 | 大小 | 用途 |
|---|---|---|
| nvs | 20 KB | 配置 |
| otadata | 8 KB | OTA 启动记录 |
| ota_0 / ota_1 | 各 6 MB | 双 app 槽，支持回滚 |
| spiffs | 3.875 MB | 表盘、快应用、固件包 |

固件 1.6 MB 左右，6 MB 的槽有将近四倍余量。

## 目录

```
src/          固件源码
tools/        构建钩子、校验、回归测试、版本工具
firmware/     当前版本固件
docs/         刷写说明、表盘安装、管理台截图
partitions_ota_16mb.csv
platformio.ini
version.txt   版本号真源
```

## 许可

MIT
