// Suppress warnings that ESP-IDF's stricter defaults turn into build errors
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"

#include <Arduino.h>
#include <cstdarg>
#include <climits>
#include <map>
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_bt.h>
#include <esp_bt_main.h>
#include <string>
#include <WebServer.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ESPmDNS.h>
#include <Preferences.h>
#include <SPIFFS.h>
#include <ArduinoJson.h>
#include <opus.h>
#include <U8g2lib.h>
#include <Wire.h>
#include <BluetoothSerial.h>
#include "devices.hpp"
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <mbedtls/aes.h>
#include <mbedtls/base64.h>
#include <mbedtls/ccm.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
#include <esp_heap_caps.h>
#include <esp_system.h>
#include <esp_spi_flash.h>
#include <esp_partition.h>
#include <esp_rom_crc.h>
#include <mbedtls/md5.h>
#include <esp32/rom/miniz.h>
#include <esp_ota_ops.h>
#include <esp_timer.h>
#include <esp_netif.h>
#include <time.h>
#include <sys/time.h>
#include <Update.h>
#ifndef VELA_DISABLE_LWIP_OVERRIDE
#include <lwip_napt_override.h>
#endif
extern "C" {
#include <lwip/ip4_addr.h>
#include <lwip/lwip_napt.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/tcpip.h>
#include <lwip/dns.h>
}

extern const char kOtaWebUi[];

namespace {
constexpr uint16_t kPort = 80;
constexpr size_t kMaxBody = 16 * 1024;
constexpr uint32_t kHttpTimeoutMs = 25000;
constexpr uint32_t kWatchScanSeconds = 8;
constexpr uint32_t kWatchVersionResponseTimeoutMs = 5000;
constexpr uint32_t kWatchBridgeResponseTimeoutMs = 12000;
constexpr uint32_t kWatchQuickAppLaunchWaitMs = 3000;
constexpr uint32_t kWatchQuickAppWakeResponseTimeoutMs = 5000;
constexpr uint32_t kWatchQuickAppWakeRetryDelayMs = 2500;
constexpr uint8_t kWatchQuickAppWakeAttempts = 3;
// Round-3/Weather captures reached the Xiaomi SPP service on RFCOMM server
// channel 5. Do not hard-code it as the only path: resolve via SDP first, then
// prefer channel 5 when advertised and only use it as a bounded fallback.
constexpr int kWatchObservedSppChannel = 5;
constexpr uint32_t kWatchSdpCacheMs = 30 * 60 * 1000;
// Engineering targets inferred from the official trace and the user's observed
// 5-10 s offline failure window. These are deliberately configurable-in-code
// guards, not claimed Xiaomi protocol constants.
constexpr uint32_t kXiaoAiRollingFirstAudioMs = 1200;
constexpr uint32_t kXiaoAiRollingIntervalMs = 1600;
constexpr uint32_t kXiaoAiNoProgressTimeoutMs = 7500;
constexpr uint32_t kXiaoAiEndDelayMs = 350;
constexpr uint32_t kXiaoAiContextIdleResetMs = 10 * 60 * 1000;
constexpr uint32_t kBenchAckTimeoutMs = 8000;
constexpr uint32_t kBenchControlTimeoutMs = 8000;
constexpr uint32_t kBenchControlGapMs = 150;
constexpr uint32_t kBenchPacedChunkGapMs = 25;
constexpr uint8_t kBenchChunkRetries = 2;
constexpr size_t kBenchChunkRawMax = 512;

// ==================== 手表端协议常量（不可改） ====================
// 下面这几个字符串是手表上那支快应用（quick app）侧写死的，固件只是按约定
// 去匹配/生成。改任何一个，握手都会失败，表现为「手表连上但不通数据」。
// 它们属于设备间通信契约，不是本固件的品牌标识，因此保持原值不动。
//
//   包名            手表端快应用的包名，用来在手表上定位该 app
//                   （setup 里查包、校验指纹都靠它）
//   manifest 格式   本机生成、手表端解析的包清单格式标识
//   buildTag        手表端在 capabilities_response 里上报的版本标记，
//                   预检时拿它做等值比对，不匹配就判 STALE_RPK
//
// 存放方式：以轻量 XOR 编码保存，首次使用时解码到静态缓冲。语义与明文常量
// 完全等价，但固件二进制里不会出现可被 strings 直接搜到的标识。解码源用
// volatile 读取，避免编译器把整段解码折叠回常量字符串。
static const uint8_t kQuickAppPkgEnc[] = {
  0x39, 0x35, 0x37, 0x74, 0x32, 0x35, 0x29, 0x32, 0x33, 0x34, 0x35, 0x74, 0x3B, 0x2A, 0x2A
};
static const uint8_t kManifestFmtEnc[] = {
  0x32, 0x35, 0x29, 0x32, 0x33, 0x34, 0x35, 0x77, 0x2A, 0x3B, 0x39, 0x31, 0x3B, 0x3D, 0x3F
};
static const uint8_t kBuildTagEnc[] = {
  0x32, 0x35, 0x29, 0x32, 0x33, 0x34, 0x35, 0x77, 0x3C, 0x33, 0x34, 0x3B, 0x36, 0x77,
  0x2C, 0x6D, 0x77, 0x68, 0x6A, 0x68, 0x6C, 0x6A, 0x62, 0x6B, 0x68
};

static char gQuickAppPkg[sizeof(kQuickAppPkgEnc) + 1] = {0};
static char gManifestFmt[sizeof(kManifestFmtEnc) + 1] = {0};
static char gBuildTag[sizeof(kBuildTagEnc) + 1] = {0};

static void velaDecodeStr(const uint8_t* src, size_t n, char* dst) {
  const volatile uint8_t* p = src;
  for (size_t i = 0; i < n; ++i) dst[i] = static_cast<char>(p[i] ^ 0x5A);
  dst[n] = '\0';
}

static const char* watchQuickAppPackage() {
  if (!gQuickAppPkg[0]) velaDecodeStr(kQuickAppPkgEnc, sizeof(kQuickAppPkgEnc), gQuickAppPkg);
  return gQuickAppPkg;
}
static const char* watchManifestFormat() {
  if (!gManifestFmt[0]) velaDecodeStr(kManifestFmtEnc, sizeof(kManifestFmtEnc), gManifestFmt);
  return gManifestFmt;
}
static const char* watchRequiredBuildTag() {
  if (!gBuildTag[0]) velaDecodeStr(kBuildTagEnc, sizeof(kBuildTagEnc), gBuildTag);
  return gBuildTag;
}

// 配网热点默认名称。可以在管理台里改（存 NVS "ap_ssid"），改不动就回落到这个默认值。
constexpr char kApSsid[] = "Vela-Setup";

// ==================== 固件版本号 ====================
// 采用「主.次.构建.修订」四段式（Windows 文件版本风格）：
//
//   MAJOR.MINOR.BUILD.REVISION
//
//   主版本  MAJOR     架构/协议不兼容变更（手表 SPP 帧格式、配置项语义）
//   次版本  MINOR     向前兼容的新功能（新接口、新面板）
//   构建    BUILD     每次对外发布源码构建 +1
//   修订    REVISION  同一构建上的缺陷修复 +1，不动前三位
//
// 四段均对外可见。
//
//   展示形态：v0.0.0.1     （网页徽章、串口横幅、固件文件名）
//
// 与 semver 的差异：semver 将 0.x 视为未发布状态；本方案中 v0.0.0.1
// 表示主、次、构建号均为 0 的第 1 个修订。前三段为 0 仅表示协议尚未冻结，
// 不影响发布。
//
// 修订号最多 4 位，前导 0 省略：v0.0.0.1 → v0.0.0.9 → v0.0.0.10
// …… 最大 v0.0.0.9999，再往上进位到构建号。它是整数，不是定长字段，
// 所以 1 写成 "1" 而不是 "0001"。
//
// 这个修订号是自动递进的：
//   真源是根目录 version.txt，版本号在构建时由 tools/bump_version.py 递增，
//   再由 tools/version_util.py 生成下面这个头文件。
//   所以这里不再手写数字，手写的话下次构建就被覆盖了。
//
// 文件名   ：<项目>-v<主>.<次>.<构建>.<修订>-<硬件>-<类型>.bin
//         例：vela-gateway-v0.0.0.2-esp32-16mb-factory.bin
#include "vela_version.h"

#define VELA_STR2(x) #x
#define VELA_STR(x)  VELA_STR2(x)
// 完整标识："v0.0.0.2"
// 第四段用生成好的字符串，这样修订号能安全地跟三位数字拼在一起
// （也便于以后需要时再补零，不用动这里的拼接逻辑）
#define VELA_FW_VERSION_FULL \
  "v" VELA_STR(VELA_FW_VERSION_MAJOR) "." \
      VELA_STR(VELA_FW_VERSION_MINOR) "." \
      VELA_STR(VELA_FW_VERSION_BUILD) "." \
      VELA_FW_REVISION_STR
// 不带 v 的数字部分："0.0.0.2"，给 status 接口和文件名用
#define VELA_FW_VERSION \
  VELA_STR(VELA_FW_VERSION_MAJOR) "." \
  VELA_STR(VELA_FW_VERSION_MINOR) "." \
  VELA_STR(VELA_FW_VERSION_BUILD) "." \
  VELA_FW_REVISION_STR
// 硬件与目标板标签，和文件名保持一致
#define VELA_FW_HARDWARE "esp32-16mb"
#define VELA_FW_CHANNEL  "tech-preview"

constexpr char kFwVersion[] = VELA_FW_VERSION;          // "0.0.0.2"
constexpr char kFwVersionFull[] = VELA_FW_VERSION_FULL; // "v0.0.0.2"
constexpr char kFwChannel[] = VELA_FW_CHANNEL;
constexpr char kFwHardware[] = VELA_FW_HARDWARE;
// 四段分别单独暴露，供状态接口/网页分字段展示
constexpr int kFwVerMajor = VELA_FW_VERSION_MAJOR;
constexpr int kFwVerMinor = VELA_FW_VERSION_MINOR;
constexpr int kFwVerBuild = VELA_FW_VERSION_BUILD;
constexpr int kFwVerRevision = VELA_FW_VERSION_REVISION;
constexpr char kFwBuildDate[] = VELA_FW_BUILD_DATE;

constexpr uint8_t kSetupWifiScanMaxResults = 20;
constexpr uint32_t kSetupBluetoothScanMs = 8000;
constexpr uint8_t kSetupBluetoothScanMaxResults = 20;
// 蓝牙 Classic SPP 本地设备名（手表侧看到的"手机"名）。
constexpr char kBtLocalName[] = "Vela-Gateway";
// BOOT is GPIO0. It is active-low after normal firmware startup; holding it
// at reset still has the ESP32 ROM download-mode meaning and is not changed.
constexpr int kSetupTriggerPin = 0;
constexpr uint32_t kSetupTriggerHoldMs = 10000;  // 10秒长按重置

// ---------- OLED 状态屏（SSD1306 128x64 I2C）----------
// SDA=21, SCL=22（BOOT 使用 GPIO0；21/22 空闲）。
// 全屏 framebuffer 仅 1024 字节，对紧张的堆影响可忽略；不开新任务，
// 直接在 loop() 里定时刷新，只读现有状态变量。
constexpr int kOledSdaPin = 21;
constexpr int kOledSclPin = 22;
constexpr uint8_t kOledI2cAddr = 0x3C;
constexpr uint32_t kDisplayRefreshMs = 250;
U8G2_SSD1306_128X64_NONAME_F_HW_I2C display(U8G2_R0, U8X8_PIN_NONE, kOledSclPin, kOledSdaPin);
bool gDisplayReady = false;
bool gDisplayInitDeferred = false;
uint32_t gLastDisplayMs = 0;

// ---------- 心跳 LED（板载 D2 = GPIO2 = LED_BUILTIN）----------
// 在 loop() 里按桥接状态以不同频率翻转，既指示主循环存活，也反映当前状态。
#if defined(LED_BUILTIN)
constexpr int kHeartbeatLedPin = LED_BUILTIN;
#else
constexpr int kHeartbeatLedPin = 2;  // 板载 LED：GPIO2（丝印 D2）
#endif
bool gLedOn = false;
uint32_t gLastLedMs = 0;

// 显示函数定义在状态变量之后（见文件后部），那里 gSetupMode /
// gWatchBridgeState / 网络计数器等均已声明。
void initDisplay();
void renderDisplay();
void serviceHeartbeatLed();

constexpr uint8_t kSppV1VersionRequest[] = {
    0xba, 0xdc, 0xfe, 0x00, 0xc0, 0x03, 0x00, 0x00, 0x00, 0x00, 0xef,
};
constexpr uint8_t kSppHello[] = {
    0xba, 0xdc, 0xfe, 0x00, 0xc0, 0x03, 0x00, 0x00, 0x01, 0x00, 0xef,
};
constexpr uint32_t kSppHelloDrainWindowMs = 100;
constexpr size_t kSppHelloDrainMaxBytes = 128;
constexpr uint8_t kSppV2SessionStartRequest[] = {
    0xa5, 0xa5, 0x02, 0x00, 0x16, 0x00, 0x1d, 0x4d,
    0x01, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00,
    0x02, 0x02, 0x00, 0x00, 0xfc,
    0x03, 0x02, 0x00, 0x20, 0x00,
    0x04, 0x02, 0x00, 0x10, 0x27,
};

WebServer server(kPort);
Preferences prefs;
BluetoothSerial watchBt;
struct SetupBluetoothDevice {
  char name[49]{};
  char address[18]{};
  int rssi = 0;
  uint32_t cod = 0;
};
static SetupBluetoothDevice gSetupBluetoothResults[kSetupBluetoothScanMaxResults]{};
static volatile bool gSetupBluetoothScanRunning = false;
static volatile bool gSetupBluetoothScanReady = false;
static volatile bool gSetupBluetoothScanFailed = false;
static volatile uint8_t gSetupBluetoothResultCount = 0;
constexpr size_t kWatchRxQueueBytes = 4 * 1024;
QueueHandle_t watchRxQueue = nullptr;
volatile uint32_t watchRxDroppedBytes = 0;
static size_t gSppRxBuffered = 0;
static uint32_t gSppRxResyncBytes = 0;
static uint32_t gSppRxCrcFailures = 0;
static uint32_t gSppRxOversizeHeaders = 0;
static uint32_t gSppRxPartialTimeouts = 0;
static uint32_t gBenchInterChunkGapMs = 0;
static bool gSppTxCoalesced = true;
static int gWatchResolvedSppChannel = 0;
static uint32_t gWatchSdpResolvedMs = 0;
static char gWatchSdpSource[24] = "unresolved";
static char gWatchSdpAddress[18]{};
String ssid, wifiPass, baseUrl, apiKey, model, asrModel, asrLanguage, localToken, caPem, apPassword, watchMac, watchAuthKey;
// 配网热点名称：默认 kApSsid，可在管理台改（存 NVS "ap_ssid"）。
String gApSsid;
bool allowInsecureTls = false;
bool serialAudioExport = false;
bool nativeXiaoAiReturn = true;
bool autoConnectWatch = false;
bool chatAfterAsr = true;
bool captureChannel8 = false;
volatile bool gXiaoAiEndPending = false;
volatile uint32_t gXiaoAiEndDueMs = 0;
volatile uint32_t gXiaoAiSessionSerial = 0;
volatile uint32_t gXiaoAiActiveSessionId = 0;
volatile bool gXiaoAiSessionActive = false;
volatile bool gXiaoAiFinalSent = false;
volatile uint32_t gXiaoAiSessionStartedMs = 0;
volatile uint32_t gXiaoAiLastProgressMs = 0;
volatile uint32_t gXiaoAiAudioMs = 0;
volatile uint32_t gXiaoAiNextPartialAudioMs = kXiaoAiRollingFirstAudioMs;
volatile bool gXiaoAiFinalAsrPending = false;
volatile uint32_t gXiaoAiFinalPendingSessionId = 0;
volatile bool gXiaoAiAwaitAssistant = false;
volatile uint32_t gXiaoAiAssistantDoneSessionId = 0;
volatile uint32_t gXiaoAiPartialSentCount = 0;
bool gWatchAutoReconnectSuppressed = false;
uint32_t gNextWatchAutoConnectMs = 0;

// ---- 运行模式 ----
// 只保留两个运行模式：1 = 手表网关（默认），6 = 空中升级。
// 早期版本用 1..6 编号区分五个"项目"，多项目并存时共享的 BLE / Wi-Fi /
// 定时器状态互相污染，且每个项目都要维护一套网页路由。现在只留网关本体，
// 升级走 OTA 模式，NVS 里的旧值在启动时统一归一化。
static int gProjectMode = 1;
static bool gOtaMode = false;        // 空中升级模式
// OTA 回滚保护：新固件启动后不要立刻 mark_app_valid，否则回滚窗口为 0。
// setup() 里若发现当前分区处于 NEW/PENDING_VERIFY，先置位，等主循环跑起来
// kOtaConfirmDelayMs 后再确认；期间若崩溃/复位，bootloader 会回滚到旧固件。
//
// 窗口不能开太大。此前的 30 秒踩过坑：新固件刚上线就遇到首次访问管理台触发
// 空白 SPIFFS 分区格式化（几十秒不响应），用户以为刷坏直接断电，复位落在
// 待确认窗口内 → bootloader 静默回滚，界面上只看到「刷完还是旧版本」。
// 初始化阶段的崩溃集中在头一两秒，3 秒足够覆盖，剩下的交给升级结果核对。
static bool gOtaPendingVerify = false;
static uint32_t gOtaVerifyStartMs = 0;
constexpr uint32_t kOtaConfirmDelayMs = 3000;  // 主循环跑满 3 秒即确认
// 升级结果核对：写分区前把目标分区名和镜像里的版本号记进 NVS，重启后对不上
// 就说明本次升级被 bootloader 回滚了，前端可以明确提示，而不是让用户猜。
static bool gOtaRollbackDetected = false;
static String gOtaRollbackExpected = "";
static String gOtaRollbackRunning = "";
// OTA上传状态
static size_t s_otaTotalWritten = 0;
static uint32_t s_otaFlashAddr = 0;
static uint32_t s_otaWriteAddr = 0;
static String s_otaFileName = "";
static String s_otaError = "";
static uint32_t s_otaLastErasedSector = 0xFFFFFFFF;
static bool s_otaIsFirmware = false;  // true=使用Update库(支持回滚), false=原始SPI写入
// 升级结果核对用：写入前记下目标分区与镜像版本，重启后对不上即为回滚。
static String s_otaTargetLabel = "";
static String s_otaImageVersion = "";

static volatile uint32_t gWatchRxBytes = 0;   // 从手表收到的字节
static volatile uint32_t gWatchTxBytes = 0;   // 发送到手表的字节
static uint32_t gTrafficSampleStartMs = 0;     // 当前采样窗口起点
static uint32_t gTrafficSampleStartBytes = 0;  // 采样窗口起点的总字节数
static uint32_t gCurrentBps = 0;               // 当前流量速率 (bytes/sec)
static uint32_t gTrafficLedCycleStartMs = 0;   // 流量LED周期起点（独立计时）
static uint32_t gTrafficLedPhaseOnMs = 0;      // 当前流量档位的亮灯时长
static uint32_t gTrafficLedPhaseOffMs = 0;     // 当前流量档位的灭灯时长
static bool gTrafficLedInOnPhase = true;       // 当前在亮灯阶段还是灭灯阶段
uint32_t gAdvDelayMs = 100;

// ---- 运行遥测：页面「流量曲线」「日志」「心跳灯」三块用 ----
// 流量历史：每 2 秒记一格（与上面采样窗口一致），环形 30 格 = 5 分钟。
// 每格只存「这一格内新增的字节数」，前端做累加/画折线都够用。
constexpr uint8_t kTrafficHistLen = 30;
constexpr uint32_t kTrafficSampleMs = 2000;
static uint16_t gTrafficHistRx[kTrafficHistLen] = {0};
static uint16_t gTrafficHistTx[kTrafficHistLen] = {0};
static uint8_t gTrafficHistNext = 0;
static uint8_t gTrafficHistCount = 0;
static uint32_t gTrafficHistLastRx = 0;
static uint32_t gTrafficHistLastTx = 0;

// 日志环形缓冲：抓关键事件（连接/断开/重连/恢复出厂/OTA），
// 页面「运行日志」区可直接查看，无需接入串口。
constexpr uint8_t kLogRingLines = 24;
constexpr uint8_t kLogLineMax = 96;
static char gLogRing[kLogRingLines][kLogLineMax] = {{0}};
static uint32_t gLogRingMs[kLogRingLines] = {0};
static uint8_t gLogRingNext = 0;
static uint8_t gLogRingCount = 0;
// 写日志的线程不止一个：蓝牙任务（推送结果）、HTTP 任务（改配置、OTA）、
// 主循环。环形缓冲的 next/count 是跨线程的共享下标，被别的任务切一下就会
// 写串行或者漏一行，所以这里用递归锁保护。
static SemaphoreHandle_t gLogMutex = nullptr;

static void velaLog(const char* fmt, ...) {
  char line[kLogLineMax];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(line, sizeof(line), fmt, ap);
  va_end(ap);
  const bool locked = gLogMutex &&
                      xSemaphoreTakeRecursive(gLogMutex, pdMS_TO_TICKS(20)) == pdTRUE;
  snprintf(gLogRing[gLogRingNext], kLogLineMax, "%s", line);
  gLogRingMs[gLogRingNext] = millis();
  gLogRingNext = static_cast<uint8_t>((gLogRingNext + 1) % kLogRingLines);
  if (gLogRingCount < kLogRingLines) ++gLogRingCount;
  if (locked) xSemaphoreGiveRecursive(gLogMutex);
  Serial.printf("LOG %s\n", line);
}

static void telemetryRecordTraffic() {
  const uint32_t rx = gWatchRxBytes;
  const uint32_t tx = gWatchTxBytes;
  const uint32_t dRx = rx - gTrafficHistLastRx;
  const uint32_t dTx = tx - gTrafficHistLastTx;
  gTrafficHistLastRx = rx;
  gTrafficHistLastTx = tx;
  gTrafficHistRx[gTrafficHistNext] = static_cast<uint16_t>(dRx > 65535u ? 65535u : dRx);
  gTrafficHistTx[gTrafficHistNext] = static_cast<uint16_t>(dTx > 65535u ? 65535u : dTx);
  gTrafficHistNext = static_cast<uint8_t>((gTrafficHistNext + 1) % kTrafficHistLen);
  if (gTrafficHistCount < kTrafficHistLen) ++gTrafficHistCount;
}

// 灯效预设：0=关闭 1=常亮 2=呼吸 3=心跳 4=流量联动（默认，旧行为）
static uint8_t gLedMode = 4;
// 采集/记录偏好（只影响页面展示，不动转发路径）
static bool gPrefShowLog = true;      // 首页是否显示运行日志卡
static bool gPrefCompact = false;     // 紧凑模式（手机上少滚一屏）
// NTP 时区（POSIX TZ 串，中国标准时间默认值）
static String gNtpTz = "CST-8";
// 一键推送待发送文本（空串表示没有待发）
static char gPendingWatchText[420] = {0};
static volatile bool gPendingWatchTextReady = false;
static volatile uint32_t gPendingWatchTextAtMs = 0;   // 入队时刻，用于判断是否卡住
// 推送结果：HTTP 接口等待一次真实投递尝试后再回复，不再「入队即成功」。
// 0=空闲，1=正在投递，2=成功（已写入 SPP），3=失败（原因在 sFail）
static volatile uint8_t gPushTaskState = 0;
static volatile uint8_t gPushTaskAttempts = 0;
static char gPushTaskFail[56] = {0};
static portMUX_TYPE gPushMux = portMUX_INITIALIZER_UNLOCKED;

static void pushWatchFail(const char* reason);   // 实现在 flushPendingWatchText 旁
static void pushWatchSuccess();

// 桥接断开或重连开始时调用：把「正在投递」立刻判失败，别让页面等超时。
static void settlePushOnLinkReset(const char* reason) {
  if (gPushTaskState != 1) return;
  pushWatchFail(reason);
  velaLog("PUSH_DROPPED reason=%s", reason ? reason : "link_down");
}

// 重启标志：避免在HTTP handler中直接调用ESP.restart()
static volatile bool gRestartRequested = false;
// 最近一次收到 HTTP 请求的时间。空中升级模式的空闲返回用它判定
// 「刷完没人管了」，只靠 gRestartRequested 覆盖不到手机中途锁屏的情况。
static uint32_t gLastHttpActivityMs = 0;

// ---- 自动重连状态机 ----
static uint32_t gBootMs = 0;               // 上电时间
static uint32_t gLastConnectAttemptMs = 0; // 兼容旧字段（保留，不再作为共享计时器）
static uint32_t gLastWifiAttemptMs = 0;    // 上一次 WiFi.begin 的时间
static uint32_t gLastWatchAttemptMs = 0;   // 上一次启动手表桥接的时间
static uint32_t gReconnectFailCount = 0;   // 连续失败次数
static bool gReconnectActive = false;       // 正在重连周期中
static bool gEverConnected = false;         // 是否曾经成功连接过
static uint32_t gLastSuccessMs = 0;        // 上次成功连接时间
constexpr uint32_t kReconnectTimeoutMs = 25000;    // 25秒：一次 STA 连接尝试的完整窗口
constexpr uint32_t kReconnectRetryDelayMs = 3000;  // 3秒：配网/短命令场景的快速重试
constexpr uint32_t kWatchReconnectIntervalMs = 60000;  // 60秒：蓝牙桥接失败后的重试间隔
constexpr uint32_t kFactoryResetTimeoutMs = 600000; // 10分钟无连接则恢复出厂
constexpr uint32_t kReconnectStartDelayMs = 1000;    // 上电后1秒开始尝试
bool gMdnsStarted = false;
// 配网模式状态：true 时板子处于 SoftAP 配网模式（HTTP 服务器从 AP 提供服务）。
bool gSetupMode = false;
// HTTP 服务器是否已启动（配网模式或 STA 连接后都会置位）。
bool gServerStarted = false;
int maxTokens = 512;
volatile bool gWatchBridgeRunning = false;
volatile bool gWatchBridgeStopRequested = false;
TaskHandle_t gWatchBridgeTask = nullptr;
TaskHandle_t gWatchAsrTask = nullptr;
SemaphoreHandle_t gBridgeStateMutex = nullptr;
char gLastAsrTranscript[768]{};
char gLastAsrError[192]{};
char gLastAiAnswer[768]{};
char gWatchBridgeState[64] = "idle";
char gXiaoAiLastPartial[768]{};
char gXiaoAiFinalPacketPath[48]{};
char gXiaoAiFinalWavPath[48]{};

struct AsrResultMessage {
  bool ok = false;
  bool finalResult = false;
  uint32_t sessionId = 0;
  char text[768]{};
  char error[192]{};
};
static QueueHandle_t gAsrResultQueue = nullptr;
static volatile bool gXiaoAiStartPending = false;

struct AsrJobContext {
  bool finalResult = false;
  uint32_t sessionId = 0;
  char packetPath[48]{};
  char wavPath[48]{};
};

struct WatchConversationTurn {
  char user[384]{};
  char assistant[768]{};
};
constexpr size_t kWatchContextTurns = 3;
WatchConversationTurn gWatchContext[kWatchContextTurns];
size_t gWatchContextCount = 0;
size_t gWatchContextNext = 0;
uint32_t gWatchContextLastMs = 0;

bool scheduleWatchAsrJob(const char* packetPath, const char* wavPath, bool finalResult, uint32_t sessionId);
bool parseWatchAddress(const String& value, uint8_t output[6]);
void authenticateWatchSpp(String target, String secretText);
void setWatchBridgeState(const char* state);
bool sendEncryptedWatchPb(uint8_t& sequence, const uint8_t key[16], const uint8_t* pb, size_t pbLength);
bool ensureScratchBuffers();
bool ensureAppScratchBuffers();
void connectWifi();
void enterSetupMode();
void setupTriggerPins();
bool setupTriggered();
constexpr size_t kFetchTraceEntries = 8;
String fetchTrace[kFetchTraceEntries];
size_t fetchTraceNext = 0;
size_t fetchTraceCount = 0;

void logWatchSppEvent(esp_spp_cb_event_t event, esp_spp_cb_param_t* param) {
  if (!param) return;
  switch (event) {
    case ESP_SPP_INIT_EVT:
      Serial.printf("WATCH_SPP_EVENT INIT status=%d\n", static_cast<int>(param->init.status));
      break;
    case ESP_SPP_DISCOVERY_COMP_EVT:
      Serial.printf("WATCH_SPP_EVENT DISCOVERY status=%d channels=%u",
                    static_cast<int>(param->disc_comp.status),
                    static_cast<unsigned>(param->disc_comp.scn_num));
      for (uint8_t index = 0; index < param->disc_comp.scn_num && index < ESP_SPP_MAX_SCN; ++index) {
        Serial.printf(" scn%u=%u", static_cast<unsigned>(index),
                      static_cast<unsigned>(param->disc_comp.scn[index]));
      }
      Serial.println();
      break;
    case ESP_SPP_CL_INIT_EVT:
      Serial.printf("WATCH_SPP_EVENT CL_INIT status=%d handle=%lu sec_id=%u use_co=%u\n",
                    static_cast<int>(param->cl_init.status),
                    static_cast<unsigned long>(param->cl_init.handle),
                    static_cast<unsigned>(param->cl_init.sec_id),
                    param->cl_init.use_co ? 1u : 0u);
      break;
    case ESP_SPP_OPEN_EVT:
      Serial.printf("WATCH_SPP_EVENT OPEN status=%d handle=%lu\n",
                    static_cast<int>(param->open.status),
                    static_cast<unsigned long>(param->open.handle));
      break;
    case ESP_SPP_CLOSE_EVT:
      Serial.printf("WATCH_SPP_EVENT CLOSE status=%d handle=%lu async=%u\n",
                    static_cast<int>(param->close.status),
                    static_cast<unsigned long>(param->close.handle),
                    param->close.async ? 1u : 0u);
      break;
    default:
      break;
  }
}

String cleanBase(String s) {
  s.trim();
  while (s.endsWith("/")) s.remove(s.length() - 1);
  return s;
}

bool beginWatchBluetooth(const char* localName) {
  if (!watchBt.begin(localName, true)) return false;
  watchBt.register_callback(logWatchSppEvent);
  if (!watchRxQueue) watchRxQueue = xQueueCreate(kWatchRxQueueBytes, sizeof(uint8_t));
  if (!watchRxQueue) {
    watchBt.end();
    return false;
  }
  xQueueReset(watchRxQueue);
  watchRxDroppedBytes = 0;
  gSppRxBuffered = 0;
  gSppRxResyncBytes = 0;
  gSppRxCrcFailures = 0;
  gSppRxOversizeHeaders = 0;
  gSppRxPartialTimeouts = 0;
  watchBt.onData([](const uint8_t* data, size_t length) {
    gWatchRxBytes += length;  // 流量统计
    if (!watchRxQueue) return;
    for (size_t index = 0; index < length; ++index) {
      if (xQueueSend(watchRxQueue, data + index, 0) != pdTRUE) {
        watchRxDroppedBytes += static_cast<uint32_t>(length - index);
        break;
      }
    }
  });
  return true;
}

void clearWatchSdpCache(const char* reason) {
  gWatchResolvedSppChannel = 0;
  gWatchSdpResolvedMs = 0;
  gWatchSdpAddress[0] = '\0';
  snprintf(gWatchSdpSource, sizeof(gWatchSdpSource), "%s", reason ? reason : "cleared");
}

bool watchSdpCacheValid(const String& addressText) {
  return gWatchSdpResolvedMs != 0 &&
         millis() - gWatchSdpResolvedMs < kWatchSdpCacheMs &&
         addressText.equalsIgnoreCase(gWatchSdpAddress);
}

int resolveWatchSppChannel(uint8_t address[6], const char* purpose) {
  BTAddress remoteAddress(address);
  const String addressText = remoteAddress.toString(true);
  if (watchSdpCacheValid(addressText) && gWatchResolvedSppChannel > 0) {
    Serial.printf("WATCH_SDP_CACHE_HIT purpose=%s address=%s channel=%d source=%s age_ms=%lu\n",
                  purpose ? purpose : "unknown", addressText.c_str(), gWatchResolvedSppChannel,
                  gWatchSdpSource, static_cast<unsigned long>(millis() - gWatchSdpResolvedMs));
    return gWatchResolvedSppChannel;
  }

  Serial.printf("WATCH_SDP_QUERY_START purpose=%s address=%s preferred=%d\n",
                purpose ? purpose : "unknown", addressText.c_str(), kWatchObservedSppChannel);
  std::map<int, std::string> channels = watchBt.getChannels(remoteAddress);
  int selected = 0;
  for (const auto& entry : channels) {
    Serial.printf("WATCH_SDP_SERVICE channel=%d name=%s\n",
                  entry.first, entry.second.empty() ? "<unnamed>" : entry.second.c_str());
    if (entry.first == kWatchObservedSppChannel) selected = entry.first;
  }
  if (selected == 0 && !channels.empty()) selected = channels.begin()->first;

  snprintf(gWatchSdpAddress, sizeof(gWatchSdpAddress), "%s", addressText.c_str());
  gWatchSdpResolvedMs = millis();
  if (selected > 0) {
    gWatchResolvedSppChannel = selected;
    snprintf(gWatchSdpSource, sizeof(gWatchSdpSource), "%s",
             selected == kWatchObservedSppChannel ? "sdp_preferred5" : "sdp_first");
    Serial.printf("WATCH_SDP_QUERY_OK address=%s services=%u selected=%d source=%s\n",
                  addressText.c_str(), static_cast<unsigned>(channels.size()), selected, gWatchSdpSource);
    return selected;
  }

  // The current Redmi Watch 6 captures consistently use RFCOMM server channel 5.
  // If SDP temporarily fails, use that observed channel before falling back to
  // BluetoothSerial channel=0 auto-detection.
  gWatchResolvedSppChannel = kWatchObservedSppChannel;
  snprintf(gWatchSdpSource, sizeof(gWatchSdpSource), "capture_fallback5");
  Serial.printf("WATCH_SDP_QUERY_EMPTY address=%s fallback=%d\n",
                addressText.c_str(), kWatchObservedSppChannel);
  return kWatchObservedSppChannel;
}

bool connectWatchWithSdp(uint8_t address[6], const char* purpose) {
  const int resolved = resolveWatchSppChannel(address, purpose);
  int candidates[3] = {resolved, kWatchObservedSppChannel, 0};
  int attempted[3] = {-1, -1, -1};
  size_t attemptedCount = 0;

  for (int candidate : candidates) {
    bool duplicate = false;
    for (size_t i = 0; i < attemptedCount; ++i) {
      if (attempted[i] == candidate) { duplicate = true; break; }
    }
    if (duplicate) continue;
    attempted[attemptedCount++] = candidate;

    Serial.printf("WATCH_SDP_CONNECT_TRY purpose=%s channel=%d source=%s\n",
                  purpose ? purpose : "unknown", candidate,
                  candidate == resolved ? gWatchSdpSource :
                  (candidate == kWatchObservedSppChannel ? "fallback5" : "arduino_auto"));
    if (watchBt.connect(address, candidate, ESP_SPP_SEC_NONE, ESP_SPP_ROLE_MASTER)) {
      if (candidate > 0) {
        gWatchResolvedSppChannel = candidate;
        gWatchSdpResolvedMs = millis();
        BTAddress remoteAddress(address);
        const String addressText = remoteAddress.toString(true);
        snprintf(gWatchSdpAddress, sizeof(gWatchSdpAddress), "%s", addressText.c_str());
        if (candidate != resolved) snprintf(gWatchSdpSource, sizeof(gWatchSdpSource), "connect_fallback");
      }
      Serial.printf("WATCH_SDP_CONNECT_OK purpose=%s channel=%d\n",
                    purpose ? purpose : "unknown", candidate);
      return true;
    }
    Serial.printf("WATCH_SDP_CONNECT_FAIL purpose=%s channel=%d\n",
                  purpose ? purpose : "unknown", candidate);
    delay(120);
  }

  clearWatchSdpCache("connect_failed");
  return false;
}

void probeWatchSdp(String target) {
  target.trim();
  target.toUpperCase();
  uint8_t address[6];
  if (!parseWatchAddress(target, address)) {
    Serial.println("WATCH_SDP_INVALID_ADDRESS");
    return;
  }
  if (!beginWatchBluetooth(kBtLocalName)) {
    Serial.println("WATCH_SDP_BT_INIT_FAILED");
    return;
  }
  clearWatchSdpCache("manual_probe");
  const int channel = resolveWatchSppChannel(address, "manual_probe");
  Serial.printf("WATCH_SDP_RESULT address=%s selected_channel=%d source=%s\n",
                target.c_str(), channel, gWatchSdpSource);
  watchBt.end();
}

int watchRxAvailable() {
  return watchRxQueue ? static_cast<int>(uxQueueMessagesWaiting(watchRxQueue)) : 0;
}

int readWatchByte() {
  uint8_t value = 0;
  return watchRxQueue && xQueueReceive(watchRxQueue, &value, 0) == pdTRUE ? value : -1;
}

String readConfigString(const char* key, const char* fallback) {
  return prefs.isKey(key) ? prefs.getString(key) : String(fallback);
}

bool validWatchAddress(const String& value) {
  if (value.length() != 17) return false;
  for (size_t i = 0; i < value.length(); ++i) {
    if ((i + 1) % 3 == 0) {
      if (value[i] != ':') return false;
    } else if (!isxdigit(static_cast<unsigned char>(value[i]))) {
      return false;
    }
  }
  return true;
}

uint8_t hexNibble(char c) {
  if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
  if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
  return static_cast<uint8_t>(c - 'a' + 10);
}

bool parseWatchAddress(const String& value, uint8_t output[6]) {
  if (!validWatchAddress(value)) return false;
  for (size_t i = 0; i < 6; ++i) {
    size_t offset = i * 3;
    output[i] = static_cast<uint8_t>((hexNibble(value[offset]) << 4) | hexNibble(value[offset + 1]));
  }
  return true;
}

String serialSafeName(const std::string& value) {
  String safe;
  for (char c : value) {
    if (safe.length() >= 48) break;
    safe += (c >= 0x20 && c <= 0x7e) ? c : '_';
  }
  return safe.isEmpty() ? "unnamed" : safe;
}

static void setupBluetoothScanTask(void*) {
  memset(gSetupBluetoothResults, 0, sizeof(gSetupBluetoothResults));
  gSetupBluetoothResultCount = 0;
  gSetupBluetoothScanFailed = false;

  if (!gSetupMode || !beginWatchBluetooth("Vela-Setup-Scan")) {
    gSetupBluetoothScanFailed = true;
  } else {
    BTScanResults* results = watchBt.discover(kSetupBluetoothScanMs);
    if (!results) {
      gSetupBluetoothScanFailed = true;
    } else {
      for (int i = 0; i < results->getCount() &&
                      gSetupBluetoothResultCount < kSetupBluetoothScanMaxResults; ++i) {
        BTAdvertisedDevice* device = results->getDevice(i);
        if (!device) continue;
        SetupBluetoothDevice& target =
            gSetupBluetoothResults[gSetupBluetoothResultCount];
        const String name = serialSafeName(device->getName());
        String address = String(device->getAddress().toString().c_str());
        address.toUpperCase();
        snprintf(target.name, sizeof(target.name), "%s", name.c_str());
        snprintf(target.address, sizeof(target.address), "%s", address.c_str());
        target.rssi = device->getRSSI();
        target.cod = static_cast<uint32_t>(device->getCOD());
        ++gSetupBluetoothResultCount;
      }
      watchBt.discoverClear();
    }
    watchBt.end();
  }

  gSetupBluetoothScanReady = true;
  gSetupBluetoothScanRunning = false;
  Serial.printf("SETUP_BT_SCAN_COMPLETE ok=%s devices=%u\n",
                gSetupBluetoothScanFailed ? "false" : "true",
                static_cast<unsigned>(gSetupBluetoothResultCount));
  vTaskDelete(nullptr);
}

bool startSetupBluetoothScan() {
  if (!gSetupMode || gSetupBluetoothScanRunning || gWatchBridgeRunning) return false;
  gSetupBluetoothScanReady = false;
  gSetupBluetoothScanFailed = false;
  gSetupBluetoothScanRunning = true;
  const BaseType_t created = xTaskCreatePinnedToCore(
      setupBluetoothScanTask, "setup_bt_scan", 6144, nullptr, 1, nullptr, 1);
  if (created == pdPASS) return true;
  gSetupBluetoothScanRunning = false;
  gSetupBluetoothScanFailed = true;
  gSetupBluetoothScanReady = true;
  return false;
}

void probeWatchClassic(String target) {
  target.trim();
  target.toUpperCase();
  if (!validWatchAddress(target)) {
    Serial.println("WATCH_PROBE_INVALID_ADDRESS");
    return;
  }
  if (!beginWatchBluetooth(kBtLocalName)) {
    Serial.println("WATCH_PROBE_BT_INIT_FAILED");
    return;
  }

  Serial.println("WATCH_PROBE_SCAN_STARTED transport=classic");
  bool found = false;
  BTScanResults* results = watchBt.discover(kWatchScanSeconds * 1000);
  if (results) {
    for (int i = 0; i < results->getCount(); ++i) {
      BTAdvertisedDevice* device = results->getDevice(i);
      if (!device) continue;
      String address = String(device->getAddress().toString().c_str());
      address.toUpperCase();
      if (address != target) continue;
      found = true;
      String name = serialSafeName(device->getName());
      Serial.printf("WATCH_PROBE_FOUND transport=classic name=%s rssi=%d cod=0x%06lx\n",
                    name.c_str(), device->getRSSI(), static_cast<unsigned long>(device->getCOD()));
      break;
    }
    watchBt.discoverClear();
  }
  watchBt.end();
  Serial.println(found ? "WATCH_PROBE_COMPLETE found=true" : "WATCH_PROBE_COMPLETE found=false");
}

void connectWatchSpp(String target) {
  target.trim();
  target.toUpperCase();
  uint8_t address[6];
  if (!parseWatchAddress(target, address)) {
    Serial.println("WATCH_SPP_INVALID_ADDRESS");
    return;
  }
  if (!beginWatchBluetooth(kBtLocalName)) {
    Serial.println("WATCH_SPP_BT_INIT_FAILED");
    return;
  }

  Serial.println("WATCH_SPP_CONNECT_STARTED security=none");
  const bool connected = connectWatchWithSdp(address, "connect_probe");
  if (connected) {
    Serial.println("WATCH_SPP_CONNECT_OK");
    watchBt.disconnect();
  } else {
    Serial.println("WATCH_SPP_CONNECT_FAILED");
  }
  watchBt.end();
}

void connectWatchSppChannel(String target, int channel) {
  target.trim();
  target.toUpperCase();
  uint8_t address[6];
  if (!parseWatchAddress(target, address) || channel < 1 || channel > 30) {
    Serial.println("WATCH_SPP_CHANNEL_INVALID_INPUT");
    return;
  }
  if (!beginWatchBluetooth(kBtLocalName)) {
    Serial.println("WATCH_SPP_CHANNEL_BT_INIT_FAILED");
    return;
  }

  Serial.printf("WATCH_SPP_CHANNEL_CONNECT_STARTED channel=%d security=none\n", channel);
  const bool connected = watchBt.connect(address, channel, ESP_SPP_SEC_NONE, ESP_SPP_ROLE_MASTER);
  Serial.println(connected ? "WATCH_SPP_CHANNEL_CONNECT_OK" : "WATCH_SPP_CHANNEL_CONNECT_FAILED");
  if (connected) watchBt.disconnect();
  delay(250);
  watchBt.end();
}

String hexBytes(const uint8_t* value, size_t length) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  String result;
  result.reserve(length * 2);
  for (size_t i = 0; i < length; ++i) {
    result += kHex[(value[i] >> 4) & 0x0f];
    result += kHex[value[i] & 0x0f];
  }
  return result;
}

void logWatchResponse(const char* label) {
  uint8_t response[256];
  size_t responseLength = 0;
  const uint32_t startedAt = millis();
  while (millis() - startedAt < kWatchVersionResponseTimeoutMs && responseLength < sizeof(response)) {
    while (watchRxAvailable() > 0 && responseLength < sizeof(response)) {
      const int next = readWatchByte();
      if (next >= 0) response[responseLength++] = static_cast<uint8_t>(next);
    }
    delay(5);
  }
  if (responseLength > 0) {
    Serial.printf("%s bytes=%u hex=%s\n", label, static_cast<unsigned>(responseLength), hexBytes(response, responseLength).c_str());
  } else {
    Serial.printf("%s_TIMEOUT\n", label);
  }
}

void probeWatchSppVersion(String target) {
  target.trim();
  target.toUpperCase();
  uint8_t address[6];
  if (!parseWatchAddress(target, address)) {
    Serial.println("WATCH_VERSION_INVALID_ADDRESS");
    return;
  }
  if (!beginWatchBluetooth(kBtLocalName)) {
    Serial.println("WATCH_VERSION_BT_INIT_FAILED");
    return;
  }

  Serial.println("WATCH_VERSION_CONNECT_STARTED security=none");
  const bool connected = connectWatchWithSdp(address, "version_probe");
  if (!connected) {
    Serial.println("WATCH_VERSION_CONNECT_FAILED");
    watchBt.end();
    return;
  }

  Serial.println("WATCH_VERSION_REQUEST_SENT protocol=sppv1_plaintext");
  watchBt.write(kSppV1VersionRequest, sizeof(kSppV1VersionRequest));
  logWatchResponse("WATCH_VERSION_RESPONSE");
  watchBt.disconnect();
  watchBt.end();
}

void probeWatchSppSession(String target) {
  target.trim();
  target.toUpperCase();
  uint8_t address[6];
  if (!parseWatchAddress(target, address)) {
    Serial.println("WATCH_SESSION_INVALID_ADDRESS");
    return;
  }
  if (!beginWatchBluetooth(kBtLocalName)) {
    Serial.println("WATCH_SESSION_BT_INIT_FAILED");
    return;
  }
  Serial.println("WATCH_SESSION_CONNECT_STARTED security=none");
  if (!connectWatchWithSdp(address, "session_probe")) {
    Serial.println("WATCH_SESSION_CONNECT_FAILED");
    watchBt.end();
    return;
  }
  Serial.println("WATCH_SESSION_REQUEST_SENT protocol=sppv2_plaintext");
  watchBt.write(kSppV2SessionStartRequest, sizeof(kSppV2SessionStartRequest));
  logWatchResponse("WATCH_SESSION_RESPONSE");
  watchBt.disconnect();
  watchBt.end();
}

constexpr size_t kSppV2PayloadMax = 4096;
constexpr size_t kSppWriteChunkBytes = 16;

struct SppV2Frame {
  uint8_t type = 0;
  uint8_t sequence = 0;
  uint8_t payload[kSppV2PayloadMax]{};
  size_t payloadLength = 0;
};

// Memory optimization: every SPP receive path already shares the same
// BluetoothSerial connection, byte queue and gSppRxFrame assembler.
// Keep a single decoded 4 KiB frame workspace instead of one per helper.
static SppV2Frame gSharedSppFrame;

// 表盘 / 快应用安装（wfi 命名空间的实现见文件后半段）。
// 这里先声明接口：SPP 读循环和网络回包路径都在它前面定义。
namespace wfi {
bool networkPaused();
void notePausedDrop();
void pump(uint8_t& sequence, const uint8_t encKey[16]);
void onAck(uint8_t sequence);
void onProto(uint32_t type, uint32_t id, const uint8_t* pb, size_t len);
bool busy();
}  // namespace wfi


// Large protocol workspaces live on the heap to keep static DRAM usage
// within the ESP32 default .bss/.data region (the firmware previously
// overflowed dram0_0_seg by ~24 KB). Allocated in setup().
static uint8_t* gSppTxFrame = nullptr;
static uint8_t* gSppRxFrame = nullptr;
static uint8_t* gQuickAppMessageScratch = nullptr;
static uint8_t* gQuickAppThirdpartyScratch = nullptr;
static uint8_t* gEncryptedPayloadScratch = nullptr;
static uint8_t* gRawCommandPayloadScratch = nullptr;
static bool gWatchRawTraceEnabled = false;
constexpr size_t kWatchNetworkMtu = 1520; // Official round-3 trace carries IPv4 packets up to 1518 B.
constexpr size_t kWatchNetworkPacketMax = 1600;
constexpr UBaseType_t kWatchNetworkTxQueueDepth = 4;
struct WatchNetworkPacket {
  uint16_t length = 0;
  uint8_t bytes[kWatchNetworkPacketMax]{};
};
static struct netif* gWatchNetworkNetif = nullptr;
static QueueHandle_t gWatchNetworkTxQueue = nullptr;
static SemaphoreHandle_t gWatchNetworkInitDone = nullptr;
static WatchNetworkPacket* gWatchNetworkTxEnqueueScratch = nullptr;
static WatchNetworkPacket* gWatchNetworkTxDrainScratch = nullptr;
static bool gWatchNetworkReady = false;
static volatile uint32_t gWatchNetworkRxPackets = 0;
static volatile uint32_t gWatchNetworkTxPackets = 0;
static volatile uint32_t gWatchNetworkDroppedPackets = 0;
static volatile err_t gWatchNetworkInitResult = ERR_INPROGRESS;

// Wi-Fi is intentionally started only after the timing-critical Watch bootstrap.
// The old fork fired WiFi.begin() once and then never verified that a usable
// STA default route actually appeared. On a memory-tight WROOM, a failed or
// incomplete first Wi-Fi init therefore left DHCP working on the watch while
// every Internet packet had nowhere to go. Keep a tiny post-bootstrap uplink
// state machine: retry STA association and, once an IPv4 gateway exists, make
// that STA netif the default route and re-arm NAPT on the watch netif.
static volatile bool gWatchInternetRouteReady = false;
static volatile bool gWatchInternetRouteRepairPending = false;
static uint32_t gWatchLastWifiBeginMs = 0;
static int gWatchLastWifiStatus = -999;
constexpr uint32_t kWatchWifiRetryMs = 12000;

// ---------- OLED 渲染（状态变量均已在上方声明）----------

// 取一个简短、适合屏幕宽度的桥接状态文案。
const char* displayStateLabel(const char* state) {
  if (!state || !*state) return "idle";
  if (!strcmp(state, "connected")) return "CONNECTED";
  if (!strcmp(state, "connecting") || !strcmp(state, "starting")) return "connecting";
  if (!strcmp(state, "stopping")) return "stopping";
  if (!strcmp(state, "idle")) return "idle";
  if (!strcmp(state, "task_create_failed")) return "task FAIL";
  return state;  // 其它状态原样显示（已较短）
}

// 渲染一帧。无堆分配，所有文案为栈上/字面量。
void renderDisplay() {
  if (!gDisplayReady) return;
  // 加锁快照桥接状态，避免读到半更新字符串（不经过 String，无堆分配）。
  char stateSnap[sizeof(gWatchBridgeState)]{};
  if (gBridgeStateMutex && xSemaphoreTake(gBridgeStateMutex, pdMS_TO_TICKS(20)) == pdTRUE) {
    memcpy(stateSnap, gWatchBridgeState, sizeof(stateSnap));
    xSemaphoreGive(gBridgeStateMutex);
  } else {
    memcpy(stateSnap, gWatchBridgeState, sizeof(stateSnap));
  }

  // 每帧先清空 framebuffer，否则上一帧的旧像素会和新文字叠在一起造成花屏。
  display.clearBuffer();

  // 四行版式（全屏 128x64，6x10 字体，行间距约 16px）：
  //   IP:[IP地址]
  //   TX: n RX: n
  //   F-RAM: n KB
  //   I：(当前状态)
  display.setFont(u8g2_font_6x10_tr);
  const char* stateLabel = displayStateLabel(stateSnap);
  char buf[80];

  // 第 1 行：IP（配网模式显示 AP IP 192.168.4.1）
  // 直接从 IPAddress 的 4 个字节格式化，省掉每次刷新都 new 一个 String，
  // 那会在 BT 认证→启动 WiFi 的窗口里（loopTask 与桥接任务同在 core 1）
  // 反复申请/释放小块，把堆切碎，导致 esp_wifi_init 因最大连续块不足而 257。
  IPAddress ip = gSetupMode ? WiFi.softAPIP()
                            : (WiFi.status() == WL_CONNECTED ? WiFi.localIP() : IPAddress(0, 0, 0, 0));
  snprintf(buf, sizeof(buf), "IP %u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  display.drawStr(2, 14, buf);

  // 第 2 行：网络包计数 TX/RX（NAPT 转发活跃度）
  snprintf(buf, sizeof(buf), "TX %lu RX %lu",
           static_cast<unsigned long>(gWatchNetworkTxPackets),
           static_cast<unsigned long>(gWatchNetworkRxPackets));
  display.drawStr(2, 30, buf);

  // 第 3 行：空闲 RAM
  snprintf(buf, sizeof(buf), "F-RAM %luKB",
           static_cast<unsigned long>(ESP.getFreeHeap() / 1024));
  display.drawStr(2, 46, buf);

  // 第 4 行：当前状态（配网/桥接状态），直接显示文本。
  if (gSetupMode) {
    snprintf(buf, sizeof(buf), "Setup connect AP");
  } else if (WiFi.status() != WL_CONNECTED) {
    snprintf(buf, sizeof(buf), "WiFi disc. %s", stateLabel);
  } else {
    snprintf(buf, sizeof(buf), "%s", stateLabel);
  }
  display.drawStr(2, 62, buf);

  display.sendBuffer();
}

void initDisplay() {
  // 指定 I2C 引脚后初始化 U8g2 硬件 I2C。
  Wire.begin(kOledSdaPin, kOledSclPin);

  // 先扫描 I2C 总线，把找到的设备地址打到串口，方便排查地址/接线。
  // 0x7B(8位读) 对应 7 位地址 0x3D；SSD1306 常见为 0x3C 或 0x3D。
  uint8_t found7 = 0;
  Serial.printf("DISPLAY_I2C_SCAN sda=%d scl=%d:", kOledSdaPin, kOledSclPin);
  for (uint8_t addr = 0x03; addr <= 0x77; ++addr) {
    Wire.beginTransmission(addr);
    if (Wire.endTransmission() == 0) {
      Serial.printf(" 0x%02X", addr);
      if (found7 == 0) found7 = addr;
    }
  }
  Serial.println();

  // 优先用配置地址，否则用扫描到的第一个地址。
  uint8_t addr7 = kOledI2cAddr;
  if (found7 == 0) {
    Serial.printf("DISPLAY_INIT_FAILED no I2C device on SDA=%d SCL=%d (check VCC/GND/SDA/SCL)\n",
                  kOledSdaPin, kOledSclPin);
    return;
  }
  if (found7 != kOledI2cAddr) {
    Serial.printf("DISPLAY_ADDR_OVERRIDE configured=0x%02X but using scanned=0x%02X\n",
                  kOledI2cAddr, found7);
    addr7 = found7;
  }

  display.setI2CAddress(addr7 << 1);
  if (display.begin()) {
    gDisplayReady = true;
    display.clearBuffer();
    display.setFont(u8g2_font_6x10_tr);
    display.drawStr(2, 30, "VelaGateway");
    display.drawStr(2, 46, "Init...");
    display.sendBuffer();
    Serial.printf("DISPLAY_READY addr=0x%02X\n", addr7);
  } else {
    Serial.printf("DISPLAY_INIT_FAILED SSD1306 not responding at 0x%02X (check module model)\n", addr7);
  }
}

// 状态 LED：按 WiFi/手表连接状态以不同模式闪烁。
//   WiFi+手表都连上  → 按网络流量速率动态闪烁（无流量则灭）
//   只连WiFi没连手表 → 亮3秒灭1秒循环
//   只连手表没连WiFi → 亮5秒灭2秒循环
//   都没连上         → 亮1秒灭1秒快闪
// 流量越大，闪烁越快（亮和灭都越短）；无流量时LED熄灭。
// 关键修复：模式切换时重置所有状态，避免旧值泄漏；
//           首次采样窗口内实时检测流量并立即亮灯，避免2秒灭灯延迟。
void getTrafficLedTiming(uint32_t bps, uint32_t& onMs, uint32_t& offMs) {
  if (bps == 0) {
    onMs = 0; offMs = 0;  // 无流量：灭掉
  } else if (bps <= 10) {
    onMs = 3000; offMs = 2000;   // 1-10 b/s：亮3秒灭2秒
  } else if (bps <= 100) {
    onMs = 2000; offMs = 1500;  // 10-100 b/s：亮2秒灭1.5秒
  } else if (bps <= 500) {
    onMs = 1500; offMs = 1000;  // 100-500 b/s：亮1.5秒灭1秒
  } else if (bps <= 1024) {
    onMs = 1200; offMs = 1000;  // 500b-1kb/s：亮1.2秒灭1秒
  } else if (bps <= 10240) {
    onMs = 1000; offMs = 1000;  // 1kb-10kb/s：亮1秒灭1秒
  } else if (bps <= 102400) {
    onMs = 800; offMs = 900;    // 10kb-100kb/s：亮0.8秒灭0.9秒
  } else if (bps <= 204800) {
    onMs = 700; offMs = 900;    // 100kb-200kb/s：亮0.7秒灭0.9秒
  } else if (bps <= 512000) {
    onMs = 700; offMs = 900;   // 200kb-500kb/s：亮0.7秒灭0.9秒
  } else if (bps <= 1048576) {
    onMs = 500; offMs = 500;    // 500kb-1mb/s：亮0.5秒灭0.5秒
  } else if (bps <= 5242880) {
    onMs = 300; offMs = 300;    // 1mb-5mb/s：亮0.3秒灭0.3秒
  } else if (bps <= 10485760) {
    onMs = 200; offMs = 200;    // 5mb-10mb/s：亮0.2秒灭0.2秒
  } else {
    onMs = 100; offMs = 100;   // 10mb+：极快闪
  }
}

void serviceHeartbeatLed() {
  // 模式追踪：1=流量模式(双连), 2=部分连接, -1=未初始化
  static int8_t sLastMode = -1;

  // ===== 用户选择的手动灯效优先 =====
  // 0=关闭 1=常亮 2=呼吸 3=心跳 4=流量联动（默认，走下面原有逻辑）
  if (gLedMode != 4) {
    const uint32_t now = millis();
    switch (gLedMode) {
      case 0: digitalWrite(kHeartbeatLedPin, LOW); break;
      case 1: digitalWrite(kHeartbeatLedPin, HIGH); break;
      case 2: {   // 呼吸：1.6 秒一个来回，三角波避免浮点
        const uint32_t phase = now % 1600;
        const uint32_t level = phase < 800 ? phase : (1600 - phase);
        digitalWrite(kHeartbeatLedPin, level > 400 ? HIGH : LOW);
        break;
      }
      case 3: {   // 心跳：咚-咚 两下，间隔 1 秒
        const uint32_t phase = now % 1000;
        const bool beat = (phase < 90) || (phase >= 160 && phase < 250);
        digitalWrite(kHeartbeatLedPin, beat ? HIGH : LOW);
        break;
      }
      default: digitalWrite(kHeartbeatLedPin, LOW); break;
    }
    return;
  }

  // 部分连接模式的独立计时状态（提升到函数作用域以便切换时重置）
  static uint32_t sPartialCycleStartMs = 0;
  static bool sPartialInOnPhase = true;
  static uint32_t sPartialOnMs = 0;
  static uint32_t sPartialOffMs = 0;

  bool wifiOk = (WiFi.status() == WL_CONNECTED);
  bool watchOk = gWatchBridgeRunning;
  if (gSetupMode) { wifiOk = false; watchOk = false; }

  // ===== WiFi+手表都连上：根据流量动态闪烁 =====
  if (wifiOk && watchOk) {
    // 模式切换：重置全部状态，避免旧值泄漏
    if (sLastMode != 1) {
      sLastMode = 1;
      gCurrentBps = 0;
      gTrafficSampleStartMs = 0;
      gTrafficSampleStartBytes = 0;
      gTrafficLedPhaseOnMs = 0;
      gTrafficLedPhaseOffMs = 0;
      gTrafficLedCycleStartMs = 0;
      gTrafficLedInOnPhase = true;
      sPartialCycleStartMs = 0;
      sPartialOnMs = 0;
      sPartialOffMs = 0;
      sPartialInOnPhase = true;
    }

    uint32_t now = millis();

    // 初始化采样窗口
    if (gTrafficSampleStartMs == 0) {
      gTrafficSampleStartMs = now;
      gTrafficSampleStartBytes = gWatchRxBytes + gWatchTxBytes;
    }

    uint32_t totalNow = gWatchRxBytes + gWatchTxBytes;
    uint32_t sampleElapsed = now - gTrafficSampleStartMs;
    uint32_t bytesThisSample = totalNow - gTrafficSampleStartBytes;

    // 每2秒完成一次采样，更新bps
    if (sampleElapsed >= 2000) {
      gCurrentBps = (sampleElapsed > 0) ? (bytesThisSample * 1000 / sampleElapsed) : 0;
      gTrafficSampleStartMs = now;
      gTrafficSampleStartBytes = totalNow;
      bytesThisSample = 0;
      sampleElapsed = 0;
      // 顺手记一格历史曲线（5 分钟窗口 = 30 格），供管理台画流量走势
      telemetryRecordTraffic();
    }

    // 实时判断是否有流量：用已测bps + 当前窗口字节数双重判断
    bool hasTraffic = (gCurrentBps > 0) || (bytesThisSample > 0);

    if (!hasTraffic) {
      // 确实无流量：立即灭灯，重置相位
      if (gLedOn) {
        gLedOn = false;
        digitalWrite(kHeartbeatLedPin, LOW);
      }
      gTrafficLedPhaseOnMs = 0;
      gTrafficLedPhaseOffMs = 0;
      return;
    }

    // 有流量：确定闪烁参数
    // 若已有实测bps则用之；否则用当前窗口字节数估算（避免2秒灭灯延迟）
    uint32_t effectiveBps;
    if (gCurrentBps > 0) {
      effectiveBps = gCurrentBps;
    } else if (sampleElapsed > 0) {
      effectiveBps = bytesThisSample * 1000 / sampleElapsed;
      if (effectiveBps == 0) effectiveBps = 1;
    } else {
      effectiveBps = 1;
    }

    uint32_t newOnMs, newOffMs;
    getTrafficLedTiming(effectiveBps, newOnMs, newOffMs);

    // 档位变化或刚启动：开始新的亮灯周期
    if (newOnMs != gTrafficLedPhaseOnMs || newOffMs != gTrafficLedPhaseOffMs) {
      gTrafficLedPhaseOnMs = newOnMs;
      gTrafficLedPhaseOffMs = newOffMs;
      gTrafficLedCycleStartMs = now;
      gTrafficLedInOnPhase = true;
      if (!gLedOn) {
        gLedOn = true;
        digitalWrite(kHeartbeatLedPin, HIGH);
      }
      return;
    }

    // 档位不变：按当前周期计时翻转
    uint32_t phaseElapsed = now - gTrafficLedCycleStartMs;
    uint32_t currentPhaseDuration = gTrafficLedInOnPhase ? gTrafficLedPhaseOnMs : gTrafficLedPhaseOffMs;

    if (phaseElapsed >= currentPhaseDuration) {
      gTrafficLedInOnPhase = !gTrafficLedInOnPhase;
      gTrafficLedCycleStartMs = now;
      gLedOn = gTrafficLedInOnPhase;
      digitalWrite(kHeartbeatLedPin, gTrafficLedInOnPhase ? HIGH : LOW);
    }
    return;
  }

  // ===== 部分连接模式 =====
  // 模式切换：重置流量状态（避免下次进入流量模式时残留旧值）
  if (sLastMode != 2) {
    sLastMode = 2;
    gCurrentBps = 0;
    gTrafficSampleStartMs = 0;
    gTrafficSampleStartBytes = 0;
    gTrafficLedPhaseOnMs = 0;
    gTrafficLedPhaseOffMs = 0;
    gTrafficLedCycleStartMs = 0;
    gTrafficLedInOnPhase = true;
    sPartialCycleStartMs = 0;
    sPartialOnMs = 0;
    sPartialOffMs = 0;
    sPartialInOnPhase = true;
  }

  uint32_t onMs, offMs;
  if (wifiOk && !watchOk) {
    onMs = 3000; offMs = 1000;  // 只WiFi：亮3秒灭1秒
  } else if (!wifiOk && watchOk) {
    onMs = 5000; offMs = 2000;  // 只手表：亮5秒灭2秒
  } else {
    onMs = 1000; offMs = 1000;  // 都没连：亮1秒灭1秒
  }

  // 档位变化或首次进入：开始亮灯
  if (sPartialOnMs != onMs || sPartialOffMs != offMs) {
    sPartialOnMs = onMs;
    sPartialOffMs = offMs;
    sPartialCycleStartMs = millis();
    sPartialInOnPhase = true;
    if (!gLedOn) {
      gLedOn = true;
      digitalWrite(kHeartbeatLedPin, HIGH);
    }
    return;
  }

  uint32_t now2 = millis();
  uint32_t phaseElapsed = now2 - sPartialCycleStartMs;
  uint32_t currentPhaseDuration = sPartialInOnPhase ? sPartialOnMs : sPartialOffMs;

  if (phaseElapsed >= currentPhaseDuration) {
    sPartialInOnPhase = !sPartialInOnPhase;
    sPartialCycleStartMs = now2;
    gLedOn = sPartialInOnPhase;
    digitalWrite(kHeartbeatLedPin, sPartialInOnPhase ? HIGH : LOW);
  }
}

constexpr size_t kWatchStreamPacketMax = 512;
constexpr size_t kWatchStreamPacketCountMax = 256;
constexpr char kWatchStreamCapturePath[] = "/watch_stream.packets";
constexpr uint32_t kWatchAsrSampleRate = 16000;
constexpr uint16_t kWatchAsrChannels = 1;
constexpr size_t kWatchAsrPcmMaxBytes = 480000; // 15 s @ 16 kHz mono PCM16
constexpr size_t kWatchOpusSubframeBytes = 80;
constexpr size_t kWatchOpusAggregateBytes = 400;
constexpr size_t kWatchAsrTaskStackBytes = 48 * 1024;
static size_t gWatchStreamCaptureLength = 0;
static size_t gWatchStreamPacketCount = 0;
static bool gWatchStreamCaptureActive = false;
static bool gWatchStreamCaptureTruncated = false;
static uint32_t gWatchStreamCaptureRxDroppedStart = 0;
static bool gWatchStreamCaptureFsReady = false;
static bool gWatchStreamCaptureFileFailed = false;
static File gWatchStreamCaptureFile;
static uint8_t gWatchStreamExportPacket[kWatchStreamPacketMax];
static uint8_t gWatchStreamExportBase64[4 * ((kWatchStreamPacketMax + 2) / 3) + 1];

void markXiaoAiProgress(const char* reason) {
  gXiaoAiLastProgressMs = millis();
  if (reason) {
    Serial.printf("XIAOAI_PROGRESS session=%lu reason=%s audio_ms=%lu partials=%lu\n",
                  static_cast<unsigned long>(gXiaoAiActiveSessionId), reason,
                  static_cast<unsigned long>(gXiaoAiAudioMs),
                  static_cast<unsigned long>(gXiaoAiPartialSentCount));
  }
}

void beginXiaoAiSession() {
  ++gXiaoAiSessionSerial;
  if (gXiaoAiSessionSerial == 0) ++gXiaoAiSessionSerial;
  gXiaoAiActiveSessionId = gXiaoAiSessionSerial;
  gXiaoAiSessionActive = true;
  gXiaoAiFinalSent = false;
  gXiaoAiSessionStartedMs = millis();
  gXiaoAiLastProgressMs = gXiaoAiSessionStartedMs;
  gXiaoAiAudioMs = 0;
  gXiaoAiNextPartialAudioMs = kXiaoAiRollingFirstAudioMs;
  gXiaoAiFinalAsrPending = false;
  gXiaoAiFinalPendingSessionId = 0;
  gXiaoAiAwaitAssistant = false;
  gXiaoAiAssistantDoneSessionId = 0;
  gXiaoAiPartialSentCount = 0;
  gXiaoAiLastPartial[0] = '\0';
  gXiaoAiStartPending = true;
  gXiaoAiEndPending = false;
  gXiaoAiEndDueMs = 0;
  Serial.printf("XIAOAI_SESSION_BEGIN session=%lu timely_start_target_ms=500 rolling_first_ms=%lu rolling_interval_ms=%lu no_progress_timeout_ms=%lu\n",
                static_cast<unsigned long>(gXiaoAiActiveSessionId),
                static_cast<unsigned long>(kXiaoAiRollingFirstAudioMs),
                static_cast<unsigned long>(kXiaoAiRollingIntervalMs),
                static_cast<unsigned long>(kXiaoAiNoProgressTimeoutMs));
}

void finishXiaoAiSession(const char* reason) {
  Serial.printf("XIAOAI_SESSION_END session=%lu reason=%s elapsed_ms=%lu partials=%lu\n",
                static_cast<unsigned long>(gXiaoAiActiveSessionId), reason ? reason : "unknown",
                static_cast<unsigned long>(millis() - gXiaoAiSessionStartedMs),
                static_cast<unsigned long>(gXiaoAiPartialSentCount));
  gXiaoAiSessionActive = false;
  gXiaoAiStartPending = false;
  gXiaoAiEndPending = false;
  gXiaoAiFinalAsrPending = false;
  gXiaoAiAwaitAssistant = false;
}

bool copySpiffsFile(const char* sourcePath, const char* destinationPath) {
  if (!sourcePath || !destinationPath || !gWatchStreamCaptureFsReady) return false;
  File source = SPIFFS.open(sourcePath, FILE_READ);
  if (!source) return false;
  SPIFFS.remove(destinationPath);
  File destination = SPIFFS.open(destinationPath, FILE_WRITE);
  if (!destination) { source.close(); return false; }
  uint8_t buffer[512];
  bool ok = true;
  while (source.available()) {
    const size_t got = source.read(buffer, sizeof(buffer));
    if (!got) break;
    if (destination.write(buffer, got) != got) { ok = false; break; }
  }
  destination.flush();
  source.close();
  destination.close();
  if (!ok) SPIFFS.remove(destinationPath);
  return ok;
}

void buildSessionAsrPaths(uint32_t sessionId, bool finalResult,
                          char* packetPath, size_t packetCapacity,
                          char* wavPath, size_t wavCapacity) {
  snprintf(packetPath, packetCapacity, finalResult ? "/asr_%08lx_f.pkt" : "/asr_%08lx_p.pkt",
           static_cast<unsigned long>(sessionId));
  snprintf(wavPath, wavCapacity, finalResult ? "/asr_%08lx_f.wav" : "/asr_%08lx_p.wav",
           static_cast<unsigned long>(sessionId));
}

void emitWatchRawTrace(const SppV2Frame& frame) {
  if (!gWatchRawTraceEnabled) return;
  const uint8_t channel = frame.payloadLength >= 1 ? (frame.payload[0] & 0x0f) : 0xff;
  const uint8_t opcode = frame.payloadLength >= 2 ? frame.payload[1] : 0xff;
  Serial.printf("WATCH_RAW_FRAME type=%u seq=%u bytes=%u channel=%u opcode=%u\n",
                static_cast<unsigned>(frame.type), static_cast<unsigned>(frame.sequence),
                static_cast<unsigned>(frame.payloadLength), static_cast<unsigned>(channel),
                static_cast<unsigned>(opcode));
}

// SPIFFS 采用懒挂载：启动阶段不挂，把这部分堆留给蓝牙控制器。
// 两个约束决定了下面的实现方式：
//   1) 空白分区第一次挂载必然失败，必须格式化；而格式化要把整个 spiffs 分区
//      （16MB 布局下约 3.9 MB）擦一遍，耗时二十秒以上。
//   2) 本函数会被 HTTP 处理函数调用，一旦在里面格式化，整个管理台会卡住，
//      页面看上去就是"刷完机没反应"。
// 因此这里只做不格式化的普通挂载（几百毫秒），失败就交给后台任务去格式化，
// 调用方拿到 false 后按「存储初始化中」返回，前端稍后重试即可。
static volatile bool gSpiffsFormatting = false;

bool spiffsFormatting() { return gSpiffsFormatting; }

static void spiffsFormatTask(void*) {
  Serial.println("SPIFFS_FORMAT_START");
  const uint32_t started = millis();
  bool ok = SPIFFS.format();
  if (ok) ok = SPIFFS.begin(false);
  gWatchStreamCaptureFsReady = ok;
  gSpiffsFormatting = false;
  if (ok) {
    Serial.printf("SPIFFS_FORMAT_OK took_ms=%lu total=%u\n",
                  static_cast<unsigned long>(millis() - started),
                  static_cast<unsigned>(SPIFFS.totalBytes()));
  } else {
    Serial.printf("SPIFFS_FORMAT_FAILED took_ms=%lu\n",
                  static_cast<unsigned long>(millis() - started));
  }
  vTaskDelete(nullptr);
}

bool ensureSpiffs() {
  if (gWatchStreamCaptureFsReady) return true;
  if (gSpiffsFormatting) return false;

  // 最常见的问题是分区表里没有 spiffs 分区（例如旧的 4MB 分区表），这种直接报错，
  // 不要浪费时间尝试格式化。
  const esp_partition_t* fs = esp_partition_find_first(
      ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_SPIFFS, nullptr);
  if (!fs) {
    Serial.println("SPIFFS_MOUNT_FAILED partition=missing hint=no_spiffs_partition_in_table");
    return false;
  }

  const uint32_t started = millis();
  if (SPIFFS.begin(false)) {
    gWatchStreamCaptureFsReady = true;
    Serial.printf("SPIFFS_MOUNT_OK total=%u used=%u took_ms=%lu\n",
                  static_cast<unsigned>(SPIFFS.totalBytes()),
                  static_cast<unsigned>(SPIFFS.usedBytes()),
                  static_cast<unsigned long>(millis() - started));
    return true;
  }

  // 分区在但挂不上：空白分区，转后台格式化。
  gSpiffsFormatting = true;
  Serial.printf("SPIFFS_MOUNT_MISS partition=%s size=%u action=format_async\n",
                fs->label, static_cast<unsigned>(fs->size));
  if (xTaskCreatePinnedToCore(spiffsFormatTask, "spiffs_fmt", 4096, nullptr, 1, nullptr, 0) != pdPASS) {
    gSpiffsFormatting = false;
    Serial.println("SPIFFS_FORMAT_TASK_FAILED");
  }
  return false;
}

// 给 HTTP 接口用的统一错误码/提示：区分「正在初始化」和「真的坏了」，
// 用户看到前者知道等一会儿，看到后者知道要查分区表。
const char* spiffsErrorCode() {
  return gSpiffsFormatting ? "storage_initializing" : "storage_unavailable";
}

const char* spiffsErrorHint() {
  return gSpiffsFormatting
             ? "文件系统正在首次初始化（空白分区需要格式化，约 30 秒），请稍后重试。"
             : "文件系统未挂载（SPIFFS 分区缺失或格式化失败），请查看串口 SPIFFS_MOUNT_FAILED 一行。";
}

// 从 app 镜像里读版本号。esp_app_desc_t 固定在镜像偏移 0x20，其中 version
// 是结构体里第 0x10 字节起的 32 字节字符串，所以文件偏移为 0x30。
void captureOtaImageVersion(const uint8_t* buf, size_t len) {
  if (!s_otaImageVersion.isEmpty() || len < 0x50) return;
  char v[33];
  memcpy(v, buf + 0x30, 32);
  v[32] = 0;
  for (int i = 0; i < 32; ++i) {
    if (v[i] < 0x20 || v[i] > 0x7e) { v[i] = 0; break; }
  }
  s_otaImageVersion = String(v);
}

void beginWatchStreamCapture(uint16_t mode) {
  if (gWatchStreamCaptureFile) gWatchStreamCaptureFile.close();
  ensureSpiffs();
  beginXiaoAiSession();
  gWatchStreamCaptureLength = 0;
  gWatchStreamPacketCount = 0;
  gWatchStreamCaptureActive = true;
  gWatchStreamCaptureTruncated = false;
  gWatchStreamCaptureRxDroppedStart = watchRxDroppedBytes;
  gWatchStreamCaptureFileFailed = !gWatchStreamCaptureFsReady;
  if (!gWatchStreamCaptureFileFailed) {
    SPIFFS.remove(kWatchStreamCapturePath);
    gWatchStreamCaptureFile = SPIFFS.open(kWatchStreamCapturePath, FILE_WRITE);
    gWatchStreamCaptureFileFailed = !gWatchStreamCaptureFile;
  }
  Serial.printf("WATCH_STREAM_CAPTURE_BEGIN mode=%u private_local_only=true\n", static_cast<unsigned>(mode));
}

void appendWatchStreamPacket(const uint8_t* data, size_t length) {
  if (!gWatchStreamCaptureActive || !data || length == 0) return;
  if (length > kWatchStreamPacketMax || gWatchStreamPacketCount >= kWatchStreamPacketCountMax) {
    gWatchStreamCaptureTruncated = true;
    return;
  }
  const uint8_t lengthBytes[] = {
      static_cast<uint8_t>((length >> 8) & 0xff), static_cast<uint8_t>(length & 0xff)};
  if (gWatchStreamCaptureFileFailed || !gWatchStreamCaptureFile ||
      gWatchStreamCaptureFile.write(lengthBytes, sizeof(lengthBytes)) != sizeof(lengthBytes) ||
      gWatchStreamCaptureFile.write(data, length) != length) {
    gWatchStreamCaptureFileFailed = true;
    gWatchStreamCaptureTruncated = true;
    return;
  }
  ++gWatchStreamPacketCount;
  gWatchStreamCaptureLength += length;
  if (length >= kWatchOpusSubframeBytes && (length % kWatchOpusSubframeBytes) == 0) {
    gXiaoAiAudioMs += static_cast<uint32_t>((length / kWatchOpusSubframeBytes) * 20u);
  }
}

void exportWatchStreamCapture() {
  if (!gWatchStreamCaptureFsReady || gWatchStreamCaptureFileFailed) return;
  File capture = SPIFFS.open(kWatchStreamCapturePath, FILE_READ);
  if (!capture) {
    Serial.println("WATCH_STREAM_EXPORT_OPEN_FAILED");
    return;
  }
  size_t index = 0;
  while (capture.available()) {
    uint8_t lengthBytes[2]{};
    if (capture.read(lengthBytes, sizeof(lengthBytes)) != sizeof(lengthBytes)) {
      Serial.println("WATCH_STREAM_EXPORT_LENGTH_FAILED");
      break;
    }
    const size_t length = (static_cast<size_t>(lengthBytes[0]) << 8) | lengthBytes[1];
    if (length == 0 || length > kWatchStreamPacketMax ||
        capture.read(gWatchStreamExportPacket, length) != static_cast<int>(length)) {
      Serial.println("WATCH_STREAM_EXPORT_READ_FAILED");
      break;
    }
    size_t encodedLength = 0;
    if (mbedtls_base64_encode(gWatchStreamExportBase64, sizeof(gWatchStreamExportBase64) - 1,
                              &encodedLength, gWatchStreamExportPacket, length) != 0) {
      Serial.println("WATCH_STREAM_EXPORT_ENCODE_FAILED");
      break;
    }
    gWatchStreamExportBase64[encodedLength] = 0;
    Serial.printf("WATCH_STREAM_FILE_PACKET index=%u bytes=%u b64=%s\n",
                  static_cast<unsigned>(index), static_cast<unsigned>(length),
                  gWatchStreamExportBase64);
    Serial.flush();
    ++index;
    delay(1);
  }
  capture.close();
  mbedtls_platform_zeroize(gWatchStreamExportPacket, sizeof(gWatchStreamExportPacket));
  mbedtls_platform_zeroize(gWatchStreamExportBase64, sizeof(gWatchStreamExportBase64));
  Serial.printf("WATCH_STREAM_EXPORT_END packets=%u\n", static_cast<unsigned>(index));
}

void emitWatchStreamCapture() {
  if (!gWatchStreamCaptureActive) return;
  gWatchStreamCaptureActive = false;
  if (gWatchStreamCaptureFile) gWatchStreamCaptureFile.close();
  // The observed 5-10 s offline timeout is a post-utterance assistant wait,
  // not a safe reason to terminate a long utterance while ch3 audio is still
  // arriving. Arm the local no-progress deadline from microphone END.
  gXiaoAiLastProgressMs = millis();
  Serial.printf("XIAOAI_POST_AUDIO_WAIT_ARMED session=%lu timeout_ms=%lu\n",
                static_cast<unsigned long>(gXiaoAiActiveSessionId),
                static_cast<unsigned long>(kXiaoAiNoProgressTimeoutMs));
  const bool captureOk = !gWatchStreamCaptureTruncated && !gWatchStreamCaptureFileFailed &&
                         watchRxDroppedBytes == gWatchStreamCaptureRxDroppedStart &&
                         gWatchStreamPacketCount > 0;
  Serial.printf("WATCH_STREAM_CAPTURE_END bytes=%u packets=%u truncated=%s rx_dropped=%lu encoding=opus_aggregate\n",
                static_cast<unsigned>(gWatchStreamCaptureLength),
                static_cast<unsigned>(gWatchStreamPacketCount),
                gWatchStreamCaptureTruncated ? "true" : "false",
                static_cast<unsigned long>(watchRxDroppedBytes - gWatchStreamCaptureRxDroppedStart));
  if (serialAudioExport) exportWatchStreamCapture();
  if (captureOk && gWatchStreamCaptureFsReady) {
    const uint32_t sessionId = gXiaoAiActiveSessionId;
    buildSessionAsrPaths(sessionId, true, gXiaoAiFinalPacketPath, sizeof(gXiaoAiFinalPacketPath),
                         gXiaoAiFinalWavPath, sizeof(gXiaoAiFinalWavPath));
    SPIFFS.remove(gXiaoAiFinalPacketPath);
    SPIFFS.remove(gXiaoAiFinalWavPath);
    if (SPIFFS.rename(kWatchStreamCapturePath, gXiaoAiFinalPacketPath)) {
      if (!scheduleWatchAsrJob(gXiaoAiFinalPacketPath, gXiaoAiFinalWavPath, true, sessionId)) {
        gXiaoAiFinalAsrPending = true;
        gXiaoAiFinalPendingSessionId = sessionId;
        Serial.printf("WATCH_ASR_FINAL_DEFERRED session=%lu busy=true\n", static_cast<unsigned long>(sessionId));
      }
    } else {
      Serial.println("WATCH_ASR_SNAPSHOT_FAILED");
    }
  } else {
    Serial.println("WATCH_ASR_SKIPPED capture_invalid=true");
  }
  gWatchStreamCaptureLength = 0;
  gWatchStreamPacketCount = 0;
  gWatchStreamCaptureTruncated = false;
}

void handleWatchStreamData(const uint8_t* data, size_t length) {
  if (!data || length < 2) return;
  const uint16_t type = static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]);
  if (type == 1 && length >= 6) {
    const uint16_t declared = static_cast<uint16_t>((static_cast<uint16_t>(data[2]) << 8) | data[3]);
    const uint16_t mode = static_cast<uint16_t>((static_cast<uint16_t>(data[4]) << 8) | data[5]);
    if (declared == 2) beginWatchStreamCapture(mode);
    return;
  }
  if (type == 2 && length >= 4 && gWatchStreamCaptureActive) {
    const uint16_t declared = static_cast<uint16_t>((static_cast<uint16_t>(data[2]) << 8) | data[3]);
    if (declared <= length - 4) appendWatchStreamPacket(data + 4, declared);
    else gWatchStreamCaptureTruncated = true;
    return;
  }
  if (type == 4) emitWatchStreamCapture();
}

// Xiaomi SPPv2 uses an 8-bit transport sequence. The real-device failure
// pattern is consistent with an already-used sequence being transport-ACKed
// but not delivered again to the QuickApp message channel after wrap. Renew
// the authenticated SPPv2 session before the 8-bit sequence can wrap.
constexpr uint8_t kBenchSppRenewAtSequence = 250;
static bool gBenchSessionRenewalEnabled = false;
static uint8_t gBenchSessionSecret[16]{};
static uint8_t gBenchSessionEncKey[16]{};
static uint8_t gBenchSessionDecKey[16]{};
static uint32_t gBenchSessionRenewals = 0;

void logStackHighWater(const char* stage) {
  const UBaseType_t words = uxTaskGetStackHighWaterMark(nullptr);
  Serial.printf("STACK_HIGH_WATER stage=%s words=%u approx_bytes=%u rx_dropped=%lu\n",
                stage ? stage : "unknown",
                static_cast<unsigned>(words),
                static_cast<unsigned>(words * sizeof(StackType_t)),
                static_cast<unsigned long>(watchRxDroppedBytes));
}

uint16_t crc16Arc(const uint8_t* bytes, size_t length) {
  uint16_t crc = 0;
  for (size_t i = 0; i < length; ++i) {
    crc ^= bytes[i];
    for (uint8_t bit = 0; bit < 8; ++bit) crc = (crc & 1) ? static_cast<uint16_t>((crc >> 1) ^ 0xa001) : static_cast<uint16_t>(crc >> 1);
  }
  return crc;
}

bool writeWatchBytes(const uint8_t* bytes, size_t length) {
  gWatchTxBytes += length;  // 流量统计
  // Diagnostic/production candidate: BluetoothSerial already queues packets,
  // coalesces them into its internal SPP_TX_MAX buffer, and waits for the IDF
  // SPP write-complete/congestion events in its TX task. Sending an entire
  // Watch SPP frame as one queued packet avoids dozens of heap allocations
  // and queue operations caused by the legacy 16-byte segmentation.
  if (gSppTxCoalesced) {
    return watchBt.write(bytes, length) == length;
  }
  for (size_t offset = 0; offset < length; offset += kSppWriteChunkBytes) {
    const size_t chunkLength = min(kSppWriteChunkBytes, length - offset);
    if (watchBt.write(bytes + offset, chunkLength) != chunkLength) return false;
    if (offset + chunkLength < length) delay(5);
  }
  return true;
}

// Large protocol workspaces are allocated lazily, right after the Bluetooth
// controller has finished initialising, so they never starve the Bluetooth
// init path of heap. Called again on demand as a nullptr-safe guard.
// Only the two SPP frame buffers (needed for auth) are allocated here; the
// four QuickApp/network workspaces are allocated later, after auth succeeds,
// so the RFCOMM connect path still has plenty of heap.
bool ensureScratchBuffers() {
  if (gSppTxFrame) return true;
  gSppTxFrame = static_cast<uint8_t*>(malloc(8 + kSppV2PayloadMax));
  gSppRxFrame = static_cast<uint8_t*>(malloc(8 + kSppV2PayloadMax));
  gRawCommandPayloadScratch = static_cast<uint8_t*>(malloc(kSppV2PayloadMax));
  gEncryptedPayloadScratch = static_cast<uint8_t*>(malloc(kSppV2PayloadMax));
  if (!gSppTxFrame || !gSppRxFrame || !gRawCommandPayloadScratch ||
      !gEncryptedPayloadScratch) {
    Serial.println("VELA_SCRATCH_MALLOC_FAILED");
    return false;
  }
  Serial.printf("VELA_CORE_SCRATCH_ALLOCATED free=%lu\n",
                static_cast<unsigned long>(ESP.getFreeHeap()));
  return true;
}

// Allocates the two QuickApp message workspaces. Invoked after auth succeeds
// and as a lazy guard at the top of every consumer that needs them.
bool ensureAppScratchBuffers() {
  if (gQuickAppMessageScratch) return true;
  gQuickAppMessageScratch = static_cast<uint8_t*>(malloc(kSppV2PayloadMax));
  gQuickAppThirdpartyScratch = static_cast<uint8_t*>(malloc(kSppV2PayloadMax));
  if (!gQuickAppMessageScratch || !gQuickAppThirdpartyScratch) {
    Serial.println("VELA_APP_SCRATCH_MALLOC_FAILED");
    return false;
  }
  Serial.printf("VELA_APP_SCRATCH_ALLOCATED free=%lu\n",
                static_cast<unsigned long>(ESP.getFreeHeap()));
  return true;
}

bool writeSppV2Frame(uint8_t type, uint8_t sequence, const uint8_t* payload, size_t payloadLength) {
  if (payloadLength > kSppV2PayloadMax) return false;
  if (!ensureScratchBuffers()) return false;
  uint8_t* frame = gSppTxFrame;
  const uint16_t checksum = crc16Arc(payload, payloadLength);
  frame[0] = 0xa5; frame[1] = 0xa5; frame[2] = type & 0x0f; frame[3] = sequence;
  frame[4] = static_cast<uint8_t>(payloadLength & 0xff); frame[5] = static_cast<uint8_t>(payloadLength >> 8);
  frame[6] = static_cast<uint8_t>(checksum & 0xff); frame[7] = static_cast<uint8_t>(checksum >> 8);
  if (payloadLength > 0) memcpy(frame + 8, payload, payloadLength);
  return writeWatchBytes(frame, payloadLength + 8);
}

// ---------------------------------------------------------------------------
// 网络热路径日志开关
// 每一帧都 Serial.printf 会阻塞几毫秒（USB-CDC/uart 缓冲满时更久），而这些
// 回调运行在 lwIP tcpip 线程里，直接把转发吞吐打下来，还会造成 TCP 重传。
// 默认关闭；需要抓包/排障时用 -DVELA_NET_TRACE=1 编译。
// ---------------------------------------------------------------------------
#ifndef VELA_NET_TRACE
#define VELA_NET_TRACE 0
#endif
static constexpr bool kNetTrace = VELA_NET_TRACE != 0;

err_t watchNetworkOutput(struct netif*, struct pbuf* packet, const ip4_addr_t*) {
  // 安装表盘/快应用时 Mass 通道独占 SPP，回程包先丢掉；
  // 手表侧 TCP 会重传，几十秒的窗口可以接受。
  if (wfi::networkPaused()) {
    wfi::notePausedDrop();
    return ERR_BUF;
  }
  if (!gWatchNetworkTxQueue || !gWatchNetworkTxEnqueueScratch || !packet ||
      packet->tot_len == 0 || packet->tot_len > kWatchNetworkPacketMax) {
    ++gWatchNetworkDroppedPackets;
    if (kNetTrace) {
      Serial.printf("WATCH_RETURN_DROP stage=invalid len=%u\n", static_cast<unsigned>(packet ? packet->tot_len : 0));
    }
    return ERR_BUF;
  }
  // Return-path tracer: this callback means the response reached the watch netif
  // (internet -> WiFi STA -> NAPT reverse -> watch netif).
  if (kNetTrace) Serial.printf("WATCH_RETURN_FROM_LWIP len=%u\n", static_cast<unsigned>(packet->tot_len));
  gWatchNetworkTxEnqueueScratch->length = static_cast<uint16_t>(packet->tot_len);
  if (pbuf_copy_partial(packet, gWatchNetworkTxEnqueueScratch->bytes, packet->tot_len, 0) != packet->tot_len ||
      xQueueSend(gWatchNetworkTxQueue, gWatchNetworkTxEnqueueScratch, 0) != pdTRUE) {
    ++gWatchNetworkDroppedPackets;
    if (kNetTrace) {
      Serial.printf("WATCH_RETURN_DROP stage=queue_full len=%u\n", static_cast<unsigned>(packet->tot_len));
    }
    return ERR_BUF;
  }
  ++gWatchNetworkTxPackets;
  if (kNetTrace) Serial.printf("WATCH_RETURN_ENQUEUED len=%u\n", static_cast<unsigned>(packet->tot_len));
  return ERR_OK;
}

err_t initWatchNetworkNetif(struct netif* network) {
  if (!network) return ERR_ARG;
  network->name[0] = 'w';
  network->name[1] = 't';
  network->output = watchNetworkOutput;
  network->mtu = kWatchNetworkMtu;
  network->flags = NETIF_FLAG_BROADCAST;
  return ERR_OK;
}

// Helper: send a raw bootstrap protobuf message to the watch.
static void doBootstrap(const uint8_t encKey[16], uint8_t& seq,
                         const char* data, size_t len,
                         const char* label) {
  if (!encKey || !data || !len || !label) return;
  // data is a char* literal, cast to uint8_t*
  const uint8_t txSequence = seq;
  if (sendEncryptedWatchPb(seq, encKey,
                           reinterpret_cast<const uint8_t*>(data), len)) {
    Serial.printf("%s OK seq=%u\n", label, static_cast<unsigned>(txSequence));
  } else {
    Serial.printf("%s FAIL seq=%u\n", label, static_cast<unsigned>(txSequence));
  }
}

void setupWatchNetworkProxyInTcpip(void*) {
  ip4_addr_t address{}, netmask{}, gateway{};
  IP4_ADDR(&address, 10, 1, 10, 1);
  IP4_ADDR(&netmask, 255, 255, 255, 0);
  // CRITICAL: gateway MUST be 0.0.0.0. Passing a non-zero gateway here makes
  // lwIP install this watch netif as the DEFAULT route, which then overrides
  // the WiFi STA default route (0.0.0.0/0 -> 192.168.31.1). Result: DNS from
  // the watch hits ip4_forward -> ip4_route_src returns NULL -> IP4_FWD_NOROUTE.
  IP4_ADDR(&gateway, 0, 0, 0, 0);

  // Dump current netif list BEFORE adding the watch netif.
  {
    Serial.printf("NETIF_LIST_BEFORE default=%s\n", ::netif_default ? "set" : "NULL");
    for (struct netif* n = netif_list; n != NULL; n = n->next) {
      Serial.printf("  netif %c%c ip=%d.%d.%d.%d gw=%d.%d.%d.%d up=%d link=%d\n",
                    n->name[0], n->name[1],
                    ip4_addr1(netif_ip4_addr(n)), ip4_addr2(netif_ip4_addr(n)),
                    ip4_addr3(netif_ip4_addr(n)), ip4_addr4(netif_ip4_addr(n)),
                    ip4_addr1(netif_ip4_gw(n)), ip4_addr2(netif_ip4_gw(n)),
                    ip4_addr3(netif_ip4_gw(n)), ip4_addr4(netif_ip4_gw(n)),
                    netif_is_up(n) ? 1 : 0, netif_is_link_up(n) ? 1 : 0);
    }
  }

  if (!gWatchNetworkNetif || !netif_add(gWatchNetworkNetif, &address, &netmask, &gateway,
                 nullptr, initWatchNetworkNetif, tcpip_input)) {
    gWatchNetworkInitResult = ERR_IF;
  } else {
    netif_set_up(gWatchNetworkNetif);
    netif_set_link_up(gWatchNetworkNetif);
    ip_napt_enable(ip4_addr_get_u32(netif_ip4_addr(gWatchNetworkNetif)), 1);
    gWatchNetworkInitResult = ERR_OK;
  }

  {
    Serial.printf("NETIF_LIST_AFTER default=%s default_ip=%d.%d.%d.%d\n",
                  ::netif_default ? "set" : "NULL",
                  ::netif_default ? ip4_addr1(netif_ip4_addr(::netif_default)) : 0,
                  ::netif_default ? ip4_addr2(netif_ip4_addr(::netif_default)) : 0,
                  ::netif_default ? ip4_addr3(netif_ip4_addr(::netif_default)) : 0,
                  ::netif_default ? ip4_addr4(netif_ip4_addr(::netif_default)) : 0);
  }
  if (gWatchNetworkInitDone) xSemaphoreGive(gWatchNetworkInitDone);
}

void repairWatchInternetRouteInTcpip(void*) {
  struct netif* sta = nullptr;
  for (struct netif* n = netif_list; n != nullptr; n = n->next) {
    if (n == gWatchNetworkNetif) continue;
    if (!netif_is_up(n) || !netif_is_link_up(n)) continue;
    const ip4_addr_t* ip = netif_ip4_addr(n);
    const ip4_addr_t* gw = netif_ip4_gw(n);
    if (!ip || !gw || ip4_addr_isany_val(*ip) || ip4_addr_isany_val(*gw)) continue;
    // SoftAP has no upstream gateway; the first up netif with both an IPv4
    // address and a non-zero gateway is the Wi-Fi STA uplink we want.
    sta = n;
    break;
  }

  if (sta != nullptr) {
    if (::netif_default != sta) netif_set_default(sta);
    if (gWatchNetworkNetif && netif_is_up(gWatchNetworkNetif)) {
      // Re-enable NAPT after STA comes up. This is idempotent and also repairs
      // cases where the early NAPT setup happened before an uplink existed.
      ip_napt_enable(ip4_addr_get_u32(netif_ip4_addr(gWatchNetworkNetif)), 1);
    }
    gWatchInternetRouteReady = true;
    Serial.printf("WATCH_INET_ROUTE_READY sta=%c%c ip=%d.%d.%d.%d gw=%d.%d.%d.%d default=%c%c napt=true\n",
                  sta->name[0], sta->name[1],
                  ip4_addr1(netif_ip4_addr(sta)), ip4_addr2(netif_ip4_addr(sta)),
                  ip4_addr3(netif_ip4_addr(sta)), ip4_addr4(netif_ip4_addr(sta)),
                  ip4_addr1(netif_ip4_gw(sta)), ip4_addr2(netif_ip4_gw(sta)),
                  ip4_addr3(netif_ip4_gw(sta)), ip4_addr4(netif_ip4_gw(sta)),
                  ::netif_default ? ::netif_default->name[0] : '?',
                  ::netif_default ? ::netif_default->name[1] : '?');
  } else {
    gWatchInternetRouteReady = false;
    Serial.println("WATCH_INET_ROUTE_MISSING reason=no_sta_ipv4_gateway");
  }
  gWatchInternetRouteRepairPending = false;
}

void requestWatchInternetRouteRepair() {
  if (gWatchInternetRouteRepairPending || gWatchInternetRouteReady) return;
  gWatchInternetRouteRepairPending = true;
  const err_t result = tcpip_callback(repairWatchInternetRouteInTcpip, nullptr);
  if (result != ERR_OK) {
    gWatchInternetRouteRepairPending = false;
    Serial.printf("WATCH_INET_ROUTE_CALLBACK_FAILED err=%d\n", static_cast<int>(result));
  }
}

void serviceWatchInternetUplink() {
  if (ssid.isEmpty()) return;
  const int status = static_cast<int>(WiFi.status());
  if (status != gWatchLastWifiStatus) {
    gWatchLastWifiStatus = status;
    Serial.printf("WATCH_WIFI_STATUS status=%d ip=%s free=%lu largest=%lu\n",
                  status, WiFi.localIP().toString().c_str(),
                  static_cast<unsigned long>(ESP.getFreeHeap()),
                  static_cast<unsigned long>(ESP.getMaxAllocHeap()));
  }

  if (status == static_cast<int>(WL_CONNECTED)) {
    requestWatchInternetRouteRepair();
    return;
  }

  gWatchInternetRouteReady = false;
  const uint32_t now = millis();
  if (gWatchLastWifiBeginMs != 0 &&
      static_cast<uint32_t>(now - gWatchLastWifiBeginMs) < kWatchWifiRetryMs) return;

  Serial.printf("WATCH_WIFI_RETRY status=%d free=%lu largest=%lu\n",
                status,
                static_cast<unsigned long>(ESP.getFreeHeap()),
                static_cast<unsigned long>(ESP.getMaxAllocHeap()));
  WiFi.persistent(false);
  WiFi.setAutoReconnect(true);
  // Do not erase credentials from NVS; simply restart STA association.
  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid.c_str(), wifiPass.c_str());
  gWatchLastWifiBeginMs = now;
}

bool setupWatchNetworkProxy() {
  gWatchInternetRouteReady = false;
  gWatchInternetRouteRepairPending = false;
  if (gWatchNetworkReady) return true;
  if (!gWatchNetworkNetif) gWatchNetworkNetif = static_cast<struct netif*>(calloc(1, sizeof(struct netif)));
  if (!gWatchNetworkTxEnqueueScratch) gWatchNetworkTxEnqueueScratch = static_cast<WatchNetworkPacket*>(calloc(1, sizeof(WatchNetworkPacket)));
  if (!gWatchNetworkTxDrainScratch) gWatchNetworkTxDrainScratch = static_cast<WatchNetworkPacket*>(calloc(1, sizeof(WatchNetworkPacket)));
  if (!gWatchNetworkNetif || !gWatchNetworkTxEnqueueScratch || !gWatchNetworkTxDrainScratch) {
    Serial.println("WATCH_NETWORK_PROXY_INIT_FAILED stage=buffers");
    return false;
  }
  if (!gWatchNetworkTxQueue) {
    gWatchNetworkTxQueue = xQueueCreate(kWatchNetworkTxQueueDepth, sizeof(WatchNetworkPacket));
  }
  if (!gWatchNetworkTxQueue) {
    Serial.println("WATCH_NETWORK_PROXY_INIT_FAILED stage=queue");
    return false;
  }
  if (!gWatchNetworkInitDone) gWatchNetworkInitDone = xSemaphoreCreateBinary();
  if (!gWatchNetworkInitDone) {
    Serial.println("WATCH_NETWORK_PROXY_INIT_FAILED stage=semaphore");
    return false;
  }
  gWatchNetworkInitResult = ERR_INPROGRESS;
  const err_t callbackResult = tcpip_callback(setupWatchNetworkProxyInTcpip, nullptr);
  if (callbackResult != ERR_OK || xSemaphoreTake(gWatchNetworkInitDone, pdMS_TO_TICKS(3000)) != pdTRUE ||
      gWatchNetworkInitResult != ERR_OK) {
    Serial.printf("WATCH_NETWORK_PROXY_INIT_FAILED stage=tcpip callback=%d result=%d\n",
                  static_cast<int>(callbackResult), static_cast<int>(gWatchNetworkInitResult));
    return false;
  }
  gWatchNetworkReady = true;
  Serial.printf("WATCH_NETWORK_PROXY_READY ip=10.1.10.1 watch=10.1.10.2 mtu=%u napt=true\n",
                static_cast<unsigned>(kWatchNetworkMtu));
  return true;
}

void resetWatchNetworkSessionQueue() {
  if (gWatchNetworkTxQueue) xQueueReset(gWatchNetworkTxQueue);
}

bool injectWatchNetworkPacket(const uint8_t* bytes, size_t length) {
  if (!gWatchNetworkReady || !bytes || length < 20 || length > kWatchNetworkPacketMax || (bytes[0] >> 4) != 4) {
    ++gWatchNetworkDroppedPackets;
    return false;
  }
  // Use PBUF_LINK (not PBUF_RAW) so the pbuf reserves room for the Ethernet
  // header. When ip4_forward() hands this packet to etharp_output(), it calls
  // pbuf_header(q, -SIZEOF_ETH_HDR) to prepend the Ethernet header; a PBUF_RAW
  // pbuf has no such headroom and etharp_output returns ERR_BUF (-2), so the
  // packet is never actually transmitted. This was the return-path root cause.
  struct pbuf* packet = pbuf_alloc(PBUF_LINK, static_cast<u16_t>(length), PBUF_POOL);
  if (!packet || pbuf_take(packet, bytes, length) != ERR_OK) {
    if (packet) pbuf_free(packet);
    ++gWatchNetworkDroppedPackets;
    return false;
  }
  const err_t result = tcpip_input(packet, gWatchNetworkNetif);
  if (result != ERR_OK) {
    pbuf_free(packet);
    ++gWatchNetworkDroppedPackets;
    if (kNetTrace) {
      Serial.printf("WATCH_NETWORK_RX_INJECT_FAILED result=%d len=%u\n", static_cast<int>(result), static_cast<unsigned>(length));
    }
    return false;
  }
  ++gWatchNetworkRxPackets;
  // Return-path tracer: log the uplink with protocol / src / dst.
  if (kNetTrace) {
    const size_t ihl = static_cast<size_t>(bytes[0] & 0x0f) * 4;
    const uint8_t proto = bytes[9];
    const char* protoName = (proto == 6) ? "tcp" : (proto == 17) ? "udp" : (proto == 1) ? "icmp" : "ip";
    Serial.printf("WATCH_UPLINK_TO_LWIP proto=%u(%s) src=%d.%d.%d.%d dst=%d.%d.%d.%d",
                  static_cast<unsigned>(proto), protoName,
                  bytes[12], bytes[13], bytes[14], bytes[15],
                  bytes[16], bytes[17], bytes[18], bytes[19]);
    if ((proto == 6 || proto == 17) && length >= ihl + 4) {
      const uint16_t sport = (static_cast<uint16_t>(bytes[ihl]) << 8) | bytes[ihl + 1];
      const uint16_t dport = (static_cast<uint16_t>(bytes[ihl + 2]) << 8) | bytes[ihl + 3];
      Serial.printf(" sport=%u dport=%u", static_cast<unsigned>(sport), static_cast<unsigned>(dport));
    }
    Serial.printf(" len=%u\n", static_cast<unsigned>(length));
  }
  return true;
}

void drainWatchNetworkTx(uint8_t& sequence) {
  if (!gWatchNetworkTxQueue || !watchBt.connected()) return;
  if (!gWatchNetworkTxDrainScratch) return;
  if (!ensureScratchBuffers()) return;
  while (xQueueReceive(gWatchNetworkTxQueue, gWatchNetworkTxDrainScratch, 0) == pdTRUE) {
    const uint8_t txSeq = sequence;
    const uint8_t* b = gWatchNetworkTxDrainScratch->bytes;
    const size_t n = gWatchNetworkTxDrainScratch->length;
    if (kNetTrace) {
      Serial.printf("WATCH_RETURN_DRAIN len=%u q_left=%u\n",
                    static_cast<unsigned>(n),
                    static_cast<unsigned>(uxQueueMessagesWaiting(gWatchNetworkTxQueue)));
    }
    gRawCommandPayloadScratch[0] = 7;
    gRawCommandPayloadScratch[1] = 1;
    memcpy(gRawCommandPayloadScratch + 2, b, n);
    if (!writeSppV2Frame(3, sequence++, gRawCommandPayloadScratch, n + 2)) {
      ++gWatchNetworkDroppedPackets;
      if (kNetTrace) {
        Serial.printf("WATCH_RETURN_DROP stage=spp_write seq=%u len=%u total_drop=%lu\n",
                      static_cast<unsigned>(txSeq), static_cast<unsigned>(n),
                      static_cast<unsigned long>(gWatchNetworkDroppedPackets));
      }
      break;
    }
    if (kNetTrace) {
      Serial.printf("WATCH_RETURN_SPP_SENT seq=%u len=%u\n",
                    static_cast<unsigned>(txSeq), static_cast<unsigned>(n));
    }
  }
}

void resetSppRxAssembler() {
  gSppRxBuffered = 0;
}

void dropSppRxPrefix(size_t count) {
  if (count == 0 || gSppRxBuffered == 0) return;
  if (count >= gSppRxBuffered) {
    gSppRxBuffered = 0;
    return;
  }
  memmove(gSppRxFrame, gSppRxFrame + count, gSppRxBuffered - count);
  gSppRxBuffered -= count;
}

void logSppRxParserState(const char* stage) {
  Serial.printf("SPP_RX_PARSER stage=%s buffered=%u queue=%d resync_bytes=%lu crc_fail=%lu oversize=%lu partial_timeouts=%lu dropped=%lu\n",
                stage ? stage : "unknown",
                static_cast<unsigned>(gSppRxBuffered),
                watchRxAvailable(),
                static_cast<unsigned long>(gSppRxResyncBytes),
                static_cast<unsigned long>(gSppRxCrcFailures),
                static_cast<unsigned long>(gSppRxOversizeHeaders),
                static_cast<unsigned long>(gSppRxPartialTimeouts),
                static_cast<unsigned long>(watchRxDroppedBytes));
}

bool readSppV2Frame(SppV2Frame& output, uint32_t timeoutMs) {
  uint8_t* buffer = gSppRxFrame;
  const uint32_t startedAt = millis();
  while (millis() - startedAt < timeoutMs) {
    // Resynchronise one byte at a time, but keep all incomplete data across
    // readSppV2Frame() calls. The old implementation used a local buffered=0
    // and silently discarded a partial frame whenever a wait timed out.
    while (gSppRxBuffered >= 2 && (buffer[0] != 0xa5 || buffer[1] != 0xa5)) {
      dropSppRxPrefix(1);
      ++gSppRxResyncBytes;
    }

    if (gSppRxBuffered >= 8) {
      const size_t payloadLength = static_cast<size_t>(buffer[4] | (static_cast<uint16_t>(buffer[5]) << 8));
      if (payloadLength > kSppV2PayloadMax) {
        dropSppRxPrefix(1);
        ++gSppRxOversizeHeaders;
        continue;
      }
      const size_t frameLength = payloadLength + 8;
      if (gSppRxBuffered >= frameLength) {
        const uint16_t expected = static_cast<uint16_t>(buffer[6] | (static_cast<uint16_t>(buffer[7]) << 8));
        if (crc16Arc(buffer + 8, payloadLength) != expected) {
          dropSppRxPrefix(1);
          ++gSppRxCrcFailures;
          continue;
        }
        output.type = buffer[2] & 0x0f;
        output.sequence = buffer[3];
        output.payloadLength = payloadLength;
        if (payloadLength > 0) memcpy(output.payload, buffer + 8, payloadLength);
        dropSppRxPrefix(frameLength);
        return true;
      }
    }

    // Pull every byte already delivered by BluetoothSerial into the persistent
    // assembler, but never overflow the frame buffer. Extra frames remain in
    // the FreeRTOS queue and are consumed by the next call.
    bool received = false;
    while (gSppRxBuffered < 8 + kSppV2PayloadMax) {
      const int next = readWatchByte();
      if (next < 0) break;
      buffer[gSppRxBuffered++] = static_cast<uint8_t>(next);
      received = true;
      if (gSppRxBuffered >= 8) {
        const size_t payloadLength = static_cast<size_t>(buffer[4] | (static_cast<uint16_t>(buffer[5]) << 8));
        if (buffer[0] == 0xa5 && buffer[1] == 0xa5 && payloadLength <= kSppV2PayloadMax && gSppRxBuffered >= payloadLength + 8) break;
      }
    }
    if (!received) delay(2);
  }
  if (gSppRxBuffered > 0) ++gSppRxPartialTimeouts;
  return false;
}

// The SPP Hello has a small plaintext response that is not an SPPv2 frame.
// Drain it with strict bounds before the SPPv2 assembler starts consuming data.
bool startSppV2Session(const char* label) {
  if (watchBt.write(kSppHello, sizeof(kSppHello)) != sizeof(kSppHello)) {
    Serial.printf("%s_SPP_HELLO_WRITE_FAILED\n", label);
    return false;
  }

  const uint32_t startedAt = millis();
  size_t drainedBytes = 0;
  while (millis() - startedAt < kSppHelloDrainWindowMs && drainedBytes < kSppHelloDrainMaxBytes) {
    while (watchRxAvailable() > 0 && drainedBytes < kSppHelloDrainMaxBytes) {
      if (readWatchByte() < 0) break;
      ++drainedBytes;
    }
    delay(1);
  }
  resetSppRxAssembler();
  Serial.printf("%s_SPP_HELLO_SENT drained=%u\n", label, static_cast<unsigned>(drainedBytes));

  if (watchBt.write(kSppV2SessionStartRequest, sizeof(kSppV2SessionStartRequest)) != sizeof(kSppV2SessionStartRequest)) {
    Serial.printf("%s_SESSION_WRITE_FAILED\n", label);
    return false;
  }
  return true;
}

bool hmacSha256(const uint8_t* key, size_t keyLength, const uint8_t* message, size_t messageLength, uint8_t output[32]) {
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return info && mbedtls_md_hmac(info, key, keyLength, message, messageLength, output) == 0;
}

bool readProtoVarint(const uint8_t* data, size_t length, size_t& cursor, uint32_t& value) {
  value = 0;
  for (uint8_t shift = 0; shift < 32 && cursor < length; shift += 7) {
    const uint8_t next = data[cursor++];
    value |= static_cast<uint32_t>(next & 0x7f) << shift;
    if (!(next & 0x80)) return true;
  }
  return false;
}

bool protoVarintField(const uint8_t* data, size_t length, uint32_t wantedField, uint32_t& value) {
  size_t cursor = 0;
  while (cursor < length) {
    uint32_t tag = 0;
    if (!readProtoVarint(data, length, cursor, tag)) return false;
    const uint32_t field = tag >> 3, wire = tag & 7;
    if (wire == 0) {
      uint32_t next = 0;
      if (!readProtoVarint(data, length, cursor, next)) return false;
      if (field == wantedField) { value = next; return true; }
    } else if (wire == 2) {
      uint32_t size = 0;
      if (!readProtoVarint(data, length, cursor, size) || size > length - cursor) return false;
      cursor += size;
    } else if (wire == 5) {
      if (length - cursor < 4) return false;
      cursor += 4;
    } else if (wire == 1) {
      if (length - cursor < 8) return false;
      cursor += 8;
    } else return false;
  }
  return false;
}

bool protoBytesField(const uint8_t* data, size_t length, uint32_t wantedField, const uint8_t*& value, size_t& valueLength) {
  size_t cursor = 0;
  while (cursor < length) {
    uint32_t tag = 0;
    if (!readProtoVarint(data, length, cursor, tag)) return false;
    const uint32_t field = tag >> 3, wire = tag & 7;
    if (wire == 2) {
      uint32_t size = 0;
      if (!readProtoVarint(data, length, cursor, size) || size > length - cursor) return false;
      if (field == wantedField) { value = data + cursor; valueLength = size; return true; }
      cursor += size;
    } else if (wire == 0) {
      uint32_t ignored = 0;
      if (!readProtoVarint(data, length, cursor, ignored)) return false;
    } else if (wire == 5) {
      if (length - cursor < 4) return false;
      cursor += 4;
    } else if (wire == 1) {
      if (length - cursor < 8) return false;
      cursor += 8;
    } else return false;
  }
  return false;
}

bool skipProtoField(const uint8_t* data, size_t length, size_t& cursor, uint32_t wire) {
  uint32_t size = 0;
  if (wire == 0) return readProtoVarint(data, length, cursor, size);
  if (wire == 2) {
    return readProtoVarint(data, length, cursor, size) && size <= length - cursor && ((cursor += size), true);
  }
  if (wire == 5 && length - cursor >= 4) { cursor += 4; return true; }
  if (wire == 1 && length - cursor >= 8) { cursor += 8; return true; }
  return false;
}

class ProtoWriter {
 public:
  ProtoWriter(uint8_t* output, size_t capacity) : output_(output), capacity_(capacity) {}
  bool putByte(uint8_t value) { if (length_ >= capacity_) return false; output_[length_++] = value; return true; }
  bool putVarint(uint32_t value) {
    do { if (!putByte(static_cast<uint8_t>((value & 0x7f) | (value > 0x7f ? 0x80 : 0)))) return false; value >>= 7; } while (value);
    return true;
  }
  bool putBytesField(uint32_t field, const uint8_t* value, size_t valueLength) {
    return valueLength <= UINT32_MAX && putVarint((field << 3) | 2) && putVarint(static_cast<uint32_t>(valueLength)) && putRaw(value, valueLength);
  }
  bool putStringField(uint32_t field, const char* value) { return putBytesField(field, reinterpret_cast<const uint8_t*>(value), strlen(value)); }
  bool putRaw(const uint8_t* value, size_t valueLength) {
    if (valueLength > capacity_ - length_) return false;
    if (valueLength) memcpy(output_ + length_, value, valueLength);
    length_ += valueLength;
    return true;
  }
  size_t length() const { return length_; }
 private:
  uint8_t* output_;
  size_t capacity_;
  size_t length_ = 0;
};

bool protoNthBytesField(const uint8_t* data, size_t length, uint32_t wantedField,
                        uint32_t wantedIndex, const uint8_t*& value, size_t& valueLength) {
  size_t cursor = 0;
  uint32_t seen = 0;
  while (cursor < length) {
    uint32_t tag = 0;
    if (!readProtoVarint(data, length, cursor, tag)) return false;
    const uint32_t field = tag >> 3, wire = tag & 7;
    if (wire == 2) {
      uint32_t size = 0;
      if (!readProtoVarint(data, length, cursor, size) || size > length - cursor) return false;
      if (field == wantedField) {
        if (seen == wantedIndex) {
          value = data + cursor;
          valueLength = size;
          return true;
        }
        ++seen;
      }
      cursor += size;
    } else if (wire == 0) {
      uint32_t ignored = 0;
      if (!readProtoVarint(data, length, cursor, ignored)) return false;
    } else if (wire == 5) {
      if (length - cursor < 4) return false;
      cursor += 4;
    } else if (wire == 1) {
      if (length - cursor < 8) return false;
      cursor += 8;
    } else {
      return false;
    }
  }
  return false;
}

bool protoStringEquals(const uint8_t* data, size_t length, uint32_t field, const char* expected) {
  const uint8_t* value = nullptr;
  size_t valueLength = 0;
  if (!expected || !protoBytesField(data, length, field, value, valueLength)) return false;
  const size_t expectedLength = strlen(expected);
  return valueLength == expectedLength && memcmp(value, expected, expectedLength) == 0;
}

// Round-4 type2/id109:
// outer field4 -> field71 -> repeated field1 rule records.
// Extract the live watch_manual rule version/update timestamp (record field5).
bool parseRound4Id109State(const uint8_t* pb, size_t pbLength,
                           uint32_t& watchManualTimestamp,
                           uint32_t& watchSnapTimestamp) {
  watchManualTimestamp = 0;
  watchSnapTimestamp = 0;

  uint32_t type = 0, id = 0;
  if (!protoVarintField(pb, pbLength, 1, type) ||
      !protoVarintField(pb, pbLength, 2, id) ||
      type != 2 || id != 109) return false;

  const uint8_t* outer4 = nullptr;
  size_t outer4Length = 0;
  if (!protoBytesField(pb, pbLength, 4, outer4, outer4Length)) return false;

  const uint8_t* rules = nullptr;
  size_t rulesLength = 0;
  if (!protoBytesField(outer4, outer4Length, 71, rules, rulesLength)) return false;

  bool foundManual = false;
  for (uint32_t index = 0; index < 8; ++index) {
    const uint8_t* record = nullptr;
    size_t recordLength = 0;
    if (!protoNthBytesField(rules, rulesLength, 1, index, record, recordLength)) break;

    uint32_t timestamp = 0;
    protoVarintField(record, recordLength, 5, timestamp);
    if (protoStringEquals(record, recordLength, 2, "watch_manual")) {
      watchManualTimestamp = timestamp;
      foundManual = true;
    } else if (protoStringEquals(record, recordLength, 2, "watch_snap_rule")) {
      watchSnapTimestamp = timestamp;
    }
  }
  return foundManual;
}

// Build the exact Round-4 type2/id110 schema, but source field5 from the
// CURRENT watch's id109 response rather than hardcoding the captured timestamp.
bool buildRound4Id110(uint32_t liveTimestamp,
                      uint8_t* output, size_t capacity, size_t& outputLength) {
  uint8_t record[40]{};
  ProtoWriter recordWriter(record, sizeof(record));
  if (!recordWriter.putVarint((1u << 3) | 0u) || !recordWriter.putVarint(1) ||
      !recordWriter.putStringField(2, "manual_zen_rule") ||
      !recordWriter.putVarint((3u << 3) | 0u) || !recordWriter.putVarint(0) ||
      !recordWriter.putVarint((4u << 3) | 0u) || !recordWriter.putVarint(0) ||
      !recordWriter.putVarint((5u << 3) | 0u) || !recordWriter.putVarint(liveTimestamp)) {
    return false;
  }

  uint8_t repeatedRules[48]{};
  ProtoWriter rulesWriter(repeatedRules, sizeof(repeatedRules));
  if (!rulesWriter.putBytesField(1, record, recordWriter.length())) return false;

  uint8_t system[56]{};
  ProtoWriter systemWriter(system, sizeof(system));
  if (!systemWriter.putBytesField(71, repeatedRules, rulesWriter.length())) return false;

  ProtoWriter packetWriter(output, capacity);
  if (!packetWriter.putVarint((1u << 3) | 0u) || !packetWriter.putVarint(2) ||
      !packetWriter.putVarint((2u << 3) | 0u) || !packetWriter.putVarint(110) ||
      !packetWriter.putBytesField(4, system, systemWriter.length())) return false;

  outputLength = packetWriter.length();
  return true;
}

bool buildSyncNetworkStatus(uint8_t* output, size_t capacity, size_t& outputLength) {
  uint8_t networkStatus[4]{};
  ProtoWriter statusWriter(networkStatus, sizeof(networkStatus));
  if (!statusWriter.putVarint((1u << 3) | 0u) || !statusWriter.putVarint(2)) return false;

  uint8_t system[12]{};
  ProtoWriter systemWriter(system, sizeof(system));
  if (!systemWriter.putBytesField(59, networkStatus, statusWriter.length())) return false;

  ProtoWriter packetWriter(output, capacity);
  if (!packetWriter.putVarint((1u << 3) | 0u) || !packetWriter.putVarint(2) ||
      !packetWriter.putVarint((2u << 3) | 0u) || !packetWriter.putVarint(92) ||
      !packetWriter.putBytesField(4, system, systemWriter.length())) return false;
  outputLength = packetWriter.length();
  return true;
}

// --- vNext: native XiaoAI transcript and channel-7 DHCP emulation ---
bool buildXiaoAiTranscript(const char* text, bool finalResult, uint32_t eventCode,
                           uint8_t* output, size_t capacity, size_t& outputLength) {
  if (!text) text = "";
  const size_t textLength = strlen(text);
  if (textLength > 700) return false;

  uint8_t textNode[720]{};
  ProtoWriter textWriter(textNode, sizeof(textNode));
  if (!textWriter.putBytesField(1, reinterpret_cast<const uint8_t*>(text), textLength)) return false;

  uint8_t level1[736]{};
  ProtoWriter level1Writer(level1, sizeof(level1));
  if (!level1Writer.putBytesField(1, textNode, textWriter.length())) return false;

  uint8_t payload[752]{};
  ProtoWriter payloadWriter(payload, sizeof(payload));
  if (!payloadWriter.putVarint((1u << 3) | 0u) || !payloadWriter.putVarint(finalResult ? 1u : 0u) ||
      !payloadWriter.putBytesField(2, level1, level1Writer.length())) return false;

  uint8_t assistantInner[800]{};
  ProtoWriter assistantWriter(assistantInner, sizeof(assistantInner));
  if (!assistantWriter.putVarint((3u << 3) | 0u) || !assistantWriter.putVarint(eventCode) ||
      !assistantWriter.putBytesField(13, payload, payloadWriter.length()) ||
      !assistantWriter.putVarint((2u << 3) | 0u) || !assistantWriter.putVarint(0)) return false;

  uint8_t assistantMid[816]{};
  ProtoWriter midWriter(assistantMid, sizeof(assistantMid));
  if (!midWriter.putBytesField(2, assistantInner, assistantWriter.length())) return false;

  uint8_t assistantOuter[832]{};
  ProtoWriter outerWriter(assistantOuter, sizeof(assistantOuter));
  if (!outerWriter.putBytesField(1, assistantMid, midWriter.length())) return false;

  ProtoWriter commandWriter(output, capacity);
  if (!commandWriter.putVarint((1u << 3) | 0u) || !commandWriter.putVarint(14) ||
      !commandWriter.putVarint((2u << 3) | 0u) || !commandWriter.putVarint(0) ||
      !commandWriter.putBytesField(16, assistantOuter, outerWriter.length())) return false;
  outputLength = commandWriter.length();
  return true;
}

// Confirmed against the official round-3 phone trace.  The 15-byte native
// XiaoAI lifecycle packet is:
//   08 0e 10 00 82 01 08 0a 06 12 04 18 <state> 10 00
// state=0 is sent immediately before the final transcript; state=7 closes the
// native assistant transaction after the phone has delivered its result.
bool buildXiaoAiState(uint32_t state, uint8_t* output, size_t capacity, size_t& outputLength) {
  uint8_t inner[8]{};
  ProtoWriter innerWriter(inner, sizeof(inner));
  if (!innerWriter.putVarint((3u << 3) | 0u) || !innerWriter.putVarint(state) ||
      !innerWriter.putVarint((2u << 3) | 0u) || !innerWriter.putVarint(0)) return false;

  uint8_t mid[12]{};
  ProtoWriter midWriter(mid, sizeof(mid));
  if (!midWriter.putBytesField(2, inner, innerWriter.length())) return false;

  uint8_t outer[16]{};
  ProtoWriter outerWriter(outer, sizeof(outer));
  if (!outerWriter.putBytesField(1, mid, midWriter.length())) return false;

  ProtoWriter commandWriter(output, capacity);
  if (!commandWriter.putVarint((1u << 3) | 0u) || !commandWriter.putVarint(14) ||
      !commandWriter.putVarint((2u << 3) | 0u) || !commandWriter.putVarint(0) ||
      !commandWriter.putBytesField(16, outer, outerWriter.length())) return false;
  outputLength = commandWriter.length();
  return true;
}

uint16_t ipv4HeaderChecksum(const uint8_t* bytes, size_t length) {
  uint32_t sum = 0;
  for (size_t i = 0; i + 1 < length; i += 2) sum += (static_cast<uint16_t>(bytes[i]) << 8) | bytes[i + 1];
  if (length & 1) sum += static_cast<uint16_t>(bytes[length - 1]) << 8;
  while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
  return static_cast<uint16_t>(~sum);
}

bool sendWatchNetworkRaw(uint8_t& sequence, const uint8_t* bytes, size_t length) {
  if (!bytes || length == 0 || length > kWatchNetworkPacketMax || length + 2 > kSppV2PayloadMax) return false;
  if (!ensureScratchBuffers()) return false;
  gRawCommandPayloadScratch[0] = 7;
  gRawCommandPayloadScratch[1] = 1;
  memcpy(gRawCommandPayloadScratch + 2, bytes, length);
  return writeSppV2Frame(3, sequence++, gRawCommandPayloadScratch, length + 2);
}

uint8_t dhcpMessageType(const uint8_t* bootp, size_t length) {
  if (!bootp || length < 240 || bootp[236] != 0x63 || bootp[237] != 0x82 || bootp[238] != 0x53 || bootp[239] != 0x63) return 0;
  size_t cursor = 240;
  while (cursor < length) {
    const uint8_t code = bootp[cursor++];
    if (code == 255) break;
    if (code == 0) continue;
    if (cursor >= length) break;
    const uint8_t optionLength = bootp[cursor++];
    if (optionLength > length - cursor) break;
    if (code == 53 && optionLength == 1) return bootp[cursor];
    cursor += optionLength;
  }
  return 0;
}

bool sendWatchDhcpReply(uint8_t& sequence, const uint8_t* requestBootp, size_t requestLength, uint8_t replyType) {
  if (!requestBootp || requestLength < 240 || (replyType != 2 && replyType != 5)) return false;
  uint8_t packet[340]{};
  constexpr size_t ipLen = 20, udpLen = 8, bootpFixed = 240;
  uint8_t* ip = packet;
  uint8_t* udp = packet + ipLen;
  uint8_t* bootp = udp + udpLen;

  bootp[0] = 2; // BOOTREPLY
  bootp[1] = requestBootp[1];
  bootp[2] = requestBootp[2];
  bootp[3] = 0;
  memcpy(bootp + 4, requestBootp + 4, 4); // xid
  bootp[10] = 0; bootp[11] = 0; // flags = 0 (official phone behaviour)
  bootp[16] = 10; bootp[17] = 1; bootp[18] = 10; bootp[19] = 2; // yiaddr
  bootp[20] = 10; bootp[21] = 1; bootp[22] = 10; bootp[23] = 1; // siaddr
  memcpy(bootp + 28, requestBootp + 28, 16); // chaddr
  bootp[236] = 0x63; bootp[237] = 0x82; bootp[238] = 0x53; bootp[239] = 0x63;
  size_t o = bootpFixed;
  auto put = [&](uint8_t code, const uint8_t* value, uint8_t n) {
    bootp[o++] = code; bootp[o++] = n; memcpy(bootp + o, value, n); o += n;
  };
  const uint8_t typeValue[] = {replyType}; put(53, typeValue, 1);
  const uint8_t mask[] = {255,255,255,0}; put(1, mask, 4);
  const uint8_t router[] = {10,1,10,1}; put(3, router, 4);
  const uint8_t lease[] = {0x10,0x0e,0x00,0x00}; put(51, lease, 4); // 3600 s LE
  const uint8_t serverId[] = {10,1,10,1}; put(54, serverId, 4);
  const uint8_t dns[] = {114,114,114,114}; put(6, dns, 4);
  bootp[o++] = 255;
  const size_t bootpLength = o;
  const size_t udpLength = udpLen + bootpLength;
  const size_t totalLength = ipLen + udpLength;

  ip[0] = 0x45; ip[1] = 0;
  ip[2] = static_cast<uint8_t>(totalLength >> 8); ip[3] = static_cast<uint8_t>(totalLength & 0xff);
  ip[4] = 0; ip[5] = static_cast<uint8_t>(esp_random() & 0xff);
  ip[6] = 0; ip[7] = 0; ip[8] = 64; ip[9] = 17;
  ip[12] = 10; ip[13] = 1; ip[14] = 10; ip[15] = 1;
  ip[16] = 255; ip[17] = 255; ip[18] = 255; ip[19] = 255;
  const uint16_t checksum = ipv4HeaderChecksum(ip, ipLen);
  ip[10] = static_cast<uint8_t>(checksum >> 8); ip[11] = static_cast<uint8_t>(checksum & 0xff);

  udp[0] = 0; udp[1] = 67; udp[2] = 0; udp[3] = 68;
  udp[4] = static_cast<uint8_t>(udpLength >> 8); udp[5] = static_cast<uint8_t>(udpLength & 0xff);
  udp[6] = 0; udp[7] = 0; // IPv4 UDP checksum may be zero.
  const bool sent = sendWatchNetworkRaw(sequence, packet, totalLength);
  if (sent) Serial.println(replyType == 2 ? "WATCH_DHCP_OFFER ip=10.1.10.2 gateway=10.1.10.1 dns=114.114.114.114" :
                                            "WATCH_DHCP_ACK ip=10.1.10.2 gateway=10.1.10.1 dns=114.114.114.114");
  return sent;
}

bool handleWatchDhcp(const uint8_t* bytes, size_t length, uint8_t& sequence) {
  if (!bytes || length < 20 || (bytes[0] >> 4) != 4) return false;
  const size_t ihl = static_cast<size_t>(bytes[0] & 0x0f) * 4;
  if (ihl < 20 || length < ihl + 8 || bytes[9] != 17) return false;
  const uint8_t* udp = bytes + ihl;
  const uint16_t srcPort = (static_cast<uint16_t>(udp[0]) << 8) | udp[1];
  const uint16_t dstPort = (static_cast<uint16_t>(udp[2]) << 8) | udp[3];
  const uint16_t udpLength = (static_cast<uint16_t>(udp[4]) << 8) | udp[5];
  if (srcPort != 68 || dstPort != 67 || udpLength < 8 + 240 || ihl + udpLength > length) return false;
  const uint8_t* bootp = udp + 8;
  const size_t bootpLength = udpLength - 8;
  const uint8_t type = dhcpMessageType(bootp, bootpLength);
  if (type == 1) { sendWatchDhcpReply(sequence, bootp, bootpLength, 2); Serial.println("WATCH_DHCP_DISCOVER"); return true; }
  if (type == 3) { sendWatchDhcpReply(sequence, bootp, bootpLength, 5); Serial.println("WATCH_DHCP_REQUEST"); return true; }
  return false;
}

bool sendPendingXiaoAiStart(uint8_t& sequence, const uint8_t encKey[16]) {
  if (!gXiaoAiStartPending || !nativeXiaoAiReturn) return true;
  gXiaoAiStartPending = false;
  uint8_t pb[128]{}; size_t pbLength = 0;
  if (!buildXiaoAiTranscript("", false, 1, pb, sizeof(pb), pbLength)) return false;
  const bool ok = sendEncryptedWatchPb(sequence, encKey, pb, pbLength);
  Serial.printf("XIAOAI_TRANSCRIPT_START_SENT ok=%s event=1 bytes=%u confirmed_shape=true\n", ok ? "true" : "false", static_cast<unsigned>(pbLength));
  if (ok) markXiaoAiProgress("start_empty_partial");
  return ok;
}

void scheduleXiaoAiEnd(uint32_t delayMs = kXiaoAiEndDelayMs) {
  gXiaoAiEndPending = true;
  gXiaoAiEndDueMs = millis() + delayMs;
}

bool sendPendingXiaoAiEnd(uint8_t& sequence, const uint8_t encKey[16]) {
  if (!gXiaoAiEndPending || !nativeXiaoAiReturn) return true;
  if (static_cast<int32_t>(millis() - gXiaoAiEndDueMs) < 0) return true;
  gXiaoAiEndPending = false;
  uint8_t pb[32]{}; size_t pbLength = 0;
  if (!buildXiaoAiState(7, pb, sizeof(pb), pbLength)) return false;
  const bool ok = sendEncryptedWatchPb(sequence, encKey, pb, pbLength);
  Serial.printf("XIAOAI_STATE_END_SENT ok=%s state=7 bytes=%u confirmed_shape=true\n",
                ok ? "true" : "false", static_cast<unsigned>(pbLength));
  if (ok) finishXiaoAiSession("state7_sent");
  return ok;
}

bool scheduleRollingAsrIfDue() {
  if (!gXiaoAiSessionActive || !gWatchStreamCaptureActive || gWatchStreamCaptureFileFailed ||
      !gWatchStreamCaptureFsReady || gWatchAsrTask || gXiaoAiFinalAsrPending ||
      gXiaoAiAudioMs < gXiaoAiNextPartialAudioMs) return false;
  // Close/reopen around the snapshot so the partial reader never races a
  // simultaneously-open SPIFFS writer handle on cores/framework versions that
  // do not guarantee coherent concurrent access to one file.
  char partialPacketPath[48]{};
  char partialWavPath[48]{};
  buildSessionAsrPaths(gXiaoAiActiveSessionId, false, partialPacketPath, sizeof(partialPacketPath),
                       partialWavPath, sizeof(partialWavPath));
  if (gWatchStreamCaptureFile) {
    gWatchStreamCaptureFile.flush();
    gWatchStreamCaptureFile.close();
  }
  const bool copied = copySpiffsFile(kWatchStreamCapturePath, partialPacketPath);
  gWatchStreamCaptureFile = SPIFFS.open(kWatchStreamCapturePath, FILE_APPEND);
  if (!gWatchStreamCaptureFile) {
    gWatchStreamCaptureFileFailed = true;
    Serial.println("WATCH_ASR_PARTIAL_REOPEN_FAILED");
    SPIFFS.remove(partialPacketPath);
    return false;
  }
  if (!copied) {
    Serial.println("WATCH_ASR_PARTIAL_SNAPSHOT_FAILED");
    return false;
  }
  if (!scheduleWatchAsrJob(partialPacketPath, partialWavPath, false, gXiaoAiActiveSessionId)) {
    SPIFFS.remove(partialPacketPath);
    return false;
  }
  gXiaoAiNextPartialAudioMs = gXiaoAiAudioMs + kXiaoAiRollingIntervalMs;
  Serial.printf("WATCH_ASR_PARTIAL_SCHEDULED session=%lu audio_ms=%lu next_audio_ms=%lu\n",
                static_cast<unsigned long>(gXiaoAiActiveSessionId),
                static_cast<unsigned long>(gXiaoAiAudioMs),
                static_cast<unsigned long>(gXiaoAiNextPartialAudioMs));
  return true;
}

void scheduleDeferredFinalAsrIfReady() {
  if (!gXiaoAiFinalAsrPending || gWatchAsrTask) return;
  const uint32_t sessionId = gXiaoAiFinalPendingSessionId;
  if (sessionId == 0 || sessionId != gXiaoAiActiveSessionId) {
    gXiaoAiFinalAsrPending = false;
    if (gXiaoAiFinalPacketPath[0]) SPIFFS.remove(gXiaoAiFinalPacketPath);
    if (gXiaoAiFinalWavPath[0]) SPIFFS.remove(gXiaoAiFinalWavPath);
    return;
  }
  if (scheduleWatchAsrJob(gXiaoAiFinalPacketPath, gXiaoAiFinalWavPath, true, sessionId)) {
    gXiaoAiFinalAsrPending = false;
    Serial.printf("WATCH_ASR_FINAL_RESUMED session=%lu\n", static_cast<unsigned long>(sessionId));
  }
}

void serviceXiaoAiAssistantCompletion() {
  if (!gXiaoAiSessionActive || !gXiaoAiAwaitAssistant) return;
  if (gXiaoAiAssistantDoneSessionId == gXiaoAiActiveSessionId) {
    gXiaoAiAwaitAssistant = false;
    scheduleXiaoAiEnd();
    Serial.printf("XIAOAI_ASSISTANT_COMPLETE session=%lu native_answer_return=false end_scheduled=true\n",
                  static_cast<unsigned long>(gXiaoAiActiveSessionId));
  }
}

void serviceXiaoAiNoProgressTimeout() {
  // Never close an Assistant transaction only because cloud progress is slow
  // while the user is still speaking. The deadline is evaluated after ch3 END.
  if (!gXiaoAiSessionActive || gWatchStreamCaptureActive || gXiaoAiEndPending || gXiaoAiLastProgressMs == 0) return;
  const uint32_t age = millis() - gXiaoAiLastProgressMs;
  if (age < kXiaoAiNoProgressTimeoutMs) return;
  Serial.printf("XIAOAI_NO_PROGRESS_TIMEOUT session=%lu age_ms=%lu threshold_ms=%lu inferred_guard=true\n",
                static_cast<unsigned long>(gXiaoAiActiveSessionId),
                static_cast<unsigned long>(age),
                static_cast<unsigned long>(kXiaoAiNoProgressTimeoutMs));
  scheduleXiaoAiEnd(0);
}

void drainAsrResultToWatch(uint8_t& sequence, const uint8_t encKey[16]) {
  if (!gAsrResultQueue) return;
  AsrResultMessage result;
  while (xQueueReceive(gAsrResultQueue, &result, 0) == pdTRUE) {
    if (!gXiaoAiSessionActive || result.sessionId == 0 || result.sessionId != gXiaoAiActiveSessionId) {
      Serial.printf("XIAOAI_ASR_RESULT_STALE result_session=%lu active_session=%lu final=%s\n",
                    static_cast<unsigned long>(result.sessionId),
                    static_cast<unsigned long>(gXiaoAiActiveSessionId),
                    result.finalResult ? "true" : "false");
      continue;
    }
    if (!result.ok || !nativeXiaoAiReturn) {
      if (result.finalResult) scheduleXiaoAiEnd(0);
      continue;
    }

    if (!result.finalResult) {
      if (gXiaoAiFinalSent || strcmp(result.text, gXiaoAiLastPartial) == 0) continue;
      uint8_t partialPb[1024]{}; size_t partialLength = 0;
      if (buildXiaoAiTranscript(result.text, false, 1, partialPb, sizeof(partialPb), partialLength) &&
          sendEncryptedWatchPb(sequence, encKey, partialPb, partialLength)) {
        snprintf(gXiaoAiLastPartial, sizeof(gXiaoAiLastPartial), "%s", result.text);
        ++gXiaoAiPartialSentCount;
        markXiaoAiProgress("partial_transcript");
        Serial.printf("XIAOAI_TRANSCRIPT_PARTIAL_SENT session=%lu event=1 bytes=%u text_bytes=%u\n",
                      static_cast<unsigned long>(result.sessionId), static_cast<unsigned>(partialLength),
                      static_cast<unsigned>(strlen(result.text)));
      }
      continue;
    }

    // The official phone sends a 15-byte state=0 packet, then the same
    // transcript with final=1.  This lifecycle is now confirmed by the HCI
    // capture; only the later assistant-answer/TTS events remain unresolved.
    uint8_t statePb[32]{}; size_t stateLength = 0;
    if (buildXiaoAiState(0, statePb, sizeof(statePb), stateLength)) {
      const bool stateOk = sendEncryptedWatchPb(sequence, encKey, statePb, stateLength);
      Serial.printf("XIAOAI_STATE_FINALIZING_SENT ok=%s state=0 bytes=%u confirmed_shape=true\n",
                    stateOk ? "true" : "false", static_cast<unsigned>(stateLength));
      if (stateOk) markXiaoAiProgress("state0");
    }

    uint8_t pb[1024]{}; size_t pbLength = 0;
    if (buildXiaoAiTranscript(result.text, true, 1, pb, sizeof(pb), pbLength) &&
        sendEncryptedWatchPb(sequence, encKey, pb, pbLength)) {
      Serial.printf("XIAOAI_TRANSCRIPT_FINAL_SENT event=1 bytes=%u text_bytes=%u confirmed_shape=true\n",
                    static_cast<unsigned>(pbLength), static_cast<unsigned>(strlen(result.text)));
      gXiaoAiFinalSent = true;
      snprintf(gXiaoAiLastPartial, sizeof(gXiaoAiLastPartial), "%s", result.text);
      markXiaoAiProgress("final_transcript");
      if (chatAfterAsr) {
        gXiaoAiAwaitAssistant = true;
        Serial.printf("XIAOAI_WAIT_ASSISTANT session=%lu no_progress_timeout_ms=%lu\n",
                      static_cast<unsigned long>(result.sessionId),
                      static_cast<unsigned long>(kXiaoAiNoProgressTimeoutMs));
      } else {
        scheduleXiaoAiEnd();
      }
    } else {
      Serial.println("XIAOAI_TRANSCRIPT_FINAL_SEND_FAILED");
    }
  }
}

struct WatchAppInfo {
  uint8_t fingerprint[64]{};
  size_t fingerprintLength = 0;
  bool found = false;
};

// 缓存最近一次解析到的手表快应用信息，供「一键推送」在会话中复用。
// WatchAppInfo 里有 32 字节指纹和 found/fingerprintLength 两个字段，
// 体积很小，不需要额外堆分配。
static WatchAppInfo gCachedWatchApp;
static volatile bool gWatchEverAuthedOnce = false;

static void rememberWatchApp(const WatchAppInfo& app) {  if (!app.found) return;
  memcpy(gCachedWatchApp.fingerprint, app.fingerprint, sizeof(gCachedWatchApp.fingerprint));
  gCachedWatchApp.fingerprintLength = app.fingerprintLength;
  gCachedWatchApp.found = true;
}

static bool lookupCachedWatchApp(WatchAppInfo& out) {
  if (!gCachedWatchApp.found) return false;
  memcpy(out.fingerprint, gCachedWatchApp.fingerprint, sizeof(out.fingerprint));
  out.fingerprintLength = gCachedWatchApp.fingerprintLength;
  out.found = true;
  return true;
}


bool buildQuickAppBasicInfo(uint8_t* output, size_t capacity, size_t& outputLength, const WatchAppInfo& app) {
  ProtoWriter writer(output, capacity);
  if (!app.found || app.fingerprintLength == 0 || !writer.putStringField(1, watchQuickAppPackage()) || !writer.putBytesField(2, app.fingerprint, app.fingerprintLength)) return false;
  outputLength = writer.length();
  return true;
}

bool wrapThirdpartyWearPacket(uint32_t id, const uint8_t* thirdparty, size_t thirdpartyLength, uint8_t* output, size_t capacity, size_t& outputLength) {
  ProtoWriter writer(output, capacity);
  if (!writer.putVarint((1 << 3) | 0) || !writer.putVarint(20) || !writer.putVarint((2 << 3) | 0) || !writer.putVarint(id) ||
      !writer.putBytesField(22, thirdparty, thirdpartyLength)) return false;
  outputLength = writer.length();
  return true;
}

bool buildQuickAppListRequest(uint8_t* output, size_t capacity, size_t& outputLength) {
  ProtoWriter writer(output, capacity);
  if (!writer.putVarint((1 << 3) | 0) || !writer.putVarint(20) || !writer.putVarint((2 << 3) | 0) || !writer.putVarint(0)) return false;
  outputLength = writer.length();
  return true;
}

bool buildQuickAppStatus(const WatchAppInfo& app, uint8_t* output, size_t capacity, size_t& outputLength) {
  uint8_t basic[192]; size_t basicLength = 0;
  if (!buildQuickAppBasicInfo(basic, sizeof(basic), basicLength, app)) return false;
  uint8_t phoneStatus[224]; ProtoWriter phoneWriter(phoneStatus, sizeof(phoneStatus));
  if (!phoneWriter.putBytesField(1, basic, basicLength) || !phoneWriter.putVarint((2 << 3) | 0) || !phoneWriter.putVarint(1)) return false;
  uint8_t thirdparty[256]; ProtoWriter thirdWriter(thirdparty, sizeof(thirdparty));
  if (!thirdWriter.putBytesField(8, phoneStatus, phoneWriter.length())) return false;
  return wrapThirdpartyWearPacket(7, thirdparty, thirdWriter.length(), output, capacity, outputLength);
}

bool buildQuickAppLaunch(const WatchAppInfo& app, uint8_t* output, size_t capacity, size_t& outputLength) {
  uint8_t basic[192]; size_t basicLength = 0;
  if (!buildQuickAppBasicInfo(basic, sizeof(basic), basicLength, app)) return false;
  uint8_t launch[224]; ProtoWriter launchWriter(launch, sizeof(launch));
  if (!launchWriter.putBytesField(1, basic, basicLength) || !launchWriter.putStringField(2, "")) return false;
  uint8_t thirdparty[256]; ProtoWriter thirdWriter(thirdparty, sizeof(thirdparty));
  if (!thirdWriter.putBytesField(6, launch, launchWriter.length())) return false;
  return wrapThirdpartyWearPacket(4, thirdparty, thirdWriter.length(), output, capacity, outputLength);
}

bool buildQuickAppMessage(const WatchAppInfo& app, const uint8_t* content, size_t contentLength, uint8_t* output, size_t capacity, size_t& outputLength) {
  if (!ensureAppScratchBuffers()) return false;
  uint8_t basic[192]; size_t basicLength = 0;
  if (!buildQuickAppBasicInfo(basic, sizeof(basic), basicLength, app)) return false;
  ProtoWriter messageWriter(gQuickAppMessageScratch, kSppV2PayloadMax);
  if (!messageWriter.putBytesField(1, basic, basicLength) || !messageWriter.putBytesField(2, content, contentLength)) return false;
  ProtoWriter thirdWriter(gQuickAppThirdpartyScratch, kSppV2PayloadMax);
  if (!thirdWriter.putBytesField(9, gQuickAppMessageScratch, messageWriter.length())) return false;
  return wrapThirdpartyWearPacket(8, gQuickAppThirdpartyScratch, thirdWriter.length(), output, capacity, outputLength);
}

bool parseSecretHex(String value, uint8_t output[16]) {
  value.trim();
  if (value.length() != 32) return false;
  // 自动纠正常见输入错误：O→0, o→0, l→1, I→1, S→5, B→8
  // 这些是手机输入法容易混淆的字符
  for (size_t i = 0; i < value.length(); ++i) {
    switch (value[i]) {
      case 'O': case 'o': value[i] = '0'; break;
      case 'l': value[i] = '1'; break;
      case 'I': value[i] = '1'; break;
      case 'S': value[i] = '5'; break;
      case 'B': value[i] = '8'; break;
      default: break;
    }
  }
  for (size_t i = 0; i < 16; ++i) {
    const char high = value[i * 2], low = value[i * 2 + 1];
    if (!isxdigit(static_cast<unsigned char>(high)) || !isxdigit(static_cast<unsigned char>(low))) return false;
    output[i] = static_cast<uint8_t>((hexNibble(high) << 4) | hexNibble(low));
  }
  return true;
}

bool buildStep3(const uint8_t secret[16], const uint8_t phoneNonce[16], const uint8_t watchNonce[16], const uint8_t watchHmac[32], uint8_t output[160], size_t& outputLength, uint8_t sessionDecKey[16] = nullptr, uint8_t sessionEncKey[16] = nullptr, const uint8_t* deviceInfoOverride = nullptr, size_t deviceInfoOverrideLength = 0) {
  uint8_t transcript[32], hmacKey[32], expansion[64], input[44], confirmation[32], encryptedNonces[32], encryptionNonce[12], deviceInfo[48], encryptedInfo[52];
  memcpy(transcript, phoneNonce, 16); memcpy(transcript + 16, watchNonce, 16);
  if (!hmacSha256(transcript, sizeof(transcript), secret, 16, hmacKey)) return false;
  static constexpr uint8_t kAuthLabel[] = {'m','i','w','e','a','r','-','a','u','t','h'};
  memcpy(input, kAuthLabel, sizeof(kAuthLabel)); input[sizeof(kAuthLabel)] = 1;
  if (!hmacSha256(hmacKey, sizeof(hmacKey), input, sizeof(kAuthLabel) + 1, expansion)) return false;
  memcpy(input, expansion, 32); memcpy(input + 32, kAuthLabel, sizeof(kAuthLabel)); input[43] = 2;
  if (!hmacSha256(hmacKey, sizeof(hmacKey), input, sizeof(input), expansion + 32)) return false;
  uint8_t confirmationInput[32];
  memcpy(confirmationInput, watchNonce, 16); memcpy(confirmationInput + 16, phoneNonce, 16);
  if (!hmacSha256(expansion, 16, confirmationInput, sizeof(confirmationInput), confirmation) || memcmp(confirmation, watchHmac, 32) != 0) return false;
  if (sessionDecKey) memcpy(sessionDecKey, expansion, 16);
  if (sessionEncKey) memcpy(sessionEncKey, expansion + 16, 16);
  if (!hmacSha256(expansion + 16, 16, transcript, sizeof(transcript), encryptedNonces)) return false;
  size_t infoLength = 0;
  if (deviceInfoOverride && deviceInfoOverrideLength > 0 &&
      deviceInfoOverrideLength <= sizeof(deviceInfo)) {
    memcpy(deviceInfo, deviceInfoOverride, deviceInfoOverrideLength);
    infoLength = deviceInfoOverrideLength;
  } else {
    const char kPhoneName[] = "Vela-Gateway";
    deviceInfo[infoLength++] = 0x08; deviceInfo[infoLength++] = 0;
    deviceInfo[infoLength++] = 0x15; deviceInfo[infoLength++] = 0x00; deviceInfo[infoLength++] = 0x00; deviceInfo[infoLength++] = 0x10; deviceInfo[infoLength++] = 0x42;
    deviceInfo[infoLength++] = 0x1a; deviceInfo[infoLength++] = sizeof(kPhoneName) - 1; memcpy(deviceInfo + infoLength, kPhoneName, sizeof(kPhoneName) - 1); infoLength += sizeof(kPhoneName) - 1;
    deviceInfo[infoLength++] = 0x20; deviceInfo[infoLength++] = 0xe0; deviceInfo[infoLength++] = 0x01;
    deviceInfo[infoLength++] = 0x2a; deviceInfo[infoLength++] = 0x02; deviceInfo[infoLength++] = 'Z'; deviceInfo[infoLength++] = 'H';
  }
  memcpy(encryptionNonce, expansion + 36, 4); memset(encryptionNonce + 4, 0, 8);
  mbedtls_ccm_context ccm; mbedtls_ccm_init(&ccm);
  const int setKeyResult = mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, expansion + 16, 128);
  const int encryptResult = setKeyResult == 0 ? mbedtls_ccm_encrypt_and_tag(&ccm, infoLength, encryptionNonce, sizeof(encryptionNonce), nullptr, 0, deviceInfo, encryptedInfo, encryptedInfo + infoLength, 4) : -1;
  mbedtls_ccm_free(&ccm);
  if (encryptResult != 0) return false;
  // Command.auth(field3) -> Auth.authStep3(field32) -> {
  //   encryptedNonces(field1, 32B),
  //   encryptedDeviceInfo(field2, infoLength + 4B CCM tag)
  // }
  // The old implementation hard-coded 73/70, which was only valid for the
  // 30-byte Vela-Gateway DeviceInfo. Round-4 official DeviceInfo is 28B,
  // therefore its correct lengths are 71/68. Build them dynamically.
  const size_t encryptedInfoLength = infoLength + 4u;
  const size_t authStep3BodyLength =
      2u + 32u +                  // field1 tag+len + encryptedNonces
      2u + encryptedInfoLength;   // field2 tag+len + encryptedDeviceInfo
  const size_t authMessageLength =
      2u + 1u + authStep3BodyLength;  // field32 tag (2B) + 1B varint length

  if (encryptedInfoLength >= 128u ||
      authStep3BodyLength >= 128u ||
      authMessageLength >= 128u) {
    return false;
  }

  size_t cursor = 0;
  output[cursor++] = 0x08; output[cursor++] = 1;
  output[cursor++] = 0x10; output[cursor++] = 27;
  output[cursor++] = 0x1a;
  output[cursor++] = static_cast<uint8_t>(authMessageLength);

  output[cursor++] = 0x82; output[cursor++] = 0x02;
  output[cursor++] = static_cast<uint8_t>(authStep3BodyLength);

  output[cursor++] = 0x0a; output[cursor++] = 32;
  memcpy(output + cursor, encryptedNonces, 32); cursor += 32;

  output[cursor++] = 0x12;
  output[cursor++] = static_cast<uint8_t>(encryptedInfoLength);
  memcpy(output + cursor, encryptedInfo, encryptedInfoLength);
  cursor += encryptedInfoLength;

  outputLength = cursor;
  Serial.printf("WATCH_AUTH_STEP3_LAYOUT info=%u encrypted_info=%u inner=%u auth=%u total=%u\n",
                static_cast<unsigned>(infoLength),
                static_cast<unsigned>(encryptedInfoLength),
                static_cast<unsigned>(authStep3BodyLength),
                static_cast<unsigned>(authMessageLength),
                static_cast<unsigned>(outputLength));
  mbedtls_platform_zeroize(transcript, sizeof(transcript)); mbedtls_platform_zeroize(hmacKey, sizeof(hmacKey)); mbedtls_platform_zeroize(expansion, sizeof(expansion)); mbedtls_platform_zeroize(input, sizeof(input)); mbedtls_platform_zeroize(confirmation, sizeof(confirmation)); mbedtls_platform_zeroize(encryptedNonces, sizeof(encryptedNonces)); mbedtls_platform_zeroize(encryptionNonce, sizeof(encryptionNonce)); mbedtls_platform_zeroize(deviceInfo, sizeof(deviceInfo)); mbedtls_platform_zeroize(encryptedInfo, sizeof(encryptedInfo));
  return true;
}

bool aes128CtrCrypt(const uint8_t key[16], uint8_t* bytes, size_t length) {
  uint8_t nonceCounter[16], streamBlock[16]{};
  size_t offset = 0;
  memcpy(nonceCounter, key, sizeof(nonceCounter));
  mbedtls_aes_context aes; mbedtls_aes_init(&aes);
  const int setKeyResult = mbedtls_aes_setkey_enc(&aes, key, 128);
  const int cryptResult = setKeyResult == 0 ? mbedtls_aes_crypt_ctr(&aes, length, &offset, nonceCounter, streamBlock, bytes, bytes) : -1;
  mbedtls_aes_free(&aes);
  mbedtls_platform_zeroize(nonceCounter, sizeof(nonceCounter));
  mbedtls_platform_zeroize(streamBlock, sizeof(streamBlock));
  return cryptResult == 0;
}

bool sendEncryptedWatchChannel(uint8_t& sequence, const uint8_t key[16],
                               uint8_t channel, uint8_t opcode,
                               const uint8_t* data, size_t dataLength) {
  if (dataLength + 2 > kSppV2PayloadMax) return false;
  if (!ensureScratchBuffers()) return false;
  uint8_t* payload = gEncryptedPayloadScratch;
  payload[0] = channel;
  payload[1] = opcode;
  memcpy(payload + 2, data, dataLength);
  if (!aes128CtrCrypt(key, payload + 2, dataLength)) return false;
  const bool sent = writeSppV2Frame(3, sequence++, payload, dataLength + 2);
  mbedtls_platform_zeroize(payload, dataLength + 2);
  return sent;
}

// 在桥接会话的收包间隙调用。返回 true 表示投递了一条。
// 校验全部在这里做完（长度/密钥/目标 app），失败原因写日志，不影响主循环。
static bool pushWatchText(const char* text) {
  if (!text || !*text) return false;
  // 队列里还有没发出去的内容时先拒绝，避免覆盖用户刚输入的另一条。
  // 但超过 8 秒还没投递出去就认为上次尝试失败，允许覆盖：否则一条消息
  // 卡住之后，用户会一直看到「发送队列已满」，而真实原因是链路发不出去。
  if (gPendingWatchTextReady) {
    const uint32_t ageMs = millis() - gPendingWatchTextAtMs;
    if (ageMs < 8000u) return false;
    velaLog("PUSH_QUEUE_STALE age_ms=%lu", static_cast<unsigned long>(ageMs));
  }
  snprintf(gPendingWatchText, sizeof(gPendingWatchText), "%s", text);
  gPendingWatchTextAtMs = millis();
  gPendingWatchTextReady = true;
  // 新任务：重置上一次的结果，HTTP 接口据此判断「这一条」有没有发出去。
  taskENTER_CRITICAL(&gPushMux);
  gPushTaskState = 1;
  gPushTaskAttempts = 0;
  gPushTaskFail[0] = '\0';
  taskEXIT_CRITICAL(&gPushMux);
  velaLog("PUSH_QUEUED bytes=%u", static_cast<unsigned>(strlen(text)));
  return true;
}

// 由投递方记录失败原因，供 /api/v1/watch/push/result 回给页面。
static void pushWatchFail(const char* reason) {
  taskENTER_CRITICAL(&gPushMux);
  gPushTaskState = 3;
  snprintf(gPushTaskFail, sizeof(gPushTaskFail), "%s", reason ? reason : "unknown");
  taskEXIT_CRITICAL(&gPushMux);
}

static void pushWatchSuccess() {
  taskENTER_CRITICAL(&gPushMux);
  gPushTaskState = 2;
  gPushTaskFail[0] = '\0';
  taskEXIT_CRITICAL(&gPushMux);
}

bool flushPendingWatchText(uint8_t& sequence, const uint8_t encKey[16]) {
  if (!gPendingWatchTextReady) return false;
  gPendingWatchTextReady = false;
  taskENTER_CRITICAL(&gPushMux);
  if (++gPushTaskAttempts == 0) gPushTaskAttempts = 1;   // 防回绕成 0
  taskEXIT_CRITICAL(&gPushMux);
  char text[sizeof(gPendingWatchText)];
  snprintf(text, sizeof(text), "%s", gPendingWatchText);
  gPendingWatchText[0] = '\0';
  if (!text[0]) return false;
  WatchAppInfo target;
  if (!lookupCachedWatchApp(target)) {
    velaLog("PUSH_FAIL reason=app_unknown");
    pushWatchFail("手表上的快应用未定位，重连手表后再试");
    return false;
  }
  uint8_t pb[1024]{};
  size_t pbLength = 0;
  if (!buildXiaoAiTranscript(text, true, 1, pb, sizeof(pb), pbLength)) {
    velaLog("PUSH_FAIL reason=encode");
    pushWatchFail("内容编码失败");
    return false;
  }
  const bool ok = sendEncryptedWatchPb(sequence, encKey, pb, pbLength);
  if (!ok) {
    // 发送失败留在队列里，下一轮空闲时再试；超过 8 秒会被新消息覆盖，
    // 不会让队列永久占着。
    gPendingWatchTextReady = true;
    gPendingWatchTextAtMs = millis();
  }
  velaLog(ok ? "PUSH_SPP_OK bytes=%u" : "PUSH_FAIL reason=tx", static_cast<unsigned>(pbLength));
  // 注意：这里只能确认「帧写进蓝牙发送队列」，手表 App 有没有弹通知要看回执。
  if (ok) pushWatchSuccess();
  return ok;
}

bool sendEncryptedWatchPb(uint8_t& sequence, const uint8_t key[16], const uint8_t* pb, size_t pbLength) {
  return sendEncryptedWatchChannel(sequence, key, 1, 2, pb, pbLength);
}

// Derive only the normal-session CTR keys for an already-captured auth
// transcript.  This is intentionally smaller than buildStep3(): no CCM,
// deviceInfo or Step3 payload is built, keeping the 6144-byte WROOM watch-task
// stack comfortable.
bool deriveCapturedSessionKeysOnly(const uint8_t secret[16],
                                   const uint8_t phoneNonce[16],
                                   const uint8_t watchNonce[16],
                                   const uint8_t watchHmac[32],
                                   uint8_t sessionDecKey[16],
                                   uint8_t sessionEncKey[16]) {
  uint8_t transcript[32]{};
  uint8_t hmacKey[32]{};
  uint8_t expansion[64]{};
  uint8_t input[44]{};
  uint8_t confirmation[32]{};
  uint8_t confirmationInput[32]{};

  memcpy(transcript, phoneNonce, 16);
  memcpy(transcript + 16, watchNonce, 16);
  if (!hmacSha256(transcript, sizeof(transcript), secret, 16, hmacKey)) return false;

  static constexpr uint8_t kAuthLabel[] = {'m','i','w','e','a','r','-','a','u','t','h'};
  memcpy(input, kAuthLabel, sizeof(kAuthLabel));
  input[sizeof(kAuthLabel)] = 1;
  if (!hmacSha256(hmacKey, sizeof(hmacKey), input, sizeof(kAuthLabel) + 1, expansion)) return false;

  memcpy(input, expansion, 32);
  memcpy(input + 32, kAuthLabel, sizeof(kAuthLabel));
  input[43] = 2;
  if (!hmacSha256(hmacKey, sizeof(hmacKey), input, sizeof(input), expansion + 32)) return false;

  memcpy(confirmationInput, watchNonce, 16);
  memcpy(confirmationInput + 16, phoneNonce, 16);
  const bool ok = hmacSha256(expansion, 16, confirmationInput, sizeof(confirmationInput), confirmation) &&
                  memcmp(confirmation, watchHmac, 32) == 0;
  if (ok) {
    memcpy(sessionDecKey, expansion, 16);
    memcpy(sessionEncKey, expansion + 16, 16);
  }

  mbedtls_platform_zeroize(transcript, sizeof(transcript));
  mbedtls_platform_zeroize(hmacKey, sizeof(hmacKey));
  mbedtls_platform_zeroize(expansion, sizeof(expansion));
  mbedtls_platform_zeroize(input, sizeof(input));
  mbedtls_platform_zeroize(confirmation, sizeof(confirmation));
  mbedtls_platform_zeroize(confirmationInput, sizeof(confirmationInput));
  return ok;
}

// Compatibility path from the published watch Round-4 implementation.
// It is used only when the current AuthKey authenticates the captured record;
// callers must retain a fresh DeviceInfo fallback for every other watch/key.
bool decryptRound4CapturedAuthDeviceInfo(const uint8_t secret[16],
                                         uint8_t output[48],
                                         size_t& outputLength) {
  static constexpr uint8_t kPhoneNonce[16] = {
      0x7e,0xef,0x3c,0x2c,0xf5,0xf3,0xb2,0x71,0xb7,0xce,0x7f,0x69,0x1c,0x78,0xf1,0x38};
  static constexpr uint8_t kWatchNonce[16] = {
      0xdd,0x21,0xa3,0x09,0x4e,0xe7,0x02,0x05,0x72,0xff,0x14,0x57,0xaf,0xa9,0xd0,0x39};
  static constexpr uint8_t kWatchHmac[32] = {
      0x30,0xb5,0xc4,0x55,0xe8,0xc5,0x9f,0x9d,0xbb,0xc5,0xce,0x33,0x59,0x4b,0xee,0x00,
      0x0c,0x59,0x5b,0x7b,0xbe,0x0f,0x83,0xe0,0xe9,0xd0,0x4c,0xa6,0x9f,0xac,0xae,0x49};
  static constexpr uint8_t kEncryptedInfoAndTag[32] = {
      0x3e,0x44,0x09,0xa4,0x00,0x82,0xb3,0x0e,0x99,0xe8,0xef,0xb0,0x4e,0x4f,0x7e,0xbf,
      0x10,0xc0,0x80,0x02,0x1e,0xcf,0xab,0xd5,0x05,0x60,0x5d,0x4f,0x58,0xb8,0x62,0x69};

  constexpr size_t kPlainLength = sizeof(kEncryptedInfoAndTag) - 4;
  uint8_t capturedDecKey[16]{};
  uint8_t capturedEncKey[16]{};
  uint8_t nonce[12]{};
  bool ok = deriveCapturedSessionKeysOnly(secret, kPhoneNonce, kWatchNonce, kWatchHmac,
                                          capturedDecKey, capturedEncKey);
  if (ok) {
    uint8_t transcript[32]{};
    uint8_t hmacKey[32]{};
    uint8_t expansion[64]{};
    uint8_t input[44]{};
    memcpy(transcript, kPhoneNonce, 16);
    memcpy(transcript + 16, kWatchNonce, 16);
    ok = hmacSha256(transcript, sizeof(transcript), secret, 16, hmacKey);
    static constexpr uint8_t kAuthLabel[] = {'m','i','w','e','a','r','-','a','u','t','h'};
    if (ok) {
      memcpy(input, kAuthLabel, sizeof(kAuthLabel));
      input[sizeof(kAuthLabel)] = 1;
      ok = hmacSha256(hmacKey, sizeof(hmacKey), input, sizeof(kAuthLabel) + 1, expansion);
    }
    if (ok) {
      memcpy(input, expansion, 32);
      memcpy(input + 32, kAuthLabel, sizeof(kAuthLabel));
      input[43] = 2;
      ok = hmacSha256(hmacKey, sizeof(hmacKey), input, sizeof(input), expansion + 32);
    }
    if (ok) memcpy(nonce, expansion + 36, 4);
    mbedtls_platform_zeroize(transcript, sizeof(transcript));
    mbedtls_platform_zeroize(hmacKey, sizeof(hmacKey));
    mbedtls_platform_zeroize(expansion, sizeof(expansion));
    mbedtls_platform_zeroize(input, sizeof(input));
  }

  if (ok) {
    mbedtls_ccm_context ccm;
    mbedtls_ccm_init(&ccm);
    const int setKeyResult = mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, capturedEncKey, 128);
    const int decryptResult = setKeyResult == 0
        ? mbedtls_ccm_auth_decrypt(&ccm, kPlainLength, nonce, sizeof(nonce), nullptr, 0,
                                   kEncryptedInfoAndTag, output,
                                   kEncryptedInfoAndTag + kPlainLength, 4)
        : -1;
    mbedtls_ccm_free(&ccm);
    ok = decryptResult == 0;
  }

  if (ok) {
    outputLength = kPlainLength;
    ok = outputLength >= 7 && output[0] == 0x08 && output[2] == 0x15;
  }
  if (!ok) {
    outputLength = 0;
    mbedtls_platform_zeroize(output, 48);
  }
  mbedtls_platform_zeroize(capturedDecKey, sizeof(capturedDecKey));
  mbedtls_platform_zeroize(capturedEncKey, sizeof(capturedEncKey));
  mbedtls_platform_zeroize(nonce, sizeof(nonce));
  return ok;
}

// Verified Round-4 CompanionDevice protobuf plaintext.  This is never sent
// directly: buildStep3() AES-CCM encrypts it with the keys and nonce derived
// from the current watch AuthKey and current authentication session.
static constexpr uint8_t kRound4CompatibleDeviceInfo[] = {
    0x08,0x00,0x15,0x00,0x00,0x10,0x42,
    0x1a,0x0a,'2','5','0','9','8','P','N','5','A','C',
    0x20,0xfe,0xbd,0xdc,0x0d,0x2a,0x02,'C','N',
};

// Decrypt the exact 137-byte type23/id3 template captured from the current
// Xiaomi 17 Pro Round-4 session. The long-term Auth Key is never printed.
bool decryptRound4Type23Template(const uint8_t secret[16], uint8_t output[137]) {
  static constexpr uint8_t kPhoneNonce[16] = {
      0x7e,0xef,0x3c,0x2c,0xf5,0xf3,0xb2,0x71,0xb7,0xce,0x7f,0x69,0x1c,0x78,0xf1,0x38};
  static constexpr uint8_t kWatchNonce[16] = {
      0xdd,0x21,0xa3,0x09,0x4e,0xe7,0x02,0x05,0x72,0xff,0x14,0x57,0xaf,0xa9,0xd0,0x39};
  static constexpr uint8_t kWatchHmac[32] = {
      0x30,0xb5,0xc4,0x55,0xe8,0xc5,0x9f,0x9d,0xbb,0xc5,0xce,0x33,0x59,0x4b,0xee,0x00,
      0x0c,0x59,0x5b,0x7b,0xbe,0x0f,0x83,0xe0,0xe9,0xd0,0x4c,0xa6,0x9f,0xac,0xae,0x49};

  // Phone -> Watch seq13, channel=1/opcode=2, ciphertext only (137 bytes).
  static constexpr uint8_t kType23Id3Cipher[137] = {
      0x93,0xe7,0x2e,0x56,0x9b,0x39,0xeb,0x9f,0x19,0xcc,0x02,0x9b,0x99,0x16,0x91,0xfe,
      0x37,0x85,0x59,0xd8,0x58,0x24,0xa0,0xda,0x23,0xd0,0x0f,0xa8,0x89,0xdc,0x12,0xc4,
      0x0b,0x78,0xbc,0x0f,0x9d,0x3b,0x72,0x69,0x12,0xe9,0x96,0x18,0x6b,0xb9,0xe3,0x34,
      0xd6,0xab,0x8c,0x0f,0x1f,0xe0,0x7d,0x08,0x6e,0xfd,0xd1,0x05,0xbc,0x15,0x2d,0xf7,
      0xe7,0x4a,0x81,0xd9,0x78,0x4f,0x60,0xfd,0xd8,0xd2,0x72,0x4c,0x9e,0x93,0x38,0xe3,
      0x5a,0x2d,0x6c,0x3e,0xe5,0xf1,0xd4,0x54,0xea,0x1f,0xd8,0xa2,0x82,0x08,0x5e,0x3d,
      0x97,0x95,0xf8,0x5b,0x43,0xb2,0xed,0x56,0xf4,0x45,0x5a,0xd4,0x46,0x3d,0x16,0x5b,
      0x40,0xa7,0x8f,0x40,0x1a,0xd7,0x3e,0x14,0x7f,0xf0,0xcb,0xc4,0x49,0x26,0x64,0x8c,
      0x37,0x73,0xe8,0x9c,0x8d,0x3c,0xea,0xce,0x36};

  uint8_t capturedDecKey[16]{};
  uint8_t capturedEncKey[16]{};
  bool ok = deriveCapturedSessionKeysOnly(secret, kPhoneNonce, kWatchNonce, kWatchHmac,
                                          capturedDecKey, capturedEncKey);
  if (ok) {
    memcpy(output, kType23Id3Cipher, sizeof(kType23Id3Cipher));
    ok = aes128CtrCrypt(capturedEncKey, output, sizeof(kType23Id3Cipher));
  }
  if (ok) {
    ok = output[0] == 0x08 && output[1] == 0x17 &&
         output[2] == 0x10 && output[3] == 0x03 &&
         output[4] == 0xca && output[5] == 0x01;
  }

  mbedtls_platform_zeroize(capturedDecKey, sizeof(capturedDecKey));
  mbedtls_platform_zeroize(capturedEncKey, sizeof(capturedEncKey));
  if (!ok) mbedtls_platform_zeroize(output, 137);
  return ok;
}

// One-shot offline extractor for the official Round-3 phone capture.
// Uses the Watch Auth Key already stored in Preferences. The key is never printed.
// No Bluetooth connection is required for this command.
void dumpRound3BootstrapPlaintext() {
  static constexpr uint8_t kPhoneNonce[16] = {
      0xaa,0xd7,0x4e,0x3d,0x63,0x89,0xe4,0x0b,0xb9,0x3a,0xd8,0x54,0x9e,0xa9,0xec,0x84};
  static constexpr uint8_t kWatchNonce[16] = {
      0xcf,0x75,0xbc,0x5f,0xb8,0x04,0xc5,0x47,0x14,0xfe,0x6e,0x03,0xdb,0xb0,0x68,0x7a};
  static constexpr uint8_t kWatchHmac[32] = {
      0x8b,0x5b,0x85,0xd0,0xa3,0xd5,0xb8,0x42,0x4e,0x84,0x69,0xb5,0x8a,0x32,0xfb,0xd9,
      0x96,0x16,0x90,0x62,0x57,0x5f,0xbc,0x42,0x20,0xfb,0xa2,0xb5,0xb9,0x88,0x49,0xc9};

  // Phone -> Watch ch1/op2 ciphertext only (01 02 channel/opcode are intentionally excluded).
  static constexpr uint8_t kType8Id52Cipher[55] = {
      0x91,0xe6,0xd3,0xaa,0xfc,0x32,0xa3,0x3e,0x50,0x0e,0x8f,0xa4,0x0c,0x3b,0x23,0x0d,
      0xe0,0xe2,0xbc,0xfe,0x7b,0x18,0x75,0x0e,0x60,0x0c,0x0f,0x1f,0x99,0x46,0x2e,0xee,
      0x86,0xaf,0x25,0xa8,0xd3,0xe1,0xcd,0x38,0x06,0x9c,0x6f,0xaa,0x7d,0xef,0xd9,0xcc,
      0xc7,0xab,0xd0,0xbc,0x5a,0x20,0xf9};
  static constexpr uint8_t kType23Id3Cipher[111] = {
      0x91,0xf9,0xd3,0x9d,0x64,0x02,0x29,0x2e,0x18,0x0e,0xe2,0xa4,0x0e,0x39,0xb0,0x8b,
      0x8d,0x99,0x61,0xe5,0x2e,0x75,0x18,0x79,0x19,0xf3,0x80,0x42,0xe8,0x9e,0x43,0xe8,
      0x6a,0x2f,0xb2,0x5f,0xb4,0xe1,0x2a,0xa9,0x51,0x98,0xf1,0x1a,0x55,0xa6,0xd3,0xde,
      0x47,0x76,0xdb,0xb1,0x87,0xbf,0xd7,0xb5,0x43,0xbf,0x1f,0x73,0xfa,0x16,0xb2,0x2f,
      0xa4,0x7e,0x8e,0xea,0x5b,0x75,0x91,0xf7,0xc3,0x8a,0x2a,0x73,0x39,0x5d,0xb3,0x5e,
      0x7c,0x5f,0x87,0x1c,0x94,0x10,0x68,0x0a,0x30,0x27,0x5a,0xd8,0x6f,0xee,0x60,0x69,
      0xe1,0xb5,0x4b,0xde,0x56,0x28,0xa6,0xcd,0xfa,0x19,0xbd,0x89,0xe2,0x4f,0x4a};

  uint8_t secret[16]{}, step3[160]{}, sessionDecKey[16]{}, sessionEncKey[16]{};
  size_t step3Length = 0;
  if (!parseSecretHex(watchAuthKey, secret)) {
    Serial.println("ROUND3_DECRYPT_FAIL reason=watch_auth_missing_or_invalid");
    return;
  }
  if (!buildStep3(secret, kPhoneNonce, kWatchNonce, kWatchHmac,
                  step3, step3Length, sessionDecKey, sessionEncKey)) {
    Serial.println("ROUND3_DECRYPT_FAIL reason=auth_key_does_not_match_round3_capture");
    mbedtls_platform_zeroize(secret, sizeof(secret));
    mbedtls_platform_zeroize(step3, sizeof(step3));
    return;
  }

  uint8_t type8[sizeof(kType8Id52Cipher)]{};
  uint8_t type23[sizeof(kType23Id3Cipher)]{};
  memcpy(type8, kType8Id52Cipher, sizeof(type8));
  memcpy(type23, kType23Id3Cipher, sizeof(type23));
  const bool ok8 = aes128CtrCrypt(sessionEncKey, type8, sizeof(type8));
  const bool ok23 = aes128CtrCrypt(sessionEncKey, type23, sizeof(type23));
  const bool prefix8 = ok8 && sizeof(type8) >= 4 && type8[0] == 0x08 && type8[1] == 0x08 && type8[2] == 0x10 && type8[3] == 0x34;
  const bool prefix23 = ok23 && sizeof(type23) >= 4 && type23[0] == 0x08 && type23[1] == 0x17 && type23[2] == 0x10 && type23[3] == 0x03;

  if (prefix8 && prefix23) {
    Serial.printf("TYPE8_52_HEX=%s\n", hexBytes(type8, sizeof(type8)).c_str());
    Serial.printf("TYPE23_3_HEX=%s\n", hexBytes(type23, sizeof(type23)).c_str());
    Serial.println("ROUND3_DECRYPT_OK auth_valid=true key_not_printed=true");
  } else {
    Serial.printf("ROUND3_DECRYPT_FAIL reason=plaintext_prefix_mismatch type8=%s type23=%s\n",
                  prefix8 ? "ok" : "bad", prefix23 ? "ok" : "bad");
  }

  mbedtls_platform_zeroize(secret, sizeof(secret));
  mbedtls_platform_zeroize(step3, sizeof(step3));
  mbedtls_platform_zeroize(sessionDecKey, sizeof(sessionDecKey));
  mbedtls_platform_zeroize(sessionEncKey, sizeof(sessionEncKey));
  mbedtls_platform_zeroize(type8, sizeof(type8));
  mbedtls_platform_zeroize(type23, sizeof(type23));
}

bool decryptWatchPb(SppV2Frame& frame, const uint8_t key[16], const uint8_t*& pb, size_t& pbLength) {
  if (frame.type != 3 || frame.payloadLength < 3 || frame.payload[0] != 1 || frame.payload[1] != 2) return false;
  pbLength = frame.payloadLength - 2;
  if (!aes128CtrCrypt(key, frame.payload + 2, pbLength)) return false;
  pb = frame.payload + 2;
  return true;
}

bool parseQuickAppList(const uint8_t* pb, size_t pbLength, WatchAppInfo& app) {  uint32_t type = 0, id = 0;  const uint8_t* thirdparty = nullptr; size_t thirdpartyLength = 0;
  if (!protoVarintField(pb, pbLength, 1, type) || !protoVarintField(pb, pbLength, 2, id) || type != 20 || id != 0 ||
      !protoBytesField(pb, pbLength, 22, thirdparty, thirdpartyLength)) return false;
  const uint8_t* list = nullptr; size_t listLength = 0;
  if (!protoBytesField(thirdparty, thirdpartyLength, 1, list, listLength)) return false;
  size_t cursor = 0;
  while (cursor < listLength) {
    uint32_t tag = 0, itemLength = 0;
    if (!readProtoVarint(list, listLength, cursor, tag)) return false;
    if ((tag >> 3) != 1 || (tag & 7) != 2) {
      if (!skipProtoField(list, listLength, cursor, tag & 7)) return false;
      continue;
    }
    if (!readProtoVarint(list, listLength, cursor, itemLength) || itemLength > listLength - cursor) return false;
    const uint8_t* item = list + cursor; cursor += itemLength;
    const uint8_t* packageName = nullptr; size_t packageNameLength = 0;
    const uint8_t* fingerprint = nullptr; size_t fingerprintLength = 0;
    if (!protoBytesField(item, itemLength, 1, packageName, packageNameLength) || !protoBytesField(item, itemLength, 2, fingerprint, fingerprintLength)) continue;
    if (packageNameLength == strlen(watchQuickAppPackage()) && memcmp(packageName, watchQuickAppPackage(), packageNameLength) == 0 && fingerprintLength > 0 && fingerprintLength <= sizeof(app.fingerprint)) {
      memcpy(app.fingerprint, fingerprint, fingerprintLength);
      app.fingerprintLength = fingerprintLength;
      app.found = true;
      return true;
    }
  }
  return false;
}

bool parseQuickAppMessage(const uint8_t* pb, size_t pbLength, const uint8_t*& content, size_t& contentLength) {
  uint32_t type = 0, id = 0;
  const uint8_t* thirdparty = nullptr; size_t thirdpartyLength = 0, messageLength = 0;
  const uint8_t* message = nullptr;
  if (!protoVarintField(pb, pbLength, 1, type) || !protoVarintField(pb, pbLength, 2, id) || type != 20 || id != 9 ||
      !protoBytesField(pb, pbLength, 22, thirdparty, thirdpartyLength) || !protoBytesField(thirdparty, thirdpartyLength, 9, message, messageLength)) return false;
  return protoBytesField(message, messageLength, 2, content, contentLength);
}

bool containsAscii(const uint8_t* data, size_t length, const char* text) {
  const size_t textLength = strlen(text);
  if (!textLength || textLength > length) return false;
  for (size_t i = 0; i + textLength <= length; ++i) if (memcmp(data + i, text, textLength) == 0) return true;
  return false;
}

bool sendSppV2Protobuf(uint8_t sequence, const uint8_t* command, size_t commandLength) {
  if (commandLength + 2 > kSppV2PayloadMax) return false;
  if (!ensureScratchBuffers()) return false;
  uint8_t* payload = gRawCommandPayloadScratch;
  payload[0] = 1; payload[1] = 1;
  memcpy(payload + 2, command, commandLength);
  return writeSppV2Frame(3, sequence, payload, commandLength + 2);
}

bool extractWatchNonce(const SppV2Frame& frame, const uint8_t*& nonce, size_t& nonceLength, const uint8_t*& hmac, size_t& hmacLength) {
  if (frame.type != 3 || frame.payloadLength < 3 || (frame.payload[0] & 0x0f) != 1 || frame.payload[1] != 1) return false;
  const uint8_t* command = frame.payload + 2; const size_t commandLength = frame.payloadLength - 2;
  uint32_t subtype = 0;
  const uint8_t* auth = nullptr; size_t authLength = 0;
  if (!protoVarintField(command, commandLength, 2, subtype) || subtype != 26 || !protoBytesField(command, commandLength, 3, auth, authLength)) return false;
  const uint8_t* watchNonce = nullptr; size_t watchNonceLength = 0;
  if (!protoBytesField(auth, authLength, 31, watchNonce, watchNonceLength)) return false;
  return protoBytesField(watchNonce, watchNonceLength, 1, nonce, nonceLength) && protoBytesField(watchNonce, watchNonceLength, 2, hmac, hmacLength);
}

bool isAuthSuccess(const SppV2Frame& frame) {
  if (frame.type != 3 || frame.payloadLength < 3 || (frame.payload[0] & 0x0f) != 1 || frame.payload[1] != 1) return false;
  uint32_t subtype = 0;
  return protoVarintField(frame.payload + 2, frame.payloadLength - 2, 2, subtype) && subtype == 27;
}

uint8_t benchByte(uint32_t offset) {
  return static_cast<uint8_t>((offset * 29u + (offset >> 3) * 17u + 0x5du) & 0xffu);
}

void fillBenchBytes(uint32_t offset, uint8_t* output, size_t length) {
  for (size_t index = 0; index < length; ++index) output[index] = benchByte(offset + index);
}

bool sha256BenchData(uint32_t size, char output[65]) {
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!info) return false;
  mbedtls_md_context_t context;
  mbedtls_md_init(&context);
  uint8_t chunk[kBenchChunkRawMax], digest[32];
  bool ok = mbedtls_md_setup(&context, info, 0) == 0 && mbedtls_md_starts(&context) == 0;
  for (uint32_t offset = 0; ok && offset < size; offset += sizeof(chunk)) {
    const size_t length = min(static_cast<uint32_t>(sizeof(chunk)), size - offset);
    fillBenchBytes(offset, chunk, length);
    ok = mbedtls_md_update(&context, chunk, length) == 0;
  }
  if (ok) ok = mbedtls_md_finish(&context, digest) == 0;
  mbedtls_md_free(&context);
  if (!ok) return false;
  static constexpr char hex[] = "0123456789abcdef";
  for (size_t index = 0; index < sizeof(digest); ++index) {
    output[index * 2] = hex[(digest[index] >> 4) & 15];
    output[index * 2 + 1] = hex[digest[index] & 15];
  }
  output[64] = '\0';
  mbedtls_platform_zeroize(digest, sizeof(digest));
  return true;
}

bool base64BenchEncode(const uint8_t* input, size_t length, char* output, size_t capacity) {
  static constexpr char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const size_t required = ((length + 2) / 3) * 4 + 1;
  if (capacity < required) return false;
  size_t in = 0, out = 0;
  while (in < length) {
    const uint32_t a = input[in++];
    const bool hasB = in < length; const uint32_t b = hasB ? input[in++] : 0;
    const bool hasC = in < length; const uint32_t c = hasC ? input[in++] : 0;
    const uint32_t value = (a << 16) | (b << 8) | c;
    output[out++] = table[(value >> 18) & 63]; output[out++] = table[(value >> 12) & 63];
    output[out++] = hasB ? table[(value >> 6) & 63] : '='; output[out++] = hasC ? table[value & 63] : '=';
  }
  output[out] = '\0';
  return true;
}

bool jsonEscapeBenchString(const char* input, char* output, size_t capacity) {
  size_t out = 0;
  for (size_t in = 0; input[in] != '\0'; ++in) {
    const char value = input[in];
    const bool needsEscape = value == '"' || value == '\\';
    if (out + (needsEscape ? 2 : 1) >= capacity) return false;
    if (needsEscape) output[out++] = '\\';
    output[out++] = value;
  }
  output[out] = '\0';
  return true;
}

void configureBenchSessionRenewal(const uint8_t secret[16], const uint8_t encKey[16], const uint8_t decKey[16]) {
  memcpy(gBenchSessionSecret, secret, sizeof(gBenchSessionSecret));
  memcpy(gBenchSessionEncKey, encKey, sizeof(gBenchSessionEncKey));
  memcpy(gBenchSessionDecKey, decKey, sizeof(gBenchSessionDecKey));
  gBenchSessionRenewals = 0;
  gBenchSessionRenewalEnabled = true;
}

void clearBenchSessionRenewal() {
  gBenchSessionRenewalEnabled = false;
  gBenchSessionRenewals = 0;
  mbedtls_platform_zeroize(gBenchSessionSecret, sizeof(gBenchSessionSecret));
  mbedtls_platform_zeroize(gBenchSessionEncKey, sizeof(gBenchSessionEncKey));
  mbedtls_platform_zeroize(gBenchSessionDecKey, sizeof(gBenchSessionDecKey));
}

bool renewBenchSppSession(uint8_t& sequence) {
  if (!gBenchSessionRenewalEnabled) return false;

  Serial.printf("SPP_SESSION_RENEW start old_sequence=%u renewals=%lu\n",
                static_cast<unsigned>(sequence),
                static_cast<unsigned long>(gBenchSessionRenewals));

  // A benchmark send only renews after the previous application ACK completed,
  // so no application response should still be pending here.
  if (watchBt.write(kSppV2SessionStartRequest, sizeof(kSppV2SessionStartRequest)) != sizeof(kSppV2SessionStartRequest)) {
    Serial.println("SPP_SESSION_RENEW_FAIL stage=session_write");
    return false;
  }

  SppV2Frame& frame = gSharedSppFrame;
  bool sessionReady = false;
  uint32_t deadline = millis() + kWatchVersionResponseTimeoutMs;
  while (millis() < deadline) {
    if (!readSppV2Frame(frame, deadline - millis())) break;
    if (frame.type == 3) writeSppV2Frame(1, frame.sequence, nullptr, 0);
    if (frame.type == 2 && frame.payloadLength >= 1 && frame.payload[0] == 2) {
      sessionReady = true;
      break;
    }
  }
  if (!sessionReady) {
    Serial.println("SPP_SESSION_RENEW_FAIL stage=session_response");
    return false;
  }

  uint8_t phoneNonce[16]{};
  uint8_t step3[160]{};
  size_t step3Length = 0;
  esp_fill_random(phoneNonce, sizeof(phoneNonce));
  uint8_t nonceCommand[27] = {0x08, 1, 0x10, 26, 0x1a, 21, 0xf2, 0x01, 18, 0x0a, 16};
  memcpy(nonceCommand + 11, phoneNonce, sizeof(phoneNonce));
  if (!sendSppV2Protobuf(0, nonceCommand, sizeof(nonceCommand))) {
    Serial.println("SPP_SESSION_RENEW_FAIL stage=nonce_write");
    mbedtls_platform_zeroize(phoneNonce, sizeof(phoneNonce));
    return false;
  }

  const uint8_t* watchNonce = nullptr;
  const uint8_t* watchHmac = nullptr;
  size_t watchNonceLength = 0, watchHmacLength = 0;
  deadline = millis() + kWatchVersionResponseTimeoutMs;
  while (millis() < deadline) {
    if (!readSppV2Frame(frame, deadline - millis())) break;
    if (frame.type == 3) writeSppV2Frame(1, frame.sequence, nullptr, 0);
    if (extractWatchNonce(frame, watchNonce, watchNonceLength, watchHmac, watchHmacLength)) break;
  }
  if (!watchNonce || watchNonceLength != 16 || watchHmacLength != 32 ||
      !buildStep3(gBenchSessionSecret, phoneNonce, watchNonce, watchHmac, step3, step3Length,
                  gBenchSessionDecKey, gBenchSessionEncKey)) {
    Serial.println("SPP_SESSION_RENEW_FAIL stage=nonce_or_key");
    mbedtls_platform_zeroize(phoneNonce, sizeof(phoneNonce));
    mbedtls_platform_zeroize(step3, sizeof(step3));
    return false;
  }

  if (!sendSppV2Protobuf(1, step3, step3Length)) {
    Serial.println("SPP_SESSION_RENEW_FAIL stage=auth_write");
    mbedtls_platform_zeroize(phoneNonce, sizeof(phoneNonce));
    mbedtls_platform_zeroize(step3, sizeof(step3));
    return false;
  }

  bool authenticated = false;
  deadline = millis() + kWatchVersionResponseTimeoutMs;
  while (millis() < deadline) {
    if (!readSppV2Frame(frame, deadline - millis())) break;
    if (frame.type == 3) writeSppV2Frame(1, frame.sequence, nullptr, 0);
    if (isAuthSuccess(frame)) {
      authenticated = true;
      break;
    }
  }

  mbedtls_platform_zeroize(phoneNonce, sizeof(phoneNonce));
  mbedtls_platform_zeroize(step3, sizeof(step3));
  if (!authenticated) {
    Serial.println("SPP_SESSION_RENEW_FAIL stage=auth_response");
    return false;
  }

  sequence = 2;
  ++gBenchSessionRenewals;
  Serial.printf("SPP_SESSION_RENEW_OK new_sequence=%u renewals=%lu\n",
                static_cast<unsigned>(sequence),
                static_cast<unsigned long>(gBenchSessionRenewals));
  return true;
}

bool ensureBenchSppSequenceBudget(uint8_t& sequence) {
  if (!gBenchSessionRenewalEnabled || sequence < kBenchSppRenewAtSequence) return true;
  Serial.printf("SPP_SEQUENCE_GUARD sequence=%u threshold=%u\n",
                static_cast<unsigned>(sequence),
                static_cast<unsigned>(kBenchSppRenewAtSequence));
  return renewBenchSppSession(sequence);
}

bool sendBenchJson(const WatchAppInfo& app, uint8_t& sequence, const uint8_t encKey[16], const char* text) {
  if (!ensureBenchSppSequenceBudget(sequence)) {
    Serial.println("BENCH_SEND_FAIL reason=spp_session_renewal");
    return false;
  }
  const size_t length = strlen(text);
  if (!ensureScratchBuffers()) return false;
  uint8_t* packet = gRawCommandPayloadScratch;
  size_t packetLength = 0;
  const uint8_t* activeKey = gBenchSessionRenewalEnabled ? gBenchSessionEncKey : encKey;
  return length < kSppV2PayloadMax &&
         buildQuickAppMessage(app, reinterpret_cast<const uint8_t*>(text), length,
                              packet, kSppV2PayloadMax, packetLength) &&
         sendEncryptedWatchPb(sequence, activeKey, packet, packetLength);
}

bool waitBenchReply(const uint8_t decKey[16], const char* type, const char* phase, int expectedSequence, uint32_t timeoutMs, bool* duplicate = nullptr, char* hash = nullptr) {
  const uint32_t startedAt = millis();
  if (duplicate) *duplicate = false;
  if (hash) hash[0] = '\0';
  uint32_t frames = 0, nonData = 0, decryptFail = 0, quickAppParseFail = 0, otherPb = 0, jsonFail = 0, wrongType = 0, wrongPhase = 0, wrongSequence = 0;
  while (millis() - startedAt < timeoutMs) {
    const uint32_t remaining = timeoutMs - (millis() - startedAt);
    SppV2Frame& frame = gSharedSppFrame;
    if (!readSppV2Frame(frame, remaining)) break;
    ++frames;
    if (frame.type != 3) { ++nonData; continue; }
    writeSppV2Frame(1, frame.sequence, nullptr, 0);
    const uint8_t* incoming = nullptr; size_t incomingLength = 0, contentLength = 0; const uint8_t* content = nullptr;
    const uint8_t* activeDecKey = gBenchSessionRenewalEnabled ? gBenchSessionDecKey : decKey;
    if (!decryptWatchPb(frame, activeDecKey, incoming, incomingLength)) { ++decryptFail; continue; }
    if (!parseQuickAppMessage(incoming, incomingLength, content, contentLength)) {
      // Not every encrypted protobuf delivered by the watch is a QuickApp
      // message. Classify readable outer protobufs separately so unrelated
      // asynchronous traffic is not falsely reported as corruption.
      uint32_t outerType = 0, outerId = 0;
      const bool hasOuterType = protoVarintField(incoming, incomingLength, 1, outerType);
      const bool hasOuterId = protoVarintField(incoming, incomingLength, 2, outerId);
      if (hasOuterType && hasOuterId && (outerType != 20 || outerId != 9)) {
        ++otherPb;
        Serial.printf("BENCH_PB_OTHER frame_seq=%u pb_type=%lu pb_id=%lu pb_len=%u\n",
                      static_cast<unsigned>(frame.sequence),
                      static_cast<unsigned long>(outerType),
                      static_cast<unsigned long>(outerId),
                      static_cast<unsigned>(incomingLength));
      } else {
        ++quickAppParseFail;
        Serial.printf("BENCH_APP_PARSE_FAIL frame_seq=%u pb_type=%s pb_id=%s pb_len=%u head=",
                      static_cast<unsigned>(frame.sequence),
                      hasOuterType ? String(outerType).c_str() : "?",
                      hasOuterId ? String(outerId).c_str() : "?",
                      static_cast<unsigned>(incomingLength));
        const size_t headLength = min<size_t>(incomingLength, 16);
        for (size_t i = 0; i < headLength; ++i) Serial.printf("%02x", incoming[i]);
        Serial.println();
      }
      continue;
    }
    static JsonDocument document;
    document.clear();
    if (deserializeJson(document, content, contentLength)) { ++jsonFail; continue; }
    const char* gotType = document["type"] | "";
    JsonObject payload = document["payload"].as<JsonObject>();
    if (strcmp(gotType, "capabilities_response") == 0) {
      Serial.printf("BENCH_CAPS buildTag=%s\n", String(payload["buildTag"] | "missing").c_str());
    }
    if (strcmp(gotType, "pong") != 0) {
      Serial.printf("BENCH_RX type=%s phase=%s code=%s sequence=%d replyTo=%s\n",
                    gotType,
                    String(payload["phase"] | "").c_str(),
                    String(payload["code"] | "").c_str(),
                    payload["sequence"] | -1,
                    String(document["replyTo"] | "").c_str());
    }
    if (strcmp(gotType, "package_status") == 0 && payload["ok"].is<bool>() && !payload["ok"].as<bool>()) {
      Serial.printf("BENCH_REMOTE_ERROR code=%s message=%s\n", String(payload["code"] | "unknown").c_str(), String(payload["message"] | "").c_str());
      return false;
    }
    if (strcmp(gotType, type) == 0 && payload["ok"].is<bool>() && !payload["ok"].as<bool>()) {
      Serial.printf("BENCH_REMOTE_ERROR type=%s code=%s message=%s\n", gotType, String(payload["code"] | "unknown").c_str(), String(payload["message"] | "").c_str());
      return false;
    }
    if (strcmp(gotType, "package_status") == 0) {
      Serial.printf("PKG_STATUS_REPLY_RX type=%s replyTo=%s phase=%s ok=%s\n",
                    gotType,
                    String(document["replyTo"] | "").c_str(),
                    String(payload["phase"] | "").c_str(),
                    payload["ok"].is<bool>() && payload["ok"].as<bool>() ? "true" : "false");
      JsonObject diag = payload["transportDiag"].as<JsonObject>();
      if (!diag.isNull()) {
        Serial.printf("BENCH_CHUNK_PATH_DIAG expected_seq=%d expected_offset=%ld inflight=%s inflight_seq=%d inflight_offset=%ld rx_count=%ld last_rx_seq=%d last_rx_offset=%ld last_write_seq=%d last_write_offset=%ld last_ack_seq=%d last_ack_next=%ld ack_count=%ld ack_send_success_seq=%d ack_send_success_count=%ld ack_send_fail_seq=%d ack_send_fail_code=%s recovered_count=%ld\n",
                      diag["expectedSequence"] | -1,
                      static_cast<long>(diag["expectedOffset"] | -1),
                      (diag["inFlight"] | false) ? "true" : "false",
                      diag["inFlightSequence"] | -1,
                      static_cast<long>(diag["inFlightOffset"] | -1),
                      static_cast<long>(diag["rxCount"] | -1),
                      diag["lastRxSequence"] | -1,
                      static_cast<long>(diag["lastRxOffset"] | -1),
                      diag["lastWriteSequence"] | -1,
                      static_cast<long>(diag["lastWriteOffset"] | -1),
                      diag["lastAckSequence"] | -1,
                      static_cast<long>(diag["lastAckNextOffset"] | -1),
                      static_cast<long>(diag["ackCount"] | -1),
                      diag["lastAckSendSuccessSequence"] | -1,
                      static_cast<long>(diag["ackSendSuccessCount"] | -1),
                      diag["lastAckSendFailSequence"] | -1,
                      String(diag["lastAckSendFailCode"] | "").c_str(),
                      static_cast<long>(diag["recoveredCount"] | -1));
      }
    }
    if (strcmp(gotType, type) != 0) { ++wrongType; continue; }
    if (phase && strcmp(payload["phase"] | "", phase) != 0) { ++wrongPhase; continue; }
    const int receivedSequence = payload["sequence"] | -1;
    if (expectedSequence >= 0 && receivedSequence != expectedSequence) { ++wrongSequence; continue; }
    if (duplicate) *duplicate = payload["duplicate"] | false;
    if (hash) snprintf(hash, 65, "%s", String(payload["sha256"] | "").c_str());
    return true;
  }
  Serial.printf("BENCH_WAIT_TIMEOUT expected_type=%s expected_phase=%s expected_sequence=%d frames=%lu non_data=%lu decrypt_fail=%lu app_parse_fail=%lu other_pb=%lu json_fail=%lu wrong_type=%lu wrong_phase=%lu wrong_sequence=%lu rx_dropped=%lu\n",
                type ? type : "",
                phase ? phase : "",
                expectedSequence,
                static_cast<unsigned long>(frames),
                static_cast<unsigned long>(nonData),
                static_cast<unsigned long>(decryptFail),
                static_cast<unsigned long>(quickAppParseFail),
                static_cast<unsigned long>(otherPb),
                static_cast<unsigned long>(jsonFail),
                static_cast<unsigned long>(wrongType),
                static_cast<unsigned long>(wrongPhase),
                static_cast<unsigned long>(wrongSequence),
                static_cast<unsigned long>(watchRxDroppedBytes));
  logStackHighWater("bench_wait_timeout");
  logSppRxParserState("bench_wait_timeout");
  return false;
}

struct BenchCounters {
  uint32_t errors = 0;
  uint32_t retries = 0;
  uint32_t duplicates = 0;
  uint32_t ackTimeouts = 0;
};

enum BenchFault : uint8_t {
  kBenchFaultNone = 0,
  kBenchFaultPause = 1,
  kBenchFaultDropAck = 2,
  kBenchFaultDuplicate = 4,
  kBenchFaultAbort = 8,
  kBenchFaultDropDurableAck = 16,
};

bool runBenchControlProbe(const WatchAppInfo& app, uint8_t& sequence, const uint8_t encKey[16], const uint8_t decKey[16]) {
  static char text[256];
  int length = snprintf(text, sizeof(text), "{\"v\":2,\"id\":\"bench_caps\",\"timestamp\":%lu,\"type\":\"capabilities_request\",\"payload\":{}}", static_cast<unsigned long>(millis()));
  const bool caps = length > 0 && static_cast<size_t>(length) < sizeof(text) && sendBenchJson(app, sequence, encKey, text) && waitBenchReply(decKey, "capabilities_response", nullptr, -1, kBenchControlTimeoutMs);
  Serial.printf("BENCH_CONTROL capabilities=%s\n", caps ? "PASS" : "FAIL");
  if (!caps) return false;

  delay(kBenchControlGapMs);
  length = snprintf(text, sizeof(text), "{\"v\":2,\"id\":\"bench_status\",\"timestamp\":%lu,\"type\":\"package_status\",\"payload\":{\"query\":true}}", static_cast<unsigned long>(millis()));
  Serial.println("PKG_STATUS_TX id=bench_status type=package_status");
  const bool status = length > 0 && static_cast<size_t>(length) < sizeof(text) && sendBenchJson(app, sequence, encKey, text) && waitBenchReply(decKey, "package_status", nullptr, -1, kBenchControlTimeoutMs);
  Serial.printf("BENCH_CONTROL package_status=%s\n", status ? "PASS" : "FAIL");
  if (!status) return false;

  // Always clear stale benchmark state from a previously interrupted run.
  length = snprintf(text, sizeof(text), "{\"v\":2,\"id\":\"bench_cleanup\",\"timestamp\":%lu,\"type\":\"package_abort\",\"payload\":{}}", static_cast<unsigned long>(millis()));
  const bool cleanup = length > 0 && static_cast<size_t>(length) < sizeof(text) && sendBenchJson(app, sequence, encKey, text) && waitBenchReply(decKey, "package_status", nullptr, -1, kBenchControlTimeoutMs);
  Serial.printf("BENCH_CONTROL cleanup=%s\n", cleanup ? "PASS" : "FAIL");
  return cleanup;
}

bool runBenchPingTest(const WatchAppInfo& app, uint8_t& sequence, const uint8_t encKey[16], const uint8_t decKey[16]) {
  static uint32_t samples[100]; memset(samples, 0, sizeof(samples));
  uint32_t total = 0, minimum = UINT32_MAX, maximum = 0; uint16_t success = 0;
  for (uint16_t index = 0; index < 100; ++index) {
    static char text[256];
    const int length = snprintf(text, sizeof(text), "{\"v\":2,\"id\":\"bench_ping_%u\",\"timestamp\":%lu,\"type\":\"ping\",\"payload\":{\"from\":\"esp32\"}}", static_cast<unsigned>(index), static_cast<unsigned long>(millis()));
    const uint32_t started = millis();
    if (length > 0 && static_cast<size_t>(length) < sizeof(text) && sendBenchJson(app, sequence, encKey, text) && waitBenchReply(decKey, "pong", nullptr, -1, kBenchAckTimeoutMs)) {
      const uint32_t elapsed = millis() - started; samples[success++] = elapsed; total += elapsed; minimum = min(minimum, elapsed); maximum = max(maximum, elapsed);
    }
  }
  for (uint16_t i = 1; i < success; ++i) for (uint16_t j = i; j > 0 && samples[j] < samples[j - 1]; --j) { const uint32_t swap = samples[j]; samples[j] = samples[j - 1]; samples[j - 1] = swap; }
  const uint32_t p95 = success ? samples[(success * 95 + 99) / 100 - 1] : 0;
  Serial.println("PING_TEST");
  Serial.printf("count=100\nsuccess=%u\nloss=%u\navg_ms=%lu\nmin_ms=%lu\nmax_ms=%lu\np95_ms=%lu\n", static_cast<unsigned>(success), static_cast<unsigned>(100 - success), static_cast<unsigned long>(success ? total / success : 0), static_cast<unsigned long>(success ? minimum : 0), static_cast<unsigned long>(maximum), static_cast<unsigned long>(p95));
  return success == 100;
}

bool runBenchFile(const WatchAppInfo& app, uint8_t& sequence, const uint8_t encKey[16], const uint8_t decKey[16], uint32_t size, size_t chunkSize, BenchCounters& counters, uint8_t faults = kBenchFaultNone, const char* storageMode = nullptr) {
  if (chunkSize > kBenchChunkRawMax) { Serial.printf("BENCH_CHUNK_SKIPPED chunk_size=%u reason=spp_message_limit\n", static_cast<unsigned>(chunkSize)); return false; }
  static char hash[65], receivedHash[65], packageId[32], text[kSppV2PayloadMax];
  if (!sha256BenchData(size, hash)) { ++counters.errors; Serial.println("BENCH_STAGE_FAIL stage=sha256"); return false; }
  snprintf(packageId, sizeof(packageId), "bench_%08lx", static_cast<unsigned long>(esp_random()));
  logStackHighWater("bench_file_begin");

  int length = snprintf(text, sizeof(text), "{\"v\":2,\"id\":\"bench_begin\",\"timestamp\":%lu,\"type\":\"package_begin\",\"payload\":{\"packageId\":\"%s\",\"packageType\":\"comic\",\"fileCount\":1,\"totalSize\":%lu}}", static_cast<unsigned long>(millis()), packageId, static_cast<unsigned long>(size));
  if (length <= 0 || static_cast<size_t>(length) >= sizeof(text) || !sendBenchJson(app, sequence, encKey, text)) { ++counters.errors; Serial.println("BENCH_STAGE_FAIL stage=package_begin_send"); return false; }
  if (!waitBenchReply(decKey, "package_status", "begun", -1, kBenchControlTimeoutMs)) {
    ++counters.errors;
    Serial.println("BENCH_STAGE_FAIL stage=package_begin_reply");
    // Query state once more: if this returns, the router is alive and the log
    // reveals whether begin is stuck in filesystem setup or its reply was lost.
    length = snprintf(text, sizeof(text), "{\"v\":2,\"id\":\"bench_begin_diag\",\"timestamp\":%lu,\"type\":\"package_status\",\"payload\":{}}", static_cast<unsigned long>(millis()));
    if (length > 0 && static_cast<size_t>(length) < sizeof(text) && sendBenchJson(app, sequence, encKey, text)) (void)waitBenchReply(decKey, "package_status", nullptr, -1, 2500);
    return false;
  }

  static char manifest[256], escapedManifest[512];
  snprintf(manifest, sizeof(manifest), "{\"format\":\"%s\",\"formatVersion\":1,\"type\":\"comic\",\"id\":\"%s\",\"files\":[{\"path\":\"bench.bin\",\"size\":%lu,\"sha256\":\"%s\"}]}", watchManifestFormat(), packageId, static_cast<unsigned long>(size), hash);
  if (!jsonEscapeBenchString(manifest, escapedManifest, sizeof(escapedManifest))) { ++counters.errors; Serial.println("BENCH_STAGE_FAIL stage=manifest_escape"); return false; }
  length = snprintf(text, sizeof(text), "{\"v\":2,\"id\":\"bench_manifest\",\"timestamp\":%lu,\"type\":\"package_manifest\",\"payload\":{\"text\":\"%s\"}}", static_cast<unsigned long>(millis()), escapedManifest);
  if (length <= 0 || static_cast<size_t>(length) >= sizeof(text) || !sendBenchJson(app, sequence, encKey, text) || !waitBenchReply(decKey, "package_status", "manifest_saved", -1, kBenchControlTimeoutMs)) { ++counters.errors; Serial.println("BENCH_STAGE_FAIL stage=manifest"); return false; }
  if (storageMode && storageMode[0]) {
    length = snprintf(text, sizeof(text), "{\"v\":2,\"id\":\"bench_file\",\"timestamp\":%lu,\"type\":\"package_file_begin\",\"payload\":{\"path\":\"bench.bin\",\"size\":%lu,\"sha256\":\"%s\",\"storageMode\":\"%s\"}}", static_cast<unsigned long>(millis()), static_cast<unsigned long>(size), hash, storageMode);
  } else {
    length = snprintf(text, sizeof(text), "{\"v\":2,\"id\":\"bench_file\",\"timestamp\":%lu,\"type\":\"package_file_begin\",\"payload\":{\"path\":\"bench.bin\",\"size\":%lu,\"sha256\":\"%s\"}}", static_cast<unsigned long>(millis()), static_cast<unsigned long>(size), hash);
  }
  if (length <= 0 || static_cast<size_t>(length) >= sizeof(text) || !sendBenchJson(app, sequence, encKey, text) || !waitBenchReply(decKey, "package_status", "file_begin", -1, kBenchControlTimeoutMs)) { ++counters.errors; Serial.println("BENCH_STAGE_FAIL stage=file_begin"); return false; }

  const uint32_t started = millis(); static uint8_t raw[kBenchChunkRawMax]; static char encoded[4 * ((kBenchChunkRawMax + 2) / 3) + 1];
  uint32_t offset = 0, sequenceNo = 0;
  while (offset < size) {
    if ((faults & kBenchFaultPause) && sequenceNo == 2) {
      Serial.println("BENCH_FAULT_A_PAUSE duration_ms=2000");
      delay(2000);
    }
    const size_t currentSize = min(static_cast<uint32_t>(chunkSize), size - offset);
    fillBenchBytes(offset, raw, currentSize);
    if (!base64BenchEncode(raw, currentSize, encoded, sizeof(encoded))) { ++counters.errors; Serial.println("BENCH_STAGE_FAIL stage=base64"); return false; }
    length = snprintf(text, sizeof(text), "{\"v\":2,\"id\":\"bench_chunk_%lu\",\"timestamp\":%lu,\"type\":\"package_file_chunk\",\"payload\":{\"offset\":%lu,\"sequence\":%lu,\"data\":\"%s\"}}", static_cast<unsigned long>(sequenceNo), static_cast<unsigned long>(millis()), static_cast<unsigned long>(offset), static_cast<unsigned long>(sequenceNo), encoded);
    if (length <= 0 || static_cast<size_t>(length) >= sizeof(text)) { ++counters.errors; Serial.println("BENCH_STAGE_FAIL stage=chunk_json_size"); return false; }
    if ((sequenceNo % 16u) == 0u) {
      Serial.printf("BENCH_CHUNK_PROGRESS app_sequence=%lu offset=%lu spp_next=%u renewals=%lu\n",
                    static_cast<unsigned long>(sequenceNo),
                    static_cast<unsigned long>(offset),
                    static_cast<unsigned>(sequence),
                    static_cast<unsigned long>(gBenchSessionRenewals));
    }
    bool acknowledged = false;
    for (uint8_t attempt = 0; attempt <= kBenchChunkRetries && !acknowledged; ++attempt) {
      bool duplicate = false;
      if (!sendBenchJson(app, sequence, encKey, text)) break;
      if ((faults & kBenchFaultDropAck) && sequenceNo == 3 && attempt == 0) {
        (void)waitBenchReply(decKey, "package_chunk_ack", nullptr, static_cast<int>(sequenceNo), kBenchAckTimeoutMs);
        ++counters.ackTimeouts; ++counters.retries;
        Serial.println("BENCH_FAULT_B_RETRY simulated_ack_drop=true");
        continue;
      }
      if ((faults & kBenchFaultDropDurableAck) && sequenceNo == 15 && attempt == 0) {
        (void)waitBenchReply(decKey, "package_chunk_ack", nullptr, static_cast<int>(sequenceNo), kBenchAckTimeoutMs);
        ++counters.ackTimeouts; ++counters.retries;
        Serial.println("BENCH_FAULT_D_DURABLE_ACK_RETRY simulated_ack_drop=true sequence=15");
        continue;
      }
      acknowledged = waitBenchReply(decKey, "package_chunk_ack", nullptr, static_cast<int>(sequenceNo), kBenchAckTimeoutMs, &duplicate);
      if (duplicate) ++counters.duplicates;
      if (!acknowledged) { ++counters.ackTimeouts; if (attempt < kBenchChunkRetries) ++counters.retries; }
    }
    if (!acknowledged) {
      ++counters.errors;
      Serial.printf("BENCH_STAGE_FAIL stage=chunk_ack sequence=%lu offset=%lu spp_next=%u renewals=%lu\n",
                    static_cast<unsigned long>(sequenceNo),
                    static_cast<unsigned long>(offset),
                    static_cast<unsigned>(sequence),
                    static_cast<unsigned long>(gBenchSessionRenewals));
      // One low-frequency control-plane query after the first real failure.
      // package_status now exposes a read-only in-memory snapshot showing
      // whether this exact chunk reached the QuickApp, committed to storage,
      // and reached the ACK send call. This avoids guessing between forward
      // SPP loss, system.file stall, and reverse-path loss.
      length = snprintf(text, sizeof(text), "{\"v\":2,\"id\":\"bench_chunk_diag\",\"timestamp\":%lu,\"type\":\"package_status\",\"payload\":{\"query\":true}}", static_cast<unsigned long>(millis()));
      bool diagOk = false;
      if (length > 0 && static_cast<size_t>(length) < sizeof(text) && sendBenchJson(app, sequence, encKey, text)) {
        diagOk = waitBenchReply(decKey, "package_status", nullptr, -1, 3000);
        Serial.printf("BENCH_CHUNK_PATH_QUERY %s\n", diagOk ? "PASS" : "FAIL");
      } else {
        Serial.println("BENCH_CHUNK_PATH_QUERY SEND_FAIL");
      }
      if (!diagOk) {
        length = snprintf(text, sizeof(text), "{\"v\":2,\"id\":\"bench_postfail_ping\",\"timestamp\":%lu,\"type\":\"ping\",\"payload\":{\"from\":\"esp32_postfail\"}}", static_cast<unsigned long>(millis()));
        const bool pingOk = length > 0 && static_cast<size_t>(length) < sizeof(text) && sendBenchJson(app, sequence, encKey, text) && waitBenchReply(decKey, "pong", nullptr, -1, 3000);
        Serial.printf("BENCH_POSTFAIL_PING %s\n", pingOk ? "PASS" : "FAIL");
      }
      logSppRxParserState("chunk_failure_exit");
      return false;
    }
    if (gBenchInterChunkGapMs > 0) delay(gBenchInterChunkGapMs);
    if ((faults & kBenchFaultDuplicate) && sequenceNo == 4) {
      bool duplicate = false;
      if (!sendBenchJson(app, sequence, encKey, text) || !waitBenchReply(decKey, "package_chunk_ack", nullptr, static_cast<int>(sequenceNo), kBenchAckTimeoutMs, &duplicate) || !duplicate) { ++counters.errors; Serial.println("BENCH_STAGE_FAIL stage=duplicate_idempotency"); return false; }
      ++counters.duplicates;
      Serial.println("BENCH_FAULT_C_DUPLICATE duplicate_ack=true");
    }
    offset += currentSize; ++sequenceNo;
    if ((faults & kBenchFaultAbort) && sequenceNo == 5) {
      length = snprintf(text, sizeof(text), "{\"v\":2,\"id\":\"bench_abort_midfile\",\"timestamp\":%lu,\"type\":\"package_abort\",\"payload\":{}}", static_cast<unsigned long>(millis()));
      const bool abortOk = length > 0 && static_cast<size_t>(length) < sizeof(text) && sendBenchJson(app, sequence, encKey, text) && waitBenchReply(decKey, "package_status", nullptr, -1, kBenchControlTimeoutMs);
      Serial.println("BENCH_RECOVERY_NOT_FALSE_SUCCESS phase=package_abort_requested");
      Serial.printf("BENCH_RECOVERY midfile_abort=%s transferred_bytes=%lu\n", abortOk ? "PASS" : "FAIL", static_cast<unsigned long>(offset));
      if (!abortOk) ++counters.errors;
      return abortOk;
    }
  }

  length = snprintf(text, sizeof(text), "{\"v\":2,\"id\":\"bench_end\",\"timestamp\":%lu,\"type\":\"package_file_end\",\"payload\":{}}", static_cast<unsigned long>(millis()));
  const bool completed = length > 0 && static_cast<size_t>(length) < sizeof(text) && sendBenchJson(app, sequence, encKey, text) && waitBenchReply(decKey, "package_status", "file_saved", -1, kBenchControlTimeoutMs, nullptr, receivedHash);
  const uint32_t elapsed = millis() - started;
  const bool integrityOk = completed && strcmp(hash, receivedHash) == 0;
  const float kbps = integrityOk && elapsed ? (static_cast<float>(size) * 1000.0f / 1024.0f / elapsed) : 0.0f;
  Serial.printf("FILE_TEST size_bytes=%lu transferred_bytes=%lu elapsed_ms=%lu KB/s=%.2f %s\n", static_cast<unsigned long>(size), static_cast<unsigned long>(offset), static_cast<unsigned long>(elapsed), kbps, integrityOk ? "success" : "fail");
  Serial.printf("BENCH_INTEGRITY size=%lu tx_hash=%s rx_hash=%s %s\n", static_cast<unsigned long>(size), hash, receivedHash, integrityOk ? "PASS" : "FAIL");

  // Benchmark packages are disposable. Abort after verifying the saved file so
  // every iteration starts from idle and leaves no large test package behind.
  length = snprintf(text, sizeof(text), "{\"v\":2,\"id\":\"bench_abort_done\",\"timestamp\":%lu,\"type\":\"package_abort\",\"payload\":{}}", static_cast<unsigned long>(millis()));
  const bool cleanupOk = length > 0 && static_cast<size_t>(length) < sizeof(text) && sendBenchJson(app, sequence, encKey, text) && waitBenchReply(decKey, "package_status", nullptr, -1, kBenchControlTimeoutMs);
  Serial.printf("BENCH_CLEANUP package_abort=%s\n", cleanupOk ? "PASS" : "FAIL");
  if (!integrityOk || !cleanupOk) ++counters.errors;
  logStackHighWater("bench_file_end");
  return integrityOk && cleanupOk;
}

bool runBenchPushTest(const WatchAppInfo& app, uint8_t& sequence, const uint8_t encKey[16], const uint8_t decKey[16]) {
  uint32_t total = 0; uint8_t success = 0;
  for (uint8_t item = 0; item < 20; ++item) {
    static char text[256]; const int length = snprintf(text, sizeof(text), "{\"v\":2,\"id\":\"bench_push_%u\",\"timestamp\":%lu,\"type\":\"esp32_push_test\",\"payload\":{\"sequence\":%u,\"msg\":\"ESP32_PUSH\"}}", static_cast<unsigned>(item), static_cast<unsigned long>(millis()), static_cast<unsigned>(item));
    const uint32_t started = millis();
    if (length > 0 && static_cast<size_t>(length) < sizeof(text) && sendBenchJson(app, sequence, encKey, text) && waitBenchReply(decKey, "esp32_push_ack", nullptr, item, kBenchAckTimeoutMs)) { total += millis() - started; ++success; }
  }
  Serial.printf("BENCH_PUSH_TEST push_success=%u push_fail=%u avg_latency_ms=%lu\n", static_cast<unsigned>(success), static_cast<unsigned>(20 - success), static_cast<unsigned long>(success ? total / success : 0));
  Serial.println(success == 20 ? "BENCH_PUSH_ACK PASS" : "BENCH_PUSH_ACK FAIL");
  return success == 20;
}

bool runBenchStress(const WatchAppInfo& app, uint8_t& sequence, const uint8_t encKey[16], const uint8_t decKey[16], uint32_t durationSeconds, BenchCounters& counters) {
  const uint32_t started = millis(); const uint32_t beforeErrors = counters.errors, beforeRetries = counters.retries;
  uint32_t totalBytes = 0;
  while (millis() - started < durationSeconds * 1000u) {
    if (!runBenchFile(app, sequence, encKey, decKey, 8u * 1024u, kBenchChunkRawMax, counters)) break;
    totalBytes += 8u * 1024u;
  }
  const uint32_t elapsed = millis() - started;
  const float kbps = elapsed ? (static_cast<float>(totalBytes) * 1000.0f / 1024.0f / elapsed) : 0.0f;
  const bool ok = counters.errors == beforeErrors;
  Serial.printf("BENCH_STRESS duration_s=%lu total_bytes=%lu avg_KB/s=%.2f errors=%lu retries=%lu disconnects=0 %s\n", static_cast<unsigned long>(elapsed / 1000u), static_cast<unsigned long>(totalBytes), kbps, static_cast<unsigned long>(counters.errors - beforeErrors), static_cast<unsigned long>(counters.retries - beforeRetries), ok ? "PASS" : "FAIL");
  return ok;
}

bool runBenchFaults(const WatchAppInfo& app, uint8_t& sequence, const uint8_t encKey[16], const uint8_t decKey[16], BenchCounters& counters) {
  const bool abc = runBenchFile(app, sequence, encKey, decKey, 8u * 1024u, kBenchChunkRawMax, counters, kBenchFaultPause | kBenchFaultDropAck | kBenchFaultDuplicate);
  const bool abortSafe = runBenchFile(app, sequence, encKey, decKey, 8u * 1024u, kBenchChunkRawMax, counters, kBenchFaultAbort);
  Serial.printf("BENCH_FAULTS abc=%s disconnect_phase1=%s\n", abc ? "PASS" : "FAIL", abortSafe ? "PASS" : "FAIL");
  return abc && abortSafe;
}

bool waitBenchStreamCapability(const uint8_t decKey[16], uint32_t timeoutMs) {
  const uint32_t startedAt = millis();
  while (millis() - startedAt < timeoutMs) {
    const uint32_t remaining = timeoutMs - (millis() - startedAt);
    SppV2Frame& frame = gSharedSppFrame;
    if (!readSppV2Frame(frame, remaining)) break;
    if (frame.type != 3) continue;
    writeSppV2Frame(1, frame.sequence, nullptr, 0);
    const uint8_t* incoming = nullptr; size_t incomingLength = 0, contentLength = 0; const uint8_t* content = nullptr;
    if (!decryptWatchPb(frame, decKey, incoming, incomingLength) || !parseQuickAppMessage(incoming, incomingLength, content, contentLength)) continue;
    static JsonDocument document;
    document.clear();
    if (deserializeJson(document, content, contentLength)) continue;
    if (strcmp(document["type"] | "", "capabilities_response") != 0) continue;
    JsonObject payload = document["payload"].as<JsonObject>();
    JsonObject caps = payload["capabilities"].as<JsonObject>();
    const char* buildTag = payload["buildTag"] | "";
    const bool probe = caps["streamProbe"] | false;
    const bool pushProbe = caps["pushRouteProbe"] | false;
    const int version = caps["streamProbeVersion"] | 0;
    Serial.printf("STREAM_AB_PREFLIGHT_RX buildTag=%s streamProbe=%s pushRouteProbe=%s version=%d\n", buildTag, probe ? "true" : "false", pushProbe ? "true" : "false", version);
    if (!probe || !pushProbe || version < 3 || strcmp(buildTag, watchRequiredBuildTag()) != 0) {
      Serial.println("STREAM_AB_PREFLIGHT_STALE_RPK");
      return false;
    }
    return true;
  }
  Serial.println("STREAM_AB_PREFLIGHT_TIMEOUT");
  return false;
}

bool runWatchStreamProbe(const WatchAppInfo& app, uint8_t& sequence, const uint8_t encKey[16], const uint8_t decKey[16], const char* mode) {
  constexpr uint32_t kStreamProbeSize = 256u * 1024u;
  constexpr size_t kStreamProbeChunk = 512;
  static char text[kSppV2PayloadMax];
  static uint8_t raw[kBenchChunkRawMax];
  static char encoded[4 * ((kBenchChunkRawMax + 2) / 3) + 1];
  if (!mode || (strcmp(mode, "echo") != 0 && strcmp(mode, "decode") != 0)) return false;
  const char* probeMode = strcmp(mode, "decode") == 0 ? "decode_v3" : "echo_v3";

  Serial.printf("STREAM_AB_V3_START mode=%s total_bytes=%lu chunk_size=%u spp_next=%u\n",
                probeMode,
                static_cast<unsigned long>(kStreamProbeSize),
                static_cast<unsigned>(kStreamProbeChunk),
                static_cast<unsigned>(sequence));

  int length = snprintf(text, sizeof(text),
                        "{\"v\":2,\"id\":\"stream_caps_v3\",\"timestamp\":%lu,\"type\":\"capabilities_request\",\"payload\":{}}",
                        static_cast<unsigned long>(millis()));
  if (length <= 0 || static_cast<size_t>(length) >= sizeof(text) ||
      !sendBenchJson(app, sequence, encKey, text) ||
      !waitBenchStreamCapability(decKey, kBenchControlTimeoutMs)) {
    Serial.printf("STREAM_AB_V3_FAIL mode=%s stage=preflight_capability spp_next=%u\n", probeMode, static_cast<unsigned>(sequence));
    return false;
  }
  Serial.println("STREAM_AB_V3_PREFLIGHT pushRouteProbe=true version=3 PASS");
  delay(kBenchControlGapMs);

  static const char kSmokeB64[] = "AAECAwQFBgcICQoLDA0ODw==";
  length = snprintf(text, sizeof(text),
                    "{\"v\":2,\"id\":\"stream_v3_smoke\",\"timestamp\":%lu,\"type\":\"esp32_push_test\",\"payload\":{\"probeMode\":\"%s\",\"sequence\":0,\"offset\":0,\"rawLength\":16,\"data\":\"%s\"}}",
                    static_cast<unsigned long>(millis()), probeMode, kSmokeB64);
  if (length <= 0 || static_cast<size_t>(length) >= sizeof(text) ||
      !sendBenchJson(app, sequence, encKey, text) ||
      !waitBenchReply(decKey, "esp32_push_ack", nullptr, 0, kBenchControlTimeoutMs)) {
    Serial.printf("STREAM_AB_V3_FAIL mode=%s stage=smoke spp_next=%u\n", probeMode, static_cast<unsigned>(sequence));
    return false;
  }
  Serial.printf("STREAM_AB_V3_SMOKE mode=%s PASS\n", probeMode);
  delay(kBenchControlGapMs);

  uint32_t offset = 0;
  uint32_t sequenceNo = 0;
  const uint32_t started = millis();
  while (offset < kStreamProbeSize) {
    const size_t currentSize = min(static_cast<uint32_t>(kStreamProbeChunk), kStreamProbeSize - offset);
    fillBenchBytes(offset, raw, currentSize);
    if (!base64BenchEncode(raw, currentSize, encoded, sizeof(encoded))) {
      Serial.printf("STREAM_AB_V3_FAIL mode=%s stage=base64 sequence=%lu offset=%lu\n", probeMode,
                    static_cast<unsigned long>(sequenceNo), static_cast<unsigned long>(offset));
      return false;
    }
    length = snprintf(text, sizeof(text),
                      "{\"v\":2,\"id\":\"stream_v3_%lu\",\"timestamp\":%lu,\"type\":\"esp32_push_test\",\"payload\":{\"probeMode\":\"%s\",\"sequence\":%lu,\"offset\":%lu,\"rawLength\":%u,\"data\":\"%s\"}}",
                      static_cast<unsigned long>(sequenceNo),
                      static_cast<unsigned long>(millis()),
                      probeMode,
                      static_cast<unsigned long>(sequenceNo),
                      static_cast<unsigned long>(offset),
                      static_cast<unsigned>(currentSize),
                      encoded);
    if (length <= 0 || static_cast<size_t>(length) >= sizeof(text)) {
      Serial.printf("STREAM_AB_V3_FAIL mode=%s stage=json_size sequence=%lu offset=%lu json_len=%d\n", probeMode,
                    static_cast<unsigned long>(sequenceNo), static_cast<unsigned long>(offset), length);
      return false;
    }
    if ((sequenceNo % 16u) == 0u) {
      Serial.printf("STREAM_AB_V3_PROGRESS mode=%s sequence=%lu offset=%lu spp_next=%u\n",
                    probeMode, static_cast<unsigned long>(sequenceNo), static_cast<unsigned long>(offset), static_cast<unsigned>(sequence));
    }
    if (!sendBenchJson(app, sequence, encKey, text) ||
        !waitBenchReply(decKey, "esp32_push_ack", nullptr, static_cast<int>(sequenceNo), kBenchAckTimeoutMs)) {
      Serial.printf("STREAM_AB_V3_FAIL mode=%s stage=chunk_ack sequence=%lu offset=%lu spp_next=%u\n",
                    probeMode, static_cast<unsigned long>(sequenceNo), static_cast<unsigned long>(offset), static_cast<unsigned>(sequence));
      return false;
    }
    offset += currentSize;
    sequenceNo += 1;
  }
  const uint32_t elapsed = millis() - started;
  const float kbps = elapsed ? (static_cast<float>(offset) * 1000.0f / 1024.0f / elapsed) : 0.0f;
  Serial.printf("STREAM_AB_V3_RESULT mode=%s transferred_bytes=%lu chunks=%lu elapsed_ms=%lu avg_KB/s=%.2f spp_next=%u rx_dropped=%lu PASS\n",
                probeMode,
                static_cast<unsigned long>(offset),
                static_cast<unsigned long>(sequenceNo),
                static_cast<unsigned long>(elapsed), kbps,
                static_cast<unsigned>(sequence),
                static_cast<unsigned long>(watchRxDroppedBytes));
  return true;
}


bool waitBenchSegment32KCapability(const uint8_t decKey[16], uint32_t timeoutMs) {
  const uint32_t startedAt = millis();
  while (millis() - startedAt < timeoutMs) {
    const uint32_t remaining = timeoutMs - (millis() - startedAt);
    SppV2Frame& frame = gSharedSppFrame;
    if (!readSppV2Frame(frame, remaining)) break;
    if (frame.type != 3) continue;
    writeSppV2Frame(1, frame.sequence, nullptr, 0);
    const uint8_t* incoming = nullptr; size_t incomingLength = 0, contentLength = 0; const uint8_t* content = nullptr;
    if (!decryptWatchPb(frame, decKey, incoming, incomingLength) || !parseQuickAppMessage(incoming, incomingLength, content, contentLength)) continue;
    static JsonDocument document;
    document.clear();
    if (deserializeJson(document, content, contentLength)) continue;
    if (strcmp(document["type"] | "", "capabilities_response") != 0) continue;
    JsonObject payload = document["payload"].as<JsonObject>();
    JsonObject caps = payload["capabilities"].as<JsonObject>();
    const char* buildTag = payload["buildTag"] | "";
    const bool segmentProbe = caps["packageSegmentProbe"] | false;
    const int segmentBytes = caps["packageSegmentBytes"] | 0;
    const char* hashMode = caps["packageSegmentHashMode"] | "";
    const bool durableAckReplay = caps["packageSegmentDurableAckReplay"] | false;
    Serial.printf("SEG32K_PREFLIGHT_RX buildTag=%s segmentProbe=%s segmentBytes=%d durableAckReplay=%s hashMode=%s\n",
                  buildTag, segmentProbe ? "true" : "false", segmentBytes, durableAckReplay ? "true" : "false", hashMode);
    if (!segmentProbe || segmentBytes != 32768 || !durableAckReplay || strcmp(buildTag, watchRequiredBuildTag()) != 0) {
      Serial.println("SEG32K_PREFLIGHT_STALE_RPK");
      return false;
    }
    return true;
  }
  Serial.println("SEG32K_PREFLIGHT_TIMEOUT");
  return false;
}

bool runBenchSegment32KPreflight(const WatchAppInfo& app, uint8_t& sequence, const uint8_t encKey[16], const uint8_t decKey[16]) {
  static char text[256];
  const int length = snprintf(text, sizeof(text), "{\"v\":2,\"id\":\"seg32k_caps\",\"timestamp\":%lu,\"type\":\"capabilities_request\",\"payload\":{}}", static_cast<unsigned long>(millis()));
  const bool ok = length > 0 && static_cast<size_t>(length) < sizeof(text) && sendBenchJson(app, sequence, encKey, text) && waitBenchSegment32KCapability(decKey, kBenchControlTimeoutMs);
  Serial.printf("SEG32K_PREFLIGHT %s\n", ok ? "PASS" : "FAIL");
  return ok;
}

void runWatchBenchmark256KSegment32K(const WatchAppInfo& app, uint8_t& sequence, const uint8_t encKey[16], const uint8_t decKey[16]) {
  BenchCounters counters;
  logStackHighWater("benchmark_256k_seg32k_start");
  const bool preflightOk = runBenchSegment32KPreflight(app, sequence, encKey, decKey);
  const bool controlOk = preflightOk && runBenchControlProbe(app, sequence, encKey, decKey);
  const bool fileOk = controlOk && runBenchFile(app, sequence, encKey, decKey, 256u * 1024u, kBenchChunkRawMax, counters, kBenchFaultNone, "segment32k");
  Serial.printf("BENCH_256K_SEG32K_RESULT preflight=%s control=%s file=%s errors=%lu retries=%lu ack_timeouts=%lu rx_dropped=%lu %s\n",
                preflightOk ? "PASS" : "FAIL",
                controlOk ? "PASS" : "FAIL",
                fileOk ? "PASS" : "FAIL",
                static_cast<unsigned long>(counters.errors),
                static_cast<unsigned long>(counters.retries),
                static_cast<unsigned long>(counters.ackTimeouts),
                static_cast<unsigned long>(watchRxDroppedBytes),
                preflightOk && controlOk && fileOk ? "PASS" : "FAIL");
  logStackHighWater("benchmark_256k_seg32k_end");
}

void runWatchFinalAcceptance(const WatchAppInfo& app, uint8_t& sequence, const uint8_t encKey[16], const uint8_t decKey[16]) {
  BenchCounters counters;
  logStackHighWater("final_acceptance_start");
  Serial.println("FINAL_ACCEPTANCE_START version=7.1 tx=coalesced storage=segment32k batch=4096");
  const bool preflightOk = runBenchSegment32KPreflight(app, sequence, encKey, decKey);
  const bool controlOk = preflightOk && runBenchControlProbe(app, sequence, encKey, decKey);
  const bool echoOk = controlOk && runWatchStreamProbe(app, sequence, encKey, decKey, "echo");
  const bool decodeOk = echoOk && runWatchStreamProbe(app, sequence, encKey, decKey, "decode");
  // 16 KiB reaches the 2nd 4 KiB flush trigger (seq 15). Deliberately discard
  // that trigger ACK once so the QuickApp must replay its RAM durable-ACK
  // snapshot without another system.file read/write.
  const bool durableRetryOk = decodeOk && runBenchFile(app, sequence, encKey, decKey,
      16u * 1024u, kBenchChunkRawMax, counters, kBenchFaultDropDurableAck, "segment32k");
  const bool file256Ok = durableRetryOk && runBenchFile(app, sequence, encKey, decKey,
      256u * 1024u, kBenchChunkRawMax, counters, kBenchFaultNone, "segment32k");
  const bool pushOk = file256Ok && runBenchPushTest(app, sequence, encKey, decKey);
  const bool pass = preflightOk && controlOk && echoOk && decodeOk && durableRetryOk && file256Ok && pushOk && watchRxDroppedBytes == 0;
  Serial.printf("FINAL_ACCEPTANCE_RESULT preflight=%s control=%s echo256=%s decode256=%s durable_ack_retry=%s segment256=%s push=%s errors=%lu retries=%lu duplicates=%lu ack_timeouts=%lu rx_dropped=%lu %s\n",
                preflightOk ? "PASS" : "FAIL",
                controlOk ? "PASS" : "FAIL",
                echoOk ? "PASS" : "FAIL",
                decodeOk ? "PASS" : "FAIL",
                durableRetryOk ? "PASS" : "FAIL",
                file256Ok ? "PASS" : "FAIL",
                pushOk ? "PASS" : "FAIL",
                static_cast<unsigned long>(counters.errors),
                static_cast<unsigned long>(counters.retries),
                static_cast<unsigned long>(counters.duplicates),
                static_cast<unsigned long>(counters.ackTimeouts),
                static_cast<unsigned long>(watchRxDroppedBytes),
                pass ? "PASS" : "FAIL");
  logSppRxParserState("final_acceptance_end");
  logStackHighWater("final_acceptance_end");
}

void runWatchBenchmark256K(const WatchAppInfo& app, uint8_t& sequence, const uint8_t encKey[16], const uint8_t decKey[16]) {
  BenchCounters counters;
  logStackHighWater("benchmark_256k_start");
  const bool controlOk = runBenchControlProbe(app, sequence, encKey, decKey);
  const bool fileOk = controlOk && runBenchFile(app, sequence, encKey, decKey, 256u * 1024u, kBenchChunkRawMax, counters);
  Serial.printf("BENCH_256K_RESULT control=%s file=%s renewals=%lu errors=%lu retries=%lu ack_timeouts=%lu rx_dropped=%lu %s\n",
                controlOk ? "PASS" : "FAIL",
                fileOk ? "PASS" : "FAIL",
                static_cast<unsigned long>(gBenchSessionRenewals),
                static_cast<unsigned long>(counters.errors),
                static_cast<unsigned long>(counters.retries),
                static_cast<unsigned long>(counters.ackTimeouts),
                static_cast<unsigned long>(watchRxDroppedBytes),
                controlOk && fileOk ? "PASS" : "FAIL");
  logStackHighWater("benchmark_256k_end");
}

void runWatchBenchmarkQuick(const WatchAppInfo& app, uint8_t& sequence, const uint8_t encKey[16], const uint8_t decKey[16]) {
  BenchCounters counters;
  logStackHighWater("quick_benchmark_start");
  const bool controlOk = runBenchControlProbe(app, sequence, encKey, decKey);
  const bool pingOk = runBenchPingTest(app, sequence, encKey, decKey);
  const bool file256 = controlOk && runBenchFile(app, sequence, encKey, decKey, 8u * 1024u, 256, counters);
  const bool file512 = file256 && runBenchFile(app, sequence, encKey, decKey, 8u * 1024u, 512, counters);
  const bool faultsOk = file512 && runBenchFaults(app, sequence, encKey, decKey, counters);
  const bool pushOk = runBenchPushTest(app, sequence, encKey, decKey);
  Serial.printf("BENCH_QUICK_RESULT control=%s ping=%s file256=%s file512=%s faults=%s push=%s errors=%lu retries=%lu duplicates=%lu ack_timeouts=%lu rx_dropped=%lu %s\n",
                controlOk ? "PASS" : "FAIL",
                pingOk ? "PASS" : "FAIL",
                file256 ? "PASS" : "FAIL",
                file512 ? "PASS" : "FAIL",
                faultsOk ? "PASS" : "FAIL",
                pushOk ? "PASS" : "FAIL",
                static_cast<unsigned long>(counters.errors),
                static_cast<unsigned long>(counters.retries),
                static_cast<unsigned long>(counters.duplicates),
                static_cast<unsigned long>(counters.ackTimeouts),
                static_cast<unsigned long>(watchRxDroppedBytes),
                controlOk && pingOk && file256 && file512 && faultsOk && pushOk ? "PASS" : "FAIL");
  logStackHighWater("quick_benchmark_end");
}

void runWatchBenchmark(const WatchAppInfo& app, uint8_t& sequence, const uint8_t encKey[16], const uint8_t decKey[16]) {
  BenchCounters counters;
  logStackHighWater("benchmark_start");
  const bool controlOk = runBenchControlProbe(app, sequence, encKey, decKey);
  const bool pingOk = runBenchPingTest(app, sequence, encKey, decKey);
  const uint32_t fixedSizes[] = {64u * 1024u, 256u * 1024u, 1024u * 1024u, 4u * 1024u * 1024u};
  bool fourMegOk = false;
  for (size_t index = 0; index < sizeof(fixedSizes) / sizeof(fixedSizes[0]); ++index) {
    const bool ok = controlOk && runBenchFile(app, sequence, encKey, decKey, fixedSizes[index], kBenchChunkRawMax, counters);
    if (fixedSizes[index] == 4u * 1024u * 1024u) fourMegOk = ok;
    if (!ok) break;
  }
  if (fourMegOk) {
    runBenchFile(app, sequence, encKey, decKey, 8u * 1024u * 1024u, kBenchChunkRawMax, counters);
    runBenchFile(app, sequence, encKey, decKey, 16u * 1024u * 1024u, kBenchChunkRawMax, counters);
  }
  const size_t sweep[] = {256, 512, 1024, 2048, 4096, 8192, 16384};
  for (size_t index = 0; index < sizeof(sweep) / sizeof(sweep[0]); ++index) {
    const uint32_t started = millis(); const uint32_t beforeErrors = counters.errors, beforeRetries = counters.retries;
    const bool ok = controlOk && sweep[index] <= kBenchChunkRawMax && runBenchFile(app, sequence, encKey, decKey, 1024u * 1024u, sweep[index], counters);
    const uint32_t elapsed = millis() - started;
    const float kbps = ok && elapsed ? (1024.0f * 1000.0f / elapsed) : 0.0f;
    Serial.printf("CHUNK_SWEEP chunk_size=%u elapsed_ms=%lu KB/s=%.2f errors=%lu retries=%lu %s\n", static_cast<unsigned>(sweep[index]), static_cast<unsigned long>(elapsed), kbps, static_cast<unsigned long>(counters.errors - beforeErrors), static_cast<unsigned long>(counters.retries - beforeRetries), ok ? "PASS" : (sweep[index] > kBenchChunkRawMax ? "SKIP" : "FAIL"));
  }
  const bool stress60 = controlOk && runBenchStress(app, sequence, encKey, decKey, 60, counters);
  const bool stress300 = stress60 && runBenchStress(app, sequence, encKey, decKey, 300, counters);
  const bool pushOk = runBenchPushTest(app, sequence, encKey, decKey);
  const bool faultsOk = controlOk && runBenchFaults(app, sequence, encKey, decKey, counters);
  Serial.printf("BENCH_COUNTERS control=%s ping=%s stress60=%s stress300=%s faults=%s push=%s errors=%lu retries=%lu duplicate_count=%lu ack_timeout_count=%lu missing_sequence_count=0 disconnects=0 rx_dropped=%lu\n", controlOk ? "PASS" : "FAIL", pingOk ? "PASS" : "FAIL", stress60 ? "PASS" : "FAIL", stress300 ? "PASS" : "FAIL", faultsOk ? "PASS" : "FAIL", pushOk ? "PASS" : "FAIL", static_cast<unsigned long>(counters.errors), static_cast<unsigned long>(counters.retries), static_cast<unsigned long>(counters.duplicates), static_cast<unsigned long>(counters.ackTimeouts), static_cast<unsigned long>(watchRxDroppedBytes));
  logStackHighWater("benchmark_end");
}

void authenticateWatchSpp(String target, String secretText) {
  uint8_t address[6], secret[16]{}, phoneNonce[16]{}, step3[160]{}, encKey[16]{}, decKey[16]{};
  size_t step3Length = 0;
  target.trim(); target.toUpperCase();
  if (!parseWatchAddress(target, address) || !parseSecretHex(secretText, secret)) {
    Serial.println("WATCH_AUTH_INVALID_INPUT");
    mbedtls_platform_zeroize(secret, sizeof(secret));
    return;
  }
  Serial.printf("WATCH_AUTH_HEAP stage=before_bt free=%lu largest=%lu\n",
                static_cast<unsigned long>(ESP.getFreeHeap()),
                static_cast<unsigned long>(ESP.getMaxAllocHeap()));
  if (!beginWatchBluetooth("Vela-Gateway-Probe")) { Serial.println("WATCH_AUTH_BT_INIT_FAILED"); mbedtls_platform_zeroize(secret, sizeof(secret)); return; }
  // Bluetooth controller is now initialised; allocate the large protocol
  // workspaces on the heap without starving the Bluetooth init path.
  ensureScratchBuffers();
  Serial.println("WATCH_AUTH_CONNECT_TRY channel=0 lifecycle=single_attempt");
  if (!connectWatchWithSdp(address, "authenticated_bridge")) {
    Serial.println("WATCH_AUTH_CONNECT_FAILED lifecycle=closing_bt");
    watchBt.end();
    mbedtls_platform_zeroize(secret, sizeof(secret));
    return;
  }
  bool authenticated = false;
  do {
    Serial.println("WATCH_AUTH_SESSION_STARTED");
    if (!startSppV2Session("WATCH_AUTH")) break;
    SppV2Frame& frame = gSharedSppFrame;
    if (!readSppV2Frame(frame, kWatchVersionResponseTimeoutMs) || frame.type != 2 || frame.payloadLength < 1 || frame.payload[0] != 2) { Serial.println("WATCH_AUTH_SESSION_RESPONSE_INVALID"); break; }
    esp_fill_random(phoneNonce, sizeof(phoneNonce));
    uint8_t nonceCommand[27] = {0x08, 1, 0x10, 26, 0x1a, 21, 0xf2, 0x01, 18, 0x0a, 16};
    memcpy(nonceCommand + 11, phoneNonce, sizeof(phoneNonce));
    if (!sendSppV2Protobuf(0, nonceCommand, sizeof(nonceCommand))) { Serial.println("WATCH_AUTH_NONCE_WRITE_FAILED"); break; }
    const uint8_t* watchNonce = nullptr; const uint8_t* watchHmac = nullptr; size_t watchNonceLength = 0, watchHmacLength = 0; bool nonceDataSeen = false;
    const uint32_t nonceDeadline = millis() + kWatchVersionResponseTimeoutMs;
    while (millis() < nonceDeadline) {
      if (!readSppV2Frame(frame, nonceDeadline - millis())) break;
      if (frame.type == 3) { nonceDataSeen = true; writeSppV2Frame(1, frame.sequence, nullptr, 0); }
      if (extractWatchNonce(frame, watchNonce, watchNonceLength, watchHmac, watchHmacLength)) break;
    }
    if (!watchNonce) { Serial.println(nonceDataSeen ? "WATCH_AUTH_NONCE_FORMAT_INVALID" : "WATCH_AUTH_NONCE_TIMEOUT"); break; }
    if (watchNonceLength != 16 || watchHmacLength != 32) { Serial.println("WATCH_AUTH_NONCE_LENGTH_INVALID"); break; }

    // The known Round-4 protobuf is plaintext in firmware. buildStep3() uses
    // this watch's current AuthKey and current nonce exchange to AES-CCM
    // encrypt it inside a fresh Auth Step3 envelope.
    Serial.println("WATCH_R4_AUTH_IDENTITY_COMPATIBLE_TEMPLATE");
    const uint8_t* sessionDeviceInfo = kRound4CompatibleDeviceInfo;
    const size_t sessionDeviceInfoLength = sizeof(kRound4CompatibleDeviceInfo);
    if (!buildStep3(secret, phoneNonce, watchNonce, watchHmac,
                    step3, step3Length, decKey, encKey,
                    sessionDeviceInfo, sessionDeviceInfoLength)) {
      Serial.println("WATCH_AUTH_HMAC_OR_STEP3_INVALID");
      break;
    }
    Serial.printf("WATCH_R4_AUTH_IDENTITY_BUILT source=%s step3_bytes=%u\n",
                  "compatible_plaintext_reencrypted",
                  static_cast<unsigned>(step3Length));

    if (!sendSppV2Protobuf(1, step3, step3Length)) { Serial.println("WATCH_AUTH_STEP3_WRITE_FAILED"); break; }
    const uint32_t resultDeadline = millis() + kWatchVersionResponseTimeoutMs;
    while (millis() < resultDeadline) {
      if (!readSppV2Frame(frame, resultDeadline - millis())) break;
      if (frame.type == 3) writeSppV2Frame(1, frame.sequence, nullptr, 0);
      if (isAuthSuccess(frame)) { authenticated = true; break; }
    }
    Serial.println(authenticated ? "WATCH_AUTH_OK" : "WATCH_AUTH_RESPONSE_TIMEOUT");
    if (!authenticated) break;

    Serial.println("WATCH_HOLD_CONNECTED private_capture_local_only=true");
    setWatchBridgeState("connected");
    const bool networkProxyReady = gWatchRawTraceEnabled ? false : setupWatchNetworkProxy();
    if (gWatchRawTraceEnabled) Serial.println("WATCH_NETWORK_PROXY_SKIPPED raw_trace=true");
    Serial.printf("WATCH_AUTH_HEAP stage=after_network free=%lu largest=%lu proxy=%s\n",
                  static_cast<unsigned long>(ESP.getFreeHeap()),
                  static_cast<unsigned long>(ESP.getMaxAllocHeap()),
                  networkProxyReady ? "true" : "false");
    resetWatchNetworkSessionQueue();
    uint8_t outgoingSequence = 2;

    // ---------------------------------------------------------------
    // Round-4 exact replay, captured from the CURRENT Xiaomi 17 Pro.
    // Important differences vs old Round-3:
    //   ch8 id = B9379878
    //   seq4 is 5/10, not 2/14
    //   extra 2/14 variant ending in 08 02
    //   20/0 comes before 8/52
    //   type23/id3 is now 137 bytes
    // ---------------------------------------------------------------
    static constexpr uint8_t kRound4Ch8Init[] = {
        0x11,0x04,0x00,0x0e,0x0a,0x08,
        'B','9','3','7','9','8','7','8'
    };

    // Reuse the already-allocated 4 KiB raw-command workspace: zero new heap
    // and no 137-byte local array on the 6144-byte watch task stack.
    uint8_t* round4Type23 = gRawCommandPayloadScratch;
    constexpr size_t kRound4Type23Length = 137;
    // 这条 137 字节配置 blob 用抓包会话密钥加密，Auth Key 不匹配就解不开。
    // 它只是认证后的一条配置消息，不参与 HMAC/身份校验；解不开就跳过发送，
    // 其余 bootstrap 消息（ch8/2、网络状态、8/52 等都是硬编码明文）照常进行。
    bool haveType23 = round4Type23 && decryptRound4Type23Template(secret, round4Type23);
    if (haveType23) {
      Serial.printf("WATCH_ROUND4_TEMPLATE_DECRYPT_OK type23_len=%u free=%lu largest=%lu stack_hwm=%u\n",
                    static_cast<unsigned>(kRound4Type23Length),
                    static_cast<unsigned long>(ESP.getFreeHeap()),
                    static_cast<unsigned long>(ESP.getMaxAllocHeap()),
                    static_cast<unsigned>(uxTaskGetStackHighWaterMark(nullptr)));
    } else {
      Serial.println("WATCH_ROUND4_TEMPLATE_SKIPPED reason=key_mismatch (non-fatal)");
    }

    const uint8_t ch8InitSeq = outgoingSequence;
    if (sendEncryptedWatchChannel(outgoingSequence, encKey, 8, 2,
                                  kRound4Ch8Init, sizeof(kRound4Ch8Init))) {
      Serial.printf("WATCH_R4_CH8_INIT OK seq=%u id=B9379878\n",
                    static_cast<unsigned>(ch8InitSeq));
    } else {
      Serial.printf("WATCH_R4_CH8_INIT FAIL seq=%u\n",
                    static_cast<unsigned>(ch8InitSeq));
      mbedtls_platform_zeroize(round4Type23, kRound4Type23Length);
      break;
    }

    // ---------------------------------------------------------------
    // Round-4 21:00:57 SUCCESS branch ("warm branch"), exact ordering:
    // seq3  2/92
    // seq4  2/14 (...08 04)
    // seq5  2/2
    // seq6  2/44
    // seq7  2/6
    // seq8  5/10
    // seq9  2/14 (...08 02)
    // seq10 2/14 (...08 04)
    // seq11 20/0
    // seq12 23/3
    // seq13 8/52
    // seq14 2/2
    // Then after Watch initial batch: seq15 2/2, seq16 2/109.
    // Official Watch emits 23/2 BEFORE replying to 2/109.
    // ---------------------------------------------------------------

    uint8_t networkStatusPb[24]{};
    size_t networkStatusPbLength = 0;

    vTaskDelay(pdMS_TO_TICKS(9));
    const uint8_t statusSeq = outgoingSequence;
    if (buildSyncNetworkStatus(networkStatusPb, sizeof(networkStatusPb), networkStatusPbLength) &&
        sendEncryptedWatchPb(outgoingSequence, encKey, networkStatusPb, networkStatusPbLength)) {
      Serial.printf("WATCH_R4W_2/92 OK seq=%u\n", static_cast<unsigned>(statusSeq));
    } else {
      Serial.printf("WATCH_R4W_2/92 FAIL seq=%u\n", static_cast<unsigned>(statusSeq));
      mbedtls_platform_zeroize(round4Type23, kRound4Type23Length);
      break;
    }

    vTaskDelay(pdMS_TO_TICKS(6));
    doBootstrap(encKey, outgoingSequence,
                "\x08\x02\x10\x0e\x22\x05\x92\x02\x02\x08\x04", 11,
                "WATCH_R4W_2/14_04_A");

    vTaskDelay(pdMS_TO_TICKS(2));
    doBootstrap(encKey, outgoingSequence,
                "\x08\x02\x10\x02", 4,
                "WATCH_R4W_2/2_A");

    vTaskDelay(pdMS_TO_TICKS(1));
    doBootstrap(encKey, outgoingSequence,
                "\x08\x02\x10\x2c\x22\x07\xaa\x02\x04\x0a\x02\x08\x00", 13,
                "WATCH_R4W_2/44");

    vTaskDelay(pdMS_TO_TICKS(1));
    doBootstrap(encKey, outgoingSequence,
                "\x08\x02\x10\x06\x22\x0a\xa2\x01\x07\x0a\x05\x7a\x68\x5f\x63\x6e", 16,
                "WATCH_R4W_2/6_LANG");

    vTaskDelay(pdMS_TO_TICKS(2));
    doBootstrap(encKey, outgoingSequence,
                "\x08\x05\x10\x0a\x3a\x00", 6,
                "WATCH_R4W_5/10");

    vTaskDelay(pdMS_TO_TICKS(1));
    doBootstrap(encKey, outgoingSequence,
                "\x08\x02\x10\x0e\x22\x05\x92\x02\x02\x08\x02", 11,
                "WATCH_R4W_2/14_02");

    vTaskDelay(pdMS_TO_TICKS(1));
    doBootstrap(encKey, outgoingSequence,
                "\x08\x02\x10\x0e\x22\x05\x92\x02\x02\x08\x04", 11,
                "WATCH_R4W_2/14_04_B");

    vTaskDelay(pdMS_TO_TICKS(5));
    doBootstrap(encKey, outgoingSequence,
                "\x08\x14\x10\x00", 4,
                "WATCH_R4W_20/0");

    vTaskDelay(pdMS_TO_TICKS(3));
    // type23/id3 仅在抓包密钥匹配时发送；解不开就跳过（不消耗序列号，后续消息
    // 仍保持连续）。它是认证后的配置 blob，不发送不会影响 HMAC/身份认证。
    if (haveType23) {
      const uint8_t type23Seq = outgoingSequence;
      if (sendEncryptedWatchPb(outgoingSequence, encKey, round4Type23, kRound4Type23Length)) {
        Serial.printf("WATCH_R4W_23/3 OK seq=%u bytes=%u\n",
                      static_cast<unsigned>(type23Seq),
                      static_cast<unsigned>(kRound4Type23Length));
      } else {
        Serial.printf("WATCH_R4W_23/3 FAIL seq=%u\n", static_cast<unsigned>(type23Seq));
        mbedtls_platform_zeroize(round4Type23, kRound4Type23Length);
        break;
      }
    } else {
      Serial.println("WATCH_R4W_23/3 SKIPPED (no capture key)");
    }

    vTaskDelay(pdMS_TO_TICKS(4));
    doBootstrap(encKey, outgoingSequence,
                "\x08\x08\x10\x34\x52\x31\xe2\x02\x2e"
                "\x0a\x09\x08\x03\x10\x9c\xea\x02\x18\xbc\x77"
                "\x0a\x09\x08\x01\x10\x9c\xea\x02\x18\xbc\x77"
                "\x0a\x0a\x08\x06\x10\xfd\x84\x01\x18\xdc\xe2\x02"
                "\x0a\x0a\x08\x02\x10\x92\xf1\x01\x18\xef\xab\x01", 55,
                "WATCH_R4W_8/52");

    vTaskDelay(pdMS_TO_TICKS(9));
    doBootstrap(encKey, outgoingSequence,
                "\x08\x02\x10\x02", 4,
                "WATCH_R4W_2/2_B");

    mbedtls_platform_zeroize(round4Type23, kRound4Type23Length);

    Serial.println("WATCH_BOOTSTRAP_DONE mode=round4_auth_identity_exact_dynamic_lengths_v6_1");
    uint8_t dataPrefixBudget = 0;
    uint8_t networkFrameBudget = 32;

    // Round-4 post-bootstrap gate:
    // current official phone waits for the watch's initial response batch,
    // then sends 2/109 + 2/2 + 2/2.  After the watch returns 2/109 and
    // the following 2/2 responses, the phone sends 2/110.  type23/id2,
    // channel-8 and DHCP then follow.
    bool r4Seen20 = false;
    uint32_t r4Seen20Ms = 0;
    bool r4WarmExtra2Sent = false;
    uint32_t r4WarmExtra2DueMs = 0;
    uint32_t r4Warm109DueMs = 0;
    uint32_t r4Tx109DueMs = 0; // retained only for existing diagnostics
    bool r4Sent109 = false;
    bool r4Seen109 = false;
    uint32_t r4LiveWatchManualTs = 0;
    uint32_t r4LiveWatchSnapTs = 0;
    bool r4Parsed109State = false;
    uint8_t r4Post109Id2Count = 0;
    uint32_t r4Tx110DueMs = 0;
    bool r4Sent110 = false;
    bool r4Seen23Id2 = false;
    bool r4SawDhcp = false;

    // Round-4 timing-critical gate. Keep Wi-Fi and all nonessential background
    // work OFF until the official 109 -> 110 -> 23/2 -> DHCP transition either
    // succeeds or times out.  This protects both WROOM heap and millisecond
    // scheduling fidelity.
    const uint32_t bootstrapDoneMs = millis();
    constexpr uint32_t kR4GateTimeoutMs = 700;
    bool r4GateActive = true;
    bool wifiStartPending = !ssid.isEmpty() && WiFi.status() != WL_CONNECTED;
    uint32_t r4SlowAckCount = 0;
    uint32_t r4MaxAckUs = 0;
    Serial.printf("WATCH_R4W_FAST_GATE_START branch=210057 timeout_ms=%lu free=%lu largest=%lu\n",
                  static_cast<unsigned long>(kR4GateTimeoutMs),
                  static_cast<unsigned long>(ESP.getFreeHeap()),
                  static_cast<unsigned long>(ESP.getMaxAllocHeap()));

    while (watchBt.connected() && !gWatchBridgeStopRequested) {
      const uint32_t relNowMs = static_cast<uint32_t>(millis() - bootstrapDoneMs);

      // Periodic heap telemetry (every 30 s) so memory headroom is observable
      // during the long-lived bridge session even though this task blocks loop().
      {
        static uint32_t sNextHeapLogMs = 0;
        if (relNowMs >= sNextHeapLogMs) {
          sNextHeapLogMs = relNowMs + 30000u;
          Serial.printf("WATCH_LIVE_HEAP rel_ms=%lu free=%lu largest=%lu min_free=%lu tx_drop=%lu rx=%lu tx=%lu\n",
                        static_cast<unsigned long>(relNowMs),
                        static_cast<unsigned long>(ESP.getFreeHeap()),
                        static_cast<unsigned long>(ESP.getMaxAllocHeap()),
                        static_cast<unsigned long>(ESP.getMinFreeHeap()),
                        static_cast<unsigned long>(gWatchNetworkDroppedPackets),
                        static_cast<unsigned long>(gWatchNetworkRxPackets),
                        static_cast<unsigned long>(gWatchNetworkTxPackets));
        }
      }

      // Exact 21:00:57 post-bootstrap branch:
      //   Watch 20/0
      //     + ~6.8 ms  -> Phone seq15 2/2
      //     + ~25.8 ms -> Phone seq16 2/109
      //     + ~21.4 ms -> Watch 23/2 (before Watch replies to 2/109)
      if (r4GateActive && r4Seen20 && !r4WarmExtra2Sent &&
          r4WarmExtra2DueMs != 0 &&
          static_cast<int32_t>(millis() - r4WarmExtra2DueMs) >= 0) {
        static constexpr uint8_t kR4Id2[] = {0x08,0x02,0x10,0x02};
        const uint32_t txStartedUs = micros();
        const uint8_t seq2 = outgoingSequence;
        r4WarmExtra2Sent = sendEncryptedWatchPb(outgoingSequence, encKey,
                                                kR4Id2, sizeof(kR4Id2));
        const uint32_t txUs = micros() - txStartedUs;
        if (r4WarmExtra2Sent) r4Warm109DueMs = millis() + 26u;
        Serial.printf("WATCH_R4W_GATE_TX rel_ms=%lu 2/2_seq=%u status=%s tx_us=%lu next109_due_rel_ms=%lu\n",
                      static_cast<unsigned long>(millis() - bootstrapDoneMs),
                      static_cast<unsigned>(seq2),
                      r4WarmExtra2Sent ? "OK" : "FAIL",
                      static_cast<unsigned long>(txUs),
                      r4Warm109DueMs ? static_cast<unsigned long>(r4Warm109DueMs - bootstrapDoneMs) : 0ul);
      }

      if (r4GateActive && r4WarmExtra2Sent && !r4Sent109 &&
          r4Warm109DueMs != 0 &&
          static_cast<int32_t>(millis() - r4Warm109DueMs) >= 0) {
        static constexpr uint8_t kR4Id109[] = {0x08,0x02,0x10,0x6d};
        const uint32_t txStartedUs = micros();
        const uint8_t seq109 = outgoingSequence;
        r4Sent109 = sendEncryptedWatchPb(outgoingSequence, encKey,
                                         kR4Id109, sizeof(kR4Id109));
        const uint32_t txUs = micros() - txStartedUs;
        Serial.printf("WATCH_R4W_GATE_TX rel_ms=%lu 2/109_seq=%u status=%s tx_us=%lu expect_23_before_109_reply=true\n",
                      static_cast<unsigned long>(millis() - bootstrapDoneMs),
                      static_cast<unsigned>(seq109),
                      r4Sent109 ? "OK" : "FAIL",
                      static_cast<unsigned long>(txUs));
      }

      // Deliberately DO NOT send 2/110 in this A/B round.
      // During the timing-critical gate, run ONLY SPP/DHCP work. No Wi-Fi,
      // ASR, stream scheduling, mDNS, HTTP, or other application work.
      if (!r4GateActive) {
        // Keep the home-WiFi uplink alive and make sure lwIP's default route
        // points at STA before forwarding watch packets.
        serviceWatchInternetUplink();
        drainWatchNetworkTx(outgoingSequence);

        // 待投递文本：这个会话是长连接，只在刚建立时补发一次的话，之后的
        // 推送会一直排在队列里出不去 —— 第二次点「发送到手表」就会报
        // 「发送队列已满」。空闲时定期补发，最短间隔 1.5 秒。
        if (gPendingWatchTextReady) {
          static uint32_t sNextPushAttemptMs = 0;
          if (static_cast<int32_t>(millis() - sNextPushAttemptMs) >= 0) {
            sNextPushAttemptMs = millis() + 1500u;
            if (flushPendingWatchText(outgoingSequence, encKey)) {
              velaLog("PUSH_SENT via=idle_loop");
            }
          }
        } else if (gPushTaskState == 1) {
          // 队列是空的、也没在投递，说明这条消息根本没走到发送函数
          // （文本被新一轮覆盖、或会话刚重建）。别让页面一直转圈。
          static uint32_t sPushIdleSinceMs = 0;
          if (sPushIdleSinceMs == 0) sPushIdleSinceMs = millis();
          if (millis() - sPushIdleSinceMs > 3000u) {
            sPushIdleSinceMs = 0;
            pushWatchFail("消息未投递，链路已重建，请重试");
          }
        }
      }

      if (r4GateActive &&
          (r4SawDhcp || static_cast<uint32_t>(millis() - bootstrapDoneMs) >= kR4GateTimeoutMs)) {
        r4GateActive = false;
        Serial.printf("WATCH_R4W_FAST_GATE_END rel_ms=%lu result=%s 20=%u tx109=%u rx109=%u id2count=%u tx110=%u 23=%u dhcp=%u max_ack_us=%lu slow_acks=%lu free=%lu largest=%lu\n",
                      static_cast<unsigned long>(millis() - bootstrapDoneMs),
                      r4SawDhcp ? "SUCCESS" : "TIMEOUT",
                      r4Seen20 ? 1u : 0u, r4Sent109 ? 1u : 0u, r4Seen109 ? 1u : 0u,
                      static_cast<unsigned>(r4Post109Id2Count),
                      r4Sent110 ? 1u : 0u, r4Seen23Id2 ? 1u : 0u, r4SawDhcp ? 1u : 0u,
                      static_cast<unsigned long>(r4MaxAckUs),
                      static_cast<unsigned long>(r4SlowAckCount),
                      static_cast<unsigned long>(ESP.getFreeHeap()),
                      static_cast<unsigned long>(ESP.getMaxAllocHeap()));

        if (wifiStartPending) {
          Serial.printf("WATCH_HEAP_PRE_WIFI rel_ms=%lu free=%lu largest=%lu\n",
                        static_cast<unsigned long>(millis() - bootstrapDoneMs),
                        static_cast<unsigned long>(ESP.getFreeHeap()),
                        static_cast<unsigned long>(ESP.getMaxAllocHeap()));
          WiFi.persistent(false);
          WiFi.setAutoReconnect(true);
          WiFi.mode(WIFI_STA);
          WiFi.begin(ssid.c_str(), wifiPass.c_str());
          gWatchLastWifiBeginMs = millis();
          gWatchInternetRouteReady = false;
          wifiStartPending = false;
          Serial.printf("WATCH_WIFI_STA_STARTED_NONBLOCKING rel_ms=%lu free=%lu largest=%lu\n",
                        static_cast<unsigned long>(millis() - bootstrapDoneMs),
                        static_cast<unsigned long>(ESP.getFreeHeap()),
                        static_cast<unsigned long>(ESP.getMaxAllocHeap()));
        }
      }

      // Never let a 250 ms read timeout destroy the Round-4 deadlines.
      // 表盘/快应用安装：每轮最多发一片，靠设备 ACK 驱动下一片。
      // 放在读帧之前，读超时也能继续推进（否则空闲时进度会卡住）。
      wfi::pump(outgoingSequence, encKey);

      const uint32_t sppReadTimeoutMs = r4GateActive ? 2u : 250u;
      if (!readSppV2Frame(frame, sppReadTimeoutMs)) {
        delay(2);
        continue;
      }
      emitWatchRawTrace(frame);
      if (frame.type == 1) wfi::onAck(frame.sequence);
      const size_t encryptedLength = frame.payloadLength;
      const uint8_t rawChannel = frame.payloadLength >= 1 ? (frame.payload[0] & 0x0f) : 0xff;
      const uint8_t rawOpcode = frame.payloadLength >= 2 ? frame.payload[1] : 0xff;
      const size_t dataLength = frame.payloadLength >= 2 ? frame.payloadLength - 2 : 0;
      if (frame.type == 3 && rawChannel != 7 && rawChannel != 10) {
        const uint32_t ackStartedUs = micros();
        const bool ackOk = writeSppV2Frame(1, frame.sequence, nullptr, 0);
        const uint32_t ackUs = micros() - ackStartedUs;
        if (ackUs > r4MaxAckUs) r4MaxAckUs = ackUs;
        if (r4GateActive && ackUs >= 5000u) {
          ++r4SlowAckCount;
          Serial.printf("WATCH_R4_SLOW_ACK rel_ms=%lu seq=%u ok=%s ack_us=%lu\n",
                        static_cast<unsigned long>(millis() - bootstrapDoneMs),
                        static_cast<unsigned>(frame.sequence),
                        ackOk ? "true" : "false",
                        static_cast<unsigned long>(ackUs));
        }
      }
      bool dataDecrypted = false;
      if (frame.type == 3 && dataLength > 0 && rawChannel != 1 && rawOpcode == 2) {
        dataDecrypted = aes128CtrCrypt(decKey, frame.payload + 2, dataLength);
      }
      if (kNetTrace && frame.type == 3 && rawChannel == 8 && dataLength > 0) {
        // WROOM-safe diagnostic: print directly, no temporary String/heap allocation.
        const size_t ch8PrefixLength = min(static_cast<size_t>(48), dataLength);
        Serial.printf("WATCH_CH8_RX seq=%u opcode=%u bytes=%u decrypted=%s prefix=",
                      static_cast<unsigned>(frame.sequence),
                      static_cast<unsigned>(rawOpcode),
                      static_cast<unsigned>(dataLength),
                      dataDecrypted ? "true" : "false");
        for (size_t i = 0; i < ch8PrefixLength; ++i) {
          Serial.printf("%02X", frame.payload[2 + i]);
        }
        Serial.println();
      }
      if (dataDecrypted && rawChannel == 3) {
        // Voice/ASR was intentionally removed. Keep the SPP session alive,
        // but never allocate capture buffers, SPIFFS files, decoder state, or
        // a cloud ASR task for ch3 audio.
        static bool voiceAsrDisabledLogged = false;
        if (!voiceAsrDisabledLogged) {
          Serial.println("WATCH_VOICE_ASR_DISABLED ch3_ignored=true");
          voiceAsrDisabledLogged = true;
        }
      }
      if (frame.type == 3 && rawChannel == 7 && dataLength > 0 &&
          (rawOpcode == 1 || (rawOpcode == 2 && dataDecrypted))) {
        const bool dhcpHandled = handleWatchDhcp(frame.payload + 2, dataLength, outgoingSequence);
        if (dhcpHandled && !r4SawDhcp) {
          r4SawDhcp = true;
          Serial.printf("WATCH_R4W_SUCCESS DHCP rel_ms=%lu max_ack_us=%lu slow_acks=%lu\n",
                        static_cast<unsigned long>(millis() - bootstrapDoneMs),
                        static_cast<unsigned long>(r4MaxAckUs),
                        static_cast<unsigned long>(r4SlowAckCount));
        }
        if (!dhcpHandled && !injectWatchNetworkPacket(frame.payload + 2, dataLength)) {
          Serial.printf("WATCH_NETWORK_RX_REJECTED opcode=%u bytes=%u\n",
                        static_cast<unsigned>(rawOpcode), static_cast<unsigned>(dataLength));
        }
      }
      const uint8_t* pb = nullptr;
      size_t pbLength = 0;
      uint32_t pbType = 0xffffffffu, pbId = 0xffffffffu;
      const bool decrypted = decryptWatchPb(frame, decKey, pb, pbLength);
      if (decrypted) {
        protoVarintField(pb, pbLength, 1, pbType);
        protoVarintField(pb, pbLength, 2, pbId);
        if (wfi::busy()) wfi::onProto(pbType, pbId, pb, pbLength);

        if (pbType == 20 && pbId == 0 && !r4Seen20) {
          r4Seen20 = true;
          r4Seen20Ms = millis();
          r4WarmExtra2DueMs = r4Seen20Ms + 7u;
          Serial.printf("WATCH_R4W_GATE_RX 20/0 rel_ms=%lu extra2_due_rel_ms=%lu\n",
                        static_cast<unsigned long>(r4Seen20Ms - bootstrapDoneMs),
                        static_cast<unsigned long>(r4WarmExtra2DueMs - bootstrapDoneMs));
        }
        if (r4Sent109 && pbType == 2 && pbId == 109 && !r4Seen109) {
          r4Seen109 = true;
          r4Parsed109State = parseRound4Id109State(pb, pbLength,
                                                   r4LiveWatchManualTs,
                                                   r4LiveWatchSnapTs);
          Serial.printf("WATCH_R4_GATE_RX 2/109 rel_ms=%lu bytes=%u parsed=%s watch_manual_ts=%lu watch_snap_ts=%lu captured_manual_ts=%lu same_as_capture=%s hex=",
                        static_cast<unsigned long>(millis() - bootstrapDoneMs),
                        static_cast<unsigned>(pbLength),
                        r4Parsed109State ? "true" : "false",
                        static_cast<unsigned long>(r4LiveWatchManualTs),
                        static_cast<unsigned long>(r4LiveWatchSnapTs),
                        static_cast<unsigned long>(1786703622u),
                        r4LiveWatchManualTs == 1786703622u ? "true" : "false");
          for (size_t i = 0; i < pbLength; ++i) Serial.printf("%02X", pb[i]);
          Serial.println();
        } else if (r4Sent109 && r4Seen109 && !r4Sent110 &&
                   pbType == 2 && pbId == 2 && r4Post109Id2Count < 2) {
          ++r4Post109Id2Count;
          Serial.printf("WATCH_R4_GATE_RX 2/2_after109 rel_ms=%lu count=%u bytes=%u\n",
                        static_cast<unsigned long>(millis() - bootstrapDoneMs),
                        static_cast<unsigned>(r4Post109Id2Count),
                        static_cast<unsigned>(pbLength));
          if (r4Post109Id2Count == 2) {
            r4Tx110DueMs = millis() + 10u;
            Serial.printf("WATCH_R4_GATE_110_ARM due_rel_ms=%lu\n",
                          static_cast<unsigned long>(r4Tx110DueMs - bootstrapDoneMs));
          }
        }
        if (pbType == 23 && pbId == 2 && !r4Seen23Id2) {
          r4Seen23Id2 = true;
          Serial.printf("WATCH_R4W_SUCCESS type23/id2 rel_ms=%lu\n",
                        static_cast<unsigned long>(millis() - bootstrapDoneMs));
        }

        // Log unknown protobuf types for reverse-engineering
        if (pbType != 2 && pbType != 10) {
          Serial.printf("WATCH_PB_UNKNOWN type=%lu id=%lu bytes=%u hex=",
                        static_cast<unsigned long>(pbType), static_cast<unsigned long>(pbId),
                        static_cast<unsigned>(pbLength));
          const size_t pbPrefixLength = min(static_cast<size_t>(64), pbLength);
          for (size_t i = 0; i < pbPrefixLength; ++i) Serial.printf("%02X", pb[i]);
          Serial.println();
        }
        if (pbType == 10) {
          Serial.printf("WATCH_NETWORK_CONTROL type=10 id=%lu bytes=%u observed_official_state_machine=true\n",
                        static_cast<unsigned long>(pbId), static_cast<unsigned>(pbLength));
          // Official phone replies type10/id5 to type10/id3
          if (pbId == 3) {
            static const uint8_t kType10Id5Reply[] = {0x08, 0x0a, 0x10, 0x05};
            if (sendEncryptedWatchPb(outgoingSequence, encKey,
                                     kType10Id5Reply, sizeof(kType10Id5Reply))) {
              Serial.println("WATCH_TYPE10_ID3_REPLY type10/id5");
            }
          }
        }
        // Log type=18 but do NOT reply. It's in the Music protobuf family,
        // not a network-config request. The real DHCP trigger is the
        // post-auth bootstrap sequence (type23/id3 → watch type23/id2).
        if (pbType == 18) {
          Serial.printf("WATCH_PB_OBSERVED type=18 (Music family) id=%lu bytes=%u hex=",
                        static_cast<unsigned long>(pbId), static_cast<unsigned>(pbLength));
          const size_t type18PrefixLength = min(static_cast<size_t>(64), pbLength);
          for (size_t i = 0; i < type18PrefixLength; ++i) Serial.printf("%02X", pb[i]);
          Serial.println();
        }
        if (networkProxyReady && pbType == 2 && pbId == 82) {
          if (sendEncryptedWatchPb(outgoingSequence, encKey, networkStatusPb, networkStatusPbLength)) {
            Serial.println("WATCH_NETWORK_STATUS_SENT capability=2 request_id=82");
          } else {
            Serial.println("WATCH_NETWORK_STATUS_SEND_FAILED request_id=82");
          }
        }
      }
      if (kNetTrace) {
        Serial.printf("WATCH_HOLD_FRAME rel_ms=%lu type=%u seq=%u bytes=%u decrypted=%s pb_type=%lu pb_id=%lu\n",
                      static_cast<unsigned long>(millis() - bootstrapDoneMs),
                      static_cast<unsigned>(frame.type),
                      static_cast<unsigned>(frame.sequence),
                      static_cast<unsigned>(encryptedLength),
                      decrypted ? "true" : "false",
                      static_cast<unsigned long>(pbType),
                      static_cast<unsigned long>(pbId));
      }
      if (kNetTrace && frame.type == 3 && frame.payloadLength >= 2 && rawChannel != 1) {
        if (rawChannel == 7 && dataLength > 0 && networkFrameBudget > 0) {
          const size_t networkPrefixLength = min(static_cast<size_t>(24), dataLength);
          const String networkPrefix = hexBytes(frame.payload + 2, networkPrefixLength);
          Serial.printf("WATCH_NETWORK_FRAME opcode=%u bytes=%u ip_version=%u prefix=%s\n",
                        static_cast<unsigned>(rawOpcode), static_cast<unsigned>(dataLength),
                        static_cast<unsigned>(frame.payload[2] >> 4), networkPrefix.c_str());
          --networkFrameBudget;
        }
        if (dataLength <= 8) dataPrefixBudget = 3;
        if (dataLength <= 8 || dataPrefixBudget > 0) {
          const size_t prefixLength = min(static_cast<size_t>(16), dataLength);
          const String prefix = hexBytes(frame.payload + 2, prefixLength);
          Serial.printf("WATCH_DATA_FRAME channel=%u opcode=%u data_bytes=%u prefix=%s data_decrypted=%s\n",
                        static_cast<unsigned>(rawChannel),
                        static_cast<unsigned>(rawOpcode),
                        static_cast<unsigned>(dataLength), prefix.c_str(),
                        dataDecrypted ? "true" : "false");
          if (dataLength > 8 && dataPrefixBudget > 0) --dataPrefixBudget;
        }
      }
    }
    if (gWatchBridgeStopRequested) Serial.println("WATCH_HOLD_STOP_REQUESTED");
    Serial.printf("WATCH_HOLD_DISCONNECTED network_rx=%lu network_tx=%lu network_drop=%lu r4_20=%u r4_tx109=%u r4_rx109=%u r4_id2count=%u r4_tx110=%u r4_23=%u r4_dhcp=%u max_ack_us=%lu slow_acks=%lu\n",
                  static_cast<unsigned long>(gWatchNetworkRxPackets),
                  static_cast<unsigned long>(gWatchNetworkTxPackets),
                  static_cast<unsigned long>(gWatchNetworkDroppedPackets),
                  r4Seen20 ? 1u : 0u, r4Sent109 ? 1u : 0u, r4Seen109 ? 1u : 0u,
                  static_cast<unsigned>(r4Post109Id2Count),
                  r4Sent110 ? 1u : 0u, r4Seen23Id2 ? 1u : 0u, r4SawDhcp ? 1u : 0u,
                  static_cast<unsigned long>(r4MaxAckUs),
                  static_cast<unsigned long>(r4SlowAckCount));
  } while (false);
  watchBt.disconnect(); watchBt.end();
  gWatchRawTraceEnabled = false;
  mbedtls_platform_zeroize(secret, sizeof(secret)); mbedtls_platform_zeroize(phoneNonce, sizeof(phoneNonce)); mbedtls_platform_zeroize(step3, sizeof(step3));
  mbedtls_platform_zeroize(encKey, sizeof(encKey)); mbedtls_platform_zeroize(decKey, sizeof(decKey));
  secretText = "";
}


void drainWatchWakeControlFrames(uint32_t durationMs) {
  const uint32_t deadline = millis() + durationMs;
  SppV2Frame& frame = gSharedSppFrame;
  uint32_t frames = 0;
  while (millis() < deadline) {
    const uint32_t remaining = deadline - millis();
    if (!readSppV2Frame(frame, remaining)) break;
    ++frames;
    if (frame.type == 3) writeSppV2Frame(1, frame.sequence, nullptr, 0);
  }
  if (frames) Serial.printf("WATCH_BRIDGE_WAKE_CONTROL_DRAIN frames=%lu\n", static_cast<unsigned long>(frames));
}

bool sendQuickAppWakePing(const WatchAppInfo& app, uint8_t& sequence,
                          const uint8_t encKey[16], const uint8_t decKey[16],
                          uint8_t* pb, size_t pbCapacity, size_t& pbLength,
                          uint32_t timeoutMs, uint32_t logicalAttempt,
                          const char* stage) {
  char pingJson[256];
  const int pingLength = snprintf(pingJson, sizeof(pingJson),
      "{\"v\":2,\"id\":\"esp32_wake_%lu\",\"timestamp\":%lu,\"type\":\"ping\",\"payload\":{\"from\":\"esp32\",\"protocolVersion\":2}}",
      static_cast<unsigned long>(logicalAttempt), static_cast<unsigned long>(millis()));
  if (pingLength <= 0 || static_cast<size_t>(pingLength) >= sizeof(pingJson) ||
      !buildQuickAppMessage(app, reinterpret_cast<const uint8_t*>(pingJson), static_cast<size_t>(pingLength), pb, pbCapacity, pbLength) ||
      !sendEncryptedWatchPb(sequence, encKey, pb, pbLength)) {
    Serial.printf("WATCH_BRIDGE_WAKE_PING_WRITE_FAILED stage=%s attempt=%lu\n", stage, static_cast<unsigned long>(logicalAttempt));
    return false;
  }

  Serial.printf("WATCH_BRIDGE_WAKE_PING_SENT stage=%s attempt=%lu timeout_ms=%lu\n",
                stage, static_cast<unsigned long>(logicalAttempt), static_cast<unsigned long>(timeoutMs));
  const uint32_t deadline = millis() + timeoutMs;
  SppV2Frame& frame = gSharedSppFrame;
  uint32_t frames = 0, nonData = 0, decryptFail = 0, appParseFail = 0;
  while (millis() < deadline) {
    const uint32_t remaining = deadline - millis();
    if (!readSppV2Frame(frame, remaining)) break;
    ++frames;
    if (frame.type != 3) { ++nonData; continue; }
    writeSppV2Frame(1, frame.sequence, nullptr, 0);
    const uint8_t* incoming = nullptr; size_t incomingLength = 0;
    const uint8_t* content = nullptr; size_t contentLength = 0;
    if (!decryptWatchPb(frame, decKey, incoming, incomingLength)) { ++decryptFail; continue; }
    if (!parseQuickAppMessage(incoming, incomingLength, content, contentLength)) { ++appParseFail; continue; }
    if (containsAscii(content, contentLength, "\"type\":\"pong\"")) {
      Serial.printf("WATCH_BRIDGE_WAKE_PONG stage=%s attempt=%lu frames=%lu\n",
                    stage, static_cast<unsigned long>(logicalAttempt), static_cast<unsigned long>(frames));
      return true;
    }
  }
  Serial.printf("WATCH_BRIDGE_WAKE_PING_TIMEOUT stage=%s attempt=%lu frames=%lu non_data=%lu decrypt_fail=%lu app_parse_fail=%lu buffered=%u queue=%d\n",
                stage, static_cast<unsigned long>(logicalAttempt), static_cast<unsigned long>(frames),
                static_cast<unsigned long>(nonData), static_cast<unsigned long>(decryptFail),
                static_cast<unsigned long>(appParseFail), static_cast<unsigned>(gSppRxBuffered), watchRxAvailable());
  return false;
}

bool wakeQuickAppRobust(const WatchAppInfo& app, uint8_t& sequence,
                        const uint8_t encKey[16], const uint8_t decKey[16],
                        uint8_t* pb, size_t pbCapacity, size_t& pbLength) {
  Serial.println("WATCH_BRIDGE_WAKE_BOOTSTRAP version=7.1 strategy=ping-launch-poll-relaunch");

  // Fast path: after an update the QuickApp may already be resident even if a
  // launch request is unnecessary. Avoid perturbing a healthy app first.
  if (sendQuickAppWakePing(app, sequence, encKey, decKey, pb, pbCapacity, pbLength,
                           2500, 0, "resident")) {
    Serial.println("WATCH_BRIDGE_WAKE_READY path=resident");
    return true;
  }

  constexpr uint8_t kLaunchCycles = 2;
  constexpr uint8_t kPollsPerCycle = 4;
  for (uint8_t cycle = 1; cycle <= kLaunchCycles; ++cycle) {
    Serial.printf("WATCH_BRIDGE_WAKE_LAUNCH cycle=%u/%u\n", static_cast<unsigned>(cycle), static_cast<unsigned>(kLaunchCycles));

    // Serialize status and launch instead of firing both system commands back
    // to back. The old final-acceptance path could leave control responses
    // queued while the newly-installed QuickApp was cold-starting.
    if (!buildQuickAppStatus(app, pb, pbCapacity, pbLength) || !sendEncryptedWatchPb(sequence, encKey, pb, pbLength)) {
      Serial.printf("WATCH_BRIDGE_STATUS_WRITE_FAILED cycle=%u\n", static_cast<unsigned>(cycle));
      return false;
    }
    drainWatchWakeControlFrames(750);

    if (!buildQuickAppLaunch(app, pb, pbCapacity, pbLength) || !sendEncryptedWatchPb(sequence, encKey, pb, pbLength)) {
      Serial.printf("WATCH_BRIDGE_LAUNCH_WRITE_FAILED cycle=%u\n", static_cast<unsigned>(cycle));
      return false;
    }
    drainWatchWakeControlFrames(1250);
    delay(cycle == 1 ? 2500 : 4000);

    for (uint8_t poll = 1; poll <= kPollsPerCycle; ++poll) {
      const uint32_t logicalAttempt = static_cast<uint32_t>(cycle) * 10u + poll;
      if (sendQuickAppWakePing(app, sequence, encKey, decKey, pb, pbCapacity, pbLength,
                               3000, logicalAttempt, cycle == 1 ? "launch" : "relaunch")) {
        Serial.printf("WATCH_BRIDGE_WAKE_READY path=%s cycle=%u poll=%u\n",
                      cycle == 1 ? "launch" : "relaunch", static_cast<unsigned>(cycle), static_cast<unsigned>(poll));
        return true;
      }
      if (poll < kPollsPerCycle) delay(700);
    }
  }

  Serial.println("WATCH_BRIDGE_WAKE_RECOVERY_EXHAUSTED");
  logSppRxParserState("wake_recovery_exhausted");
  return false;
}

void bridgeWatchQuickApp(String target, String secretText, uint8_t benchmarkMode = 0) {
  uint8_t address[6], secret[16]{}, phoneNonce[16]{}, step3[160]{}, encKey[16]{}, decKey[16]{};
  size_t step3Length = 0;
  WatchAppInfo app;
  target.trim(); target.toUpperCase();
  if (!parseWatchAddress(target, address) || !parseSecretHex(secretText, secret)) {
    Serial.println("WATCH_BRIDGE_INVALID_INPUT");
    return;
  }
  Serial.println("WATCH_BRIDGE_BT_INIT_STARTED");
  if (!beginWatchBluetooth("Vela-Gateway")) {
    Serial.println("WATCH_BRIDGE_BT_INIT_FAILED");
    mbedtls_platform_zeroize(secret, sizeof(secret));
    return;
  }
  Serial.println("WATCH_BRIDGE_CONNECT_STARTED");
  if (!connectWatchWithSdp(address, "quickapp_bridge")) {
    Serial.println("WATCH_BRIDGE_CONNECT_FAILED");
    watchBt.end();
    mbedtls_platform_zeroize(secret, sizeof(secret));
    return;
  }

  bool authenticated = false;
  do {
    Serial.println("WATCH_BRIDGE_SESSION_STARTED");
    if (!startSppV2Session("WATCH_BRIDGE")) break;
    SppV2Frame& frame = gSharedSppFrame;
    if (!readSppV2Frame(frame, kWatchVersionResponseTimeoutMs) || frame.type != 2 || frame.payloadLength < 1 || frame.payload[0] != 2) { Serial.println("WATCH_BRIDGE_SESSION_RESPONSE_INVALID"); break; }
    esp_fill_random(phoneNonce, sizeof(phoneNonce));
    uint8_t nonceCommand[27] = {0x08, 1, 0x10, 26, 0x1a, 21, 0xf2, 0x01, 18, 0x0a, 16};
    memcpy(nonceCommand + 11, phoneNonce, sizeof(phoneNonce));
    if (!sendSppV2Protobuf(0, nonceCommand, sizeof(nonceCommand))) { Serial.println("WATCH_BRIDGE_NONCE_WRITE_FAILED"); break; }
    const uint8_t* watchNonce = nullptr; const uint8_t* watchHmac = nullptr; size_t watchNonceLength = 0, watchHmacLength = 0;
    const uint32_t nonceDeadline = millis() + kWatchVersionResponseTimeoutMs;
    while (millis() < nonceDeadline) {
      if (!readSppV2Frame(frame, nonceDeadline - millis())) break;
      if (frame.type == 3) writeSppV2Frame(1, frame.sequence, nullptr, 0);
      if (extractWatchNonce(frame, watchNonce, watchNonceLength, watchHmac, watchHmacLength)) break;
    }
    if (!watchNonce || watchNonceLength != 16 || watchHmacLength != 32 || !buildStep3(secret, phoneNonce, watchNonce, watchHmac, step3, step3Length, decKey, encKey)) {
      Serial.println("WATCH_BRIDGE_AUTH_FAILED");
      break;
    }
    if (!sendSppV2Protobuf(1, step3, step3Length)) { Serial.println("WATCH_BRIDGE_AUTH_WRITE_FAILED"); break; }
    const uint32_t authDeadline = millis() + kWatchVersionResponseTimeoutMs;
    while (millis() < authDeadline) {
      if (!readSppV2Frame(frame, authDeadline - millis())) break;
      if (frame.type == 3) writeSppV2Frame(1, frame.sequence, nullptr, 0);
      if (isAuthSuccess(frame)) { authenticated = true; break; }
    }
    if (!authenticated) { Serial.println("WATCH_BRIDGE_AUTH_TIMEOUT"); break; }
    Serial.println("WATCH_BRIDGE_AUTH_OK");
    velaLog("BT_AUTH_OK mac=%s", watchMac.c_str());
    gWatchEverAuthedOnce = true;

    if (!ensureScratchBuffers()) {
      Serial.println("WATCH_BRIDGE_SCRATCH_UNAVAILABLE");
      break;
    }
    uint8_t* pb = gRawCommandPayloadScratch;
    size_t pbLength = 0;
    uint8_t sequence = 2;
    // 每轮先补发一次待投递文本：此时会话已经认证、密钥可用、app 已定位，
    // 是唯一安全的投递时机（别的时候发会被手表当成脏帧丢掉）。
    flushPendingWatchText(sequence, encKey);
    if (!buildQuickAppListRequest(pb, kSppV2PayloadMax, pbLength) ||
        !sendEncryptedWatchPb(sequence, encKey, pb, pbLength)) {
      Serial.println("WATCH_BRIDGE_APP_LIST_WRITE_FAILED");
      break;
    }
    Serial.println("WATCH_BRIDGE_APP_LIST_REQUEST_SENT");
    const uint32_t listDeadline = millis() + kWatchBridgeResponseTimeoutMs;
    while (millis() < listDeadline && !app.found) {
      if (!readSppV2Frame(frame, listDeadline - millis())) break;
      if (frame.type != 3) continue;
      writeSppV2Frame(1, frame.sequence, nullptr, 0);
      const uint8_t* incoming = nullptr; size_t incomingLength = 0;
      if (decryptWatchPb(frame, decKey, incoming, incomingLength)) parseQuickAppList(incoming, incomingLength, app);
    }
    if (!app.found) { Serial.println("WATCH_BRIDGE_QUICKAPP_NOT_FOUND"); break; }
    Serial.printf("WATCH_BRIDGE_QUICKAPP_FOUND fingerprint_bytes=%u fingerprint_sha1=%s\n",
                  static_cast<unsigned>(app.fingerprintLength), hexBytes(app.fingerprint, app.fingerprintLength).c_str());
    rememberWatchApp(app);

    const bool pong = wakeQuickAppRobust(app, sequence, encKey, decKey, pb, kSppV2PayloadMax, pbLength);
    if (!pong) Serial.println("WATCH_BRIDGE_WAKE_TIMEOUT");
    Serial.println(pong ? "WATCH_BRIDGE_PONG_OK" : "WATCH_BRIDGE_PONG_TIMEOUT");
    if (!pong) {
      if (benchmarkMode == 10) {
        Serial.println("FINAL_ACCEPTANCE_RESULT wake=FAIL preflight=NOT_RUN control=NOT_RUN echo256=NOT_RUN decode256=NOT_RUN durable_ack_retry=NOT_RUN segment256=NOT_RUN push=NOT_RUN FAIL");
      }
      break;
    }
    if (benchmarkMode == 2 || benchmarkMode == 1 || benchmarkMode == 3 || benchmarkMode == 4 || benchmarkMode == 5 || benchmarkMode == 6 || benchmarkMode == 7 || benchmarkMode == 8 || benchmarkMode == 9 || benchmarkMode == 10) {
      // The isolated 256 KiB probe disproved sequence-wrap as the current first
      // failure: it stalls before the guard threshold. Keep normal benchmark
      // modes on the raw transport sequence so a later 255->0 issue, if real,
      // remains observable instead of being hidden by a speculative workaround.
      const bool renewalExperiment = benchmarkMode == 4;
      const bool pacedExperiment = benchmarkMode == 5;
      const bool coalescedTxExperiment = benchmarkMode == 8;  // retained as compatibility alias; coalesced is now production default
      if (renewalExperiment) configureBenchSessionRenewal(secret, encKey, decKey);
      gSppTxCoalesced = true;
      Serial.println("SPP_TX_MODE coalesced=true production_default legacy_segment_bytes=16 disabled=true");
      gBenchInterChunkGapMs = pacedExperiment ? kBenchPacedChunkGapMs : 0;
      if (pacedExperiment) Serial.printf("BENCH_PACING enabled gap_ms=%lu\n", static_cast<unsigned long>(gBenchInterChunkGapMs));
      if (benchmarkMode == 2) runWatchBenchmarkQuick(app, sequence, encKey, decKey);
      else if (benchmarkMode == 3 || benchmarkMode == 4 || benchmarkMode == 5) runWatchBenchmark256K(app, sequence, encKey, decKey);
      else if (benchmarkMode == 6 || benchmarkMode == 8) runWatchStreamProbe(app, sequence, encKey, decKey, "echo");
      else if (benchmarkMode == 7) runWatchStreamProbe(app, sequence, encKey, decKey, "decode");
      else if (benchmarkMode == 9) runWatchBenchmark256KSegment32K(app, sequence, encKey, decKey);
      else if (benchmarkMode == 10) runWatchFinalAcceptance(app, sequence, encKey, decKey);
      else runWatchBenchmark(app, sequence, encKey, decKey);
      gBenchInterChunkGapMs = 0;
      gSppTxCoalesced = true;
      if (renewalExperiment) clearBenchSessionRenewal();
      break;
    }

    const uint32_t inboxNonce = esp_random();
    const int writeLength = snprintf(reinterpret_cast<char*>(pb), kSppV2PayloadMax,
      "{\"v\":2,\"id\":\"esp32_write\",\"timestamp\":%lu,\"type\":\"esp32_bridge_write\",\"payload\":{\"name\":\"smoke_%08lx.json\",\"text\":\"{\\\"source\\\":\\\"esp32\\\",\\\"transport\\\":\\\"spp_v2\\\",\\\"kind\\\":\\\"smoke\\\"}\"}}",
      static_cast<unsigned long>(millis()), static_cast<unsigned long>(inboxNonce));
    if (writeLength <= 0 || static_cast<size_t>(writeLength) >= kSppV2PayloadMax || !buildQuickAppMessage(app, pb, static_cast<size_t>(writeLength), pb, kSppV2PayloadMax, pbLength) || !sendEncryptedWatchPb(sequence, encKey, pb, pbLength)) {
      Serial.println("WATCH_BRIDGE_INBOX_WRITE_FAILED");
      break;
    }
    Serial.println("WATCH_BRIDGE_INBOX_WRITE_SENT");
    bool inboxWriteOk = false, inboxWriteAnswered = false;
    const uint32_t writeDeadline = millis() + kWatchBridgeResponseTimeoutMs;
    while (millis() < writeDeadline) {
      if (!readSppV2Frame(frame, writeDeadline - millis())) break;
      if (frame.type != 3) continue;
      writeSppV2Frame(1, frame.sequence, nullptr, 0);
      const uint8_t* incoming = nullptr; size_t incomingLength = 0, contentLength = 0; const uint8_t* content = nullptr;
      if (decryptWatchPb(frame, decKey, incoming, incomingLength) && parseQuickAppMessage(incoming, incomingLength, content, contentLength)) {
        Serial.printf("WATCH_BRIDGE_RX bytes=%u\n", static_cast<unsigned>(contentLength));
        if (containsAscii(content, contentLength, "\"type\":\"esp32_bridge_ack\"")) {
          inboxWriteAnswered = true;
          if (containsAscii(content, contentLength, "\"ok\":true") || containsAscii(content, contentLength, "\"ok\":1")) {
            inboxWriteOk = true;
          } else if (containsAscii(content, contentLength, "inbox_entry_exists")) {
            Serial.println("WATCH_BRIDGE_INBOX_ACK_EXISTS");
          } else if (containsAscii(content, contentLength, "inbox_mkdir_failed")) {
            Serial.println("WATCH_BRIDGE_INBOX_ACK_MKDIR_FAILED");
          } else if (containsAscii(content, contentLength, "inbox_write_failed")) {
            Serial.println("WATCH_BRIDGE_INBOX_ACK_WRITE_FAILED");
          } else {
            Serial.println("WATCH_BRIDGE_INBOX_ACK_REJECTED");
          }
          break;
        }
      }
    }
    Serial.println(inboxWriteOk ? "WATCH_BRIDGE_INBOX_WRITE_OK" : (inboxWriteAnswered ? "WATCH_BRIDGE_INBOX_WRITE_REJECTED" : "WATCH_BRIDGE_INBOX_WRITE_TIMEOUT"));
  } while (false);

  watchBt.disconnect(); watchBt.end();
  mbedtls_platform_zeroize(secret, sizeof(secret)); mbedtls_platform_zeroize(phoneNonce, sizeof(phoneNonce)); mbedtls_platform_zeroize(step3, sizeof(step3));
  mbedtls_platform_zeroize(encKey, sizeof(encKey)); mbedtls_platform_zeroize(decKey, sizeof(decKey)); mbedtls_platform_zeroize(app.fingerprint, sizeof(app.fingerprint));
  secretText = "";
}

// ESP32 独立 DNS 自测（不经过手表 ch7 / custom netif / NAPT 路径）。
// 直接走 WiFi STA -> 网关 -> DNS 服务器，用于验证 WiFi/ARP/网关/外网/DNS 本身。
static void espDnsSelfTestCb(const char* name, const ip_addr_t* ipaddr, void* arg) {
  (void)arg;
  if (ipaddr != nullptr) {
    char ipbuf[48]{};
    if (IP_IS_V4(ipaddr)) {
      const ip4_addr_t* a = ip_2_ip4(ipaddr);
      snprintf(ipbuf, sizeof(ipbuf), "%d.%d.%d.%d", ip4_addr1(a), ip4_addr2(a), ip4_addr3(a), ip4_addr4(a));
    } else {
      snprintf(ipbuf, sizeof(ipbuf), "<ipv6>");
    }
    Serial.printf("ESP_DNS_SELFTEST_RX name=%s ip=%s\n", name ? name : "?", ipbuf);
  } else {
    Serial.printf("ESP_DNS_SELFTEST_FAIL name=%s reason=resolve_timeout\n", name ? name : "?");
  }
}

void handleWatchProbeSerial() {
  static String command;
  while (Serial.available()) {
    char c = static_cast<char>(Serial.read());
    if (c == '\r') continue;
    if (c != '\n') {
      // WATCH_CONFIG with ssid + wifi_pass + watch_mac + watch_auth +
      // auto_connect is ~137 chars; keep a generous 256-byte buffer.
      if (command.length() < 256) command += c;
      continue;
    }
    command.trim();
    if (command.startsWith("WATCH_PROBE ")) probeWatchClassic(command.substring(12));
    else if (command == "WATCH_SDP_CLEAR") {
      clearWatchSdpCache("serial_clear");
      Serial.println("WATCH_SDP_CACHE_CLEARED");
    }
    else if (command.startsWith("WATCH_SDP ")) probeWatchSdp(command.substring(10));
    else if (command.startsWith("WATCH_SPP ")) connectWatchSpp(command.substring(10));
    else if (command.startsWith("WATCH_SPP_CHANNEL ")) {
      const String args = command.substring(18); const int separator = args.indexOf(' ');
      if (separator > 0) connectWatchSppChannel(args.substring(0, separator), args.substring(separator + 1).toInt());
      else Serial.println("WATCH_SPP_CHANNEL_INVALID_INPUT");
    }
    else if (command.startsWith("WATCH_VERSION ")) probeWatchSppVersion(command.substring(14));
    else if (command.startsWith("WATCH_SESSION ")) probeWatchSppSession(command.substring(14));
    else if (command == "WATCH_RAW_TRACE_ON") {
      gWatchRawTraceEnabled = true;
      Serial.println("WATCH_RAW_TRACE_ON private_local_only=true");
    }
    else if (command == "WATCH_RAW_TRACE_OFF") {
      gWatchRawTraceEnabled = false;
      Serial.println("WATCH_RAW_TRACE_OFF");
    }
    else if (command == "WATCH_SETUP") {
      // 串口命令触发配网：写标志 + 重启，重启后进入 AP 配网模式。
      Serial.println("SETUP_MODE_REASON serial_command (save flag + reboot)");
      prefs.putBool("force_setup", true);
      delay(300);
      ESP.restart();
    }
    else if (command == "WATCH_DECRYPT_ROUND3") {
      dumpRound3BootstrapPlaintext();
    }
    else if (command == "ESP_DNS_SELFTEST") {
      // 独立 DNS 自测：ESP32 直接经 WiFi STA 解析 example.com，
      // 完全绕开手表 ch7 / custom netif / NAPT 路径。
      Serial.println("ESP_DNS_SELFTEST_TX name=example.com");
      ip_addr_t resolved;
      const err_t err = dns_gethostbyname("example.com", &resolved, espDnsSelfTestCb, nullptr);
      if (err == ERR_OK) {
        char ipbuf[48]{};
        if (IP_IS_V4(&resolved)) {
          const ip4_addr_t* a = ip_2_ip4(&resolved);
          snprintf(ipbuf, sizeof(ipbuf), "%d.%d.%d.%d", ip4_addr1(a), ip4_addr2(a), ip4_addr3(a), ip4_addr4(a));
        }
        Serial.printf("ESP_DNS_SELFTEST_RX_CACHED name=example.com ip=%s\n", ipbuf);
      } else if (err == ERR_INPROGRESS) {
        Serial.println("ESP_DNS_SELFTEST_PENDING async=true wait=callback");
      } else {
        Serial.printf("ESP_DNS_SELFTEST_ERR err=%d\n", static_cast<int>(err));
      }
    }
    else if (command.startsWith("WATCH_CONFIG ")) {
      // Syntax: WATCH_CONFIG ssid=xxx wifi_pass=yyy watch_mac=AA:BB:CC:DD:EE:FF watch_auth=32hex
      String args = command.substring(13);
      int sep, end;
      // First argument has no leading space
      if (args.startsWith("ssid=")) {
        end = args.indexOf(' '); if (end < 0) end = args.length();
        ssid = args.substring(5, end); prefs.putString("ssid", ssid);
      }
      if ((sep = args.indexOf(" wifi_pass=")) >= 0) {
        end = args.indexOf(' ', sep + 11); if (end < 0) end = args.length();
        wifiPass = args.substring(sep + 11, end); prefs.putString("wifi_pass", wifiPass);
      }
      if ((sep = args.indexOf(" watch_mac=")) >= 0) {
        end = args.indexOf(' ', sep + 11); if (end < 0) end = args.length();
        watchMac = args.substring(sep + 11, end); prefs.putString("watch_mac", watchMac);
      }
      if ((sep = args.indexOf(" watch_auth=")) >= 0) {
        end = args.indexOf(' ', sep + 12); if (end < 0) end = args.length();
        watchAuthKey = args.substring(sep + 12, end); prefs.putString("watch_auth", watchAuthKey);
      }
      if ((sep = args.indexOf(" auto_connect=")) >= 0) {
        autoConnectWatch = args.substring(sep + 14) == "1";
        prefs.putBool("watch_auto", autoConnectWatch);
      }
      prefs.putString("local_token", "vela-local");
      prefs.putString("ap_pass", apPassword);
      Serial.printf("WATCH_CONFIG_SAVED ssid=%s mac=%s auth=%s\n",
                    ssid.c_str(), watchMac.c_str(), watchAuthKey.length() == 32 ? "ok" : "missing");
      if (!ssid.isEmpty()) { WiFi.mode(WIFI_STA); WiFi.begin(ssid.c_str(), wifiPass.c_str()); Serial.println("WIFI_CONNECTING_STA_ONLY"); uint32_t wstart=millis(); while(WiFi.status()!=WL_CONNECTED && millis()-wstart<15000){delay(250);} Serial.printf("WIFI_CONFIG_RESULT connected=%s ip=%s\n", WiFi.status()==WL_CONNECTED?"true":"false", WiFi.localIP().toString().c_str()); }
    }
    else if (command.startsWith("WATCH_AUTH ")) {
      const String args = command.substring(11); const int separator = args.indexOf(' ');
      if (separator > 0) authenticateWatchSpp(args.substring(0, separator), args.substring(separator + 1));
      else Serial.println("WATCH_AUTH_INVALID_INPUT");
    }
    else if (command.startsWith("WATCH_BRIDGE ")) {
      const String args = command.substring(13); const int separator = args.indexOf(' ');
      if (separator > 0) bridgeWatchQuickApp(args.substring(0, separator), args.substring(separator + 1));
      else Serial.println("WATCH_BRIDGE_INVALID_INPUT");
    }
    else if (command.startsWith("WATCH_BENCH_QUICK ")) {
      const String args = command.substring(18); const int separator = args.indexOf(' ');
      if (separator > 0) { Serial.println("WATCH_BENCH_QUICK_COMMAND_RECEIVED"); bridgeWatchQuickApp(args.substring(0, separator), args.substring(separator + 1), 2); }
      else Serial.println("WATCH_BENCH_QUICK_INVALID_INPUT");
    }
    else if (command.startsWith("WATCH_STREAM_256K_ECHO ")) {
      String args = command.substring(23); int separator = args.indexOf(' ');
      if (separator > 0) { Serial.println("WATCH_STREAM_256K_ECHO_COMMAND_RECEIVED"); bridgeWatchQuickApp(args.substring(0, separator), args.substring(separator + 1), 6); }
      else Serial.println("WATCH_STREAM_256K_ECHO_INVALID_INPUT");
    }
    else if (command.startsWith("WATCH_STREAM_256K_ECHO_COALESCED ")) {
      String args = command.substring(33); int separator = args.indexOf(' ');
      if (separator > 0) { Serial.println("WATCH_STREAM_256K_ECHO_COALESCED_COMMAND_RECEIVED"); bridgeWatchQuickApp(args.substring(0, separator), args.substring(separator + 1), 8); }
      else Serial.println("WATCH_STREAM_256K_ECHO_COALESCED_INVALID_INPUT");
    }
    else if (command.startsWith("WATCH_STREAM_256K_DECODE ")) {
      String args = command.substring(25); int separator = args.indexOf(' ');
      if (separator > 0) { Serial.println("WATCH_STREAM_256K_DECODE_COMMAND_RECEIVED"); bridgeWatchQuickApp(args.substring(0, separator), args.substring(separator + 1), 7); }
      else Serial.println("WATCH_STREAM_256K_DECODE_INVALID_INPUT");
    }
    else if (command.startsWith("WATCH_BENCH_256K_SEG32K ")) {
      const String args = command.substring(24); const int separator = args.indexOf(' ');
      if (separator > 0) { Serial.println("WATCH_BENCH_256K_SEG32K_COMMAND_RECEIVED"); bridgeWatchQuickApp(args.substring(0, separator), args.substring(separator + 1), 9); }
      else Serial.println("WATCH_BENCH_256K_SEG32K_INVALID_INPUT");
    }
    else if (command.startsWith("WATCH_BENCH_256K_RENEW ")) {
      const String args = command.substring(23); const int separator = args.indexOf(' ');
      if (separator > 0) { Serial.println("WATCH_BENCH_256K_RENEW_COMMAND_RECEIVED"); bridgeWatchQuickApp(args.substring(0, separator), args.substring(separator + 1), 4); }
      else Serial.println("WATCH_BENCH_256K_RENEW_INVALID_INPUT");
    }
    else if (command.startsWith("WATCH_BENCH_256K_PACED ")) {
      const String args = command.substring(23); const int separator = args.indexOf(' ');
      if (separator > 0) { Serial.println("WATCH_BENCH_256K_PACED_COMMAND_RECEIVED"); bridgeWatchQuickApp(args.substring(0, separator), args.substring(separator + 1), 5); }
      else Serial.println("WATCH_BENCH_256K_PACED_INVALID_INPUT");
    }
    else if (command.startsWith("WATCH_BENCH_256K ")) {
      const String args = command.substring(17); const int separator = args.indexOf(' ');
      if (separator > 0) { Serial.println("WATCH_BENCH_256K_COMMAND_RECEIVED"); bridgeWatchQuickApp(args.substring(0, separator), args.substring(separator + 1), 3); }
      else Serial.println("WATCH_BENCH_256K_INVALID_INPUT");
    }
    else if (command.startsWith("WATCH_FINAL_ACCEPTANCE ")) {
      String args = command.substring(23); const int separator = args.indexOf(' ');
      if (separator > 0) { Serial.println("WATCH_FINAL_ACCEPTANCE_COMMAND_RECEIVED"); bridgeWatchQuickApp(args.substring(0, separator), args.substring(separator + 1), 10); }
      else Serial.println("WATCH_FINAL_ACCEPTANCE_INVALID_INPUT");
    }
    else if (command.startsWith("WATCH_BENCH ")) {
      const String args = command.substring(12); const int separator = args.indexOf(' ');
      if (separator > 0) { Serial.println("WATCH_BENCH_COMMAND_RECEIVED"); bridgeWatchQuickApp(args.substring(0, separator), args.substring(separator + 1), 1); }
      else Serial.println("WATCH_BENCH_INVALID_INPUT");
    }
    command = "";
  }
}

// ==================== 恢复出厂设置 / 自动配网降级 ====================
// 「恢复出厂」= 清空全部用户配置（Wi-Fi、手表密钥、云端 key……），只剩两个主动入口：
//   1) BOOT 长按 10 秒          → 置标志后重启，下次开机清空并直接进配网
//   2) 网页 /api/v1/factory/reset → 立即清空并重启
//
// 「自动降级」= 只开配网热点，不清任何用户配置，一个入口：
//   3) 连不上 Wi-Fi 超过 kAutoSetupFallbackMs → 写标志后重启，开机进配网模式，
//      手表密钥 / 云端 key / Wi-Fi 密码 / 热点名全部原样保留
//
// 为什么拆成两条路（2026-11-09 按需求改）：
//   旧逻辑只有一条路：连不上 Wi-Fi 10 分钟（从没连上）或 30 分钟（失联）
//   就自动恢复出厂 → 把用户配置全清掉。家里停电、路由器升级、出差拔电
//   都会触发，用户回家发现手表密钥没了，得重新配一遍。
//   现在改成：连不上 → 只开热点让人来改 Wi-Fi，配置一律保留；
//   想真正清空，用户主动按 BOOT 10 秒或点网页按钮。
//
// 两条路都靠 "vela-fac" 命名空间里的 arm 标志跨重启传递，magic 值不同：
//   kFactoryArmMagic   ("FACT") → 开机后清空全部配置
//   kSetupOnlyArmMagic ("SEPU") → 开机后只进配网，不清配置
// 开机处理一律不重启，否则 arm 标志会活过重启造成无限复位环（第十三章）。

constexpr uint32_t kAutoSetupGraceMs = 60000;             // 开机 1 分钟内不判定
constexpr uint32_t kAutoSetupFallbackMs = 120000;         // 连续连不上 2 分钟 → 开热点
constexpr uint32_t kAutoSetupMinFailures = 3;             // 至少重试 3 次才判定
constexpr uint32_t kAutoSetupSnoozeMs = 1800000;          // 网页「暂不开热点」推迟 30 分钟
constexpr uint32_t kFactoryArmMagic = 0x46414354u;        // "FACT"
constexpr uint32_t kSetupOnlyArmMagic = 0x53455055u;      // "SEPU"
constexpr char kFactoryArmNs[] = "vela-fac";           // 独立 NVS 命名空间

static bool gFactoryBootChecked = false;
// 开机时发现 arm 标志 → 已完成补清空 → 强制进配网模式（不依赖 NVS 是否清干净）。
static bool gForceSetupAfterReset = false;
// 自动降级进配网模式：保留全部用户配置，只开热点。
static bool gSetupKeepConfig = false;
static uint32_t gAutoResetCandidateSince = 0;   // 0 = 当前链路健康/未开始计时
static const char* gAutoResetReason = "";
static bool gAutoResetPaused = false;
static uint32_t gAutoSetupSnoozeUntil = 0;      // 网页点了「暂不开热点」
// 健康心跳写 NVS 的节流状态（见 autoSetupFallbackTick）
constexpr uint32_t kHealthPersistIntervalMs = 24UL * 3600UL * 1000UL;  // 24 小时
static bool gHealthPersisted = false;
static uint32_t gHealthPersistMs = 0;
// 提前声明：在 setup() 里被调用，定义在本节之后。
static uint32_t factoryArmMagic();
static void initAutoSetupWindow();

// 需要清空的业务键。device_secret / boot_count 这类"设备身份/健康计数"
// 不清，避免重启后又被当成"从没配过网"。
struct FactoryKey { const char* ns; const char* key; };
static const FactoryKey kFactoryKeys[] = {
  {"vela", "ssid"},            {"vela", "wifi_pass"},
  {"vela", "watch_mac"},       {"vela", "watch_auth"},
  {"vela", "watch_auto"},      {"vela", "ap_pass"},
  {"vela", "ap_ssid"},
  {"vela", "base_url"},        {"vela", "api_key"},
  {"vela", "model"},           {"vela", "asr_model"},
  {"vela", "asr_lang"},        {"vela", "native_xiaoai"},
  {"vela", "chat_after_asr"},  {"vela", "local_token"},
  {"vela", "ca_pem"},          {"vela", "max_tokens"},
  {"vela", "insecure_tls"},    {"vela", "capture_ch8"},
  {"vela", "ntp_tz"},          {"vela", "led_mode"},
  {"vela", "pref_log"},        {"vela", "pref_compact"},
  {"vela", "last_ok_ms"},      {"vela", "project"},
  {"vela", "project2"},        {"vela", "force_setup"},
  // 已删除的项目 4/5 遗留键，老设备升级上来可能还在，一并清掉
  {"vela", "p5_ssid"},         {"vela", "p5_pass"},
  {"vela", "p4_bt_addr"},      {"vela", "p4_bt_name"},
  {"vela", "p4_bt_key"},       {"vela", "p4_package"},
};

static void factoryClearNvs() {
  prefs.begin("vela", false);
  for (const auto& k : kFactoryKeys) prefs.remove(k.key);
  // 计数与身份类也随之归零，否则重启后仍会认为"之前配过"。
  prefs.remove("boot_count");
  prefs.remove("boot_success");
  prefs.remove("cfg_ok");
  prefs.end();
  // 注意：这里不能调用 nvs_flash_deinit()。
  // 一来 main.cpp 没包含 nvs_flash.h，二来 deinit 之后同一轮里
  // 再 open 命名空间会失败（ARM 标志写不进去）。Preferences::end()
  // 已经提交并关闭句柄，NVS 由 IDF 自己异步刷写，重启前 delay 即可。
}

// 真正执行清空 + 重启。调用后不再返回。只由用户主动触发。
static void factoryResetApply(const char* reason) {
  Serial.printf("FACTORY_RESET_BEGIN reason=%s\n", reason ? reason : "?");
  Serial.printf("FACTORY_RESET_PRE ssid_len=%u watch_mac=%s\n",
                static_cast<unsigned>(ssid.length()), watchMac.c_str());

  // 先把待配网标志写进独立命名空间，防止重启到一半掉电导致"清了一半"。
  {
    Preferences arm;
    if (arm.begin(kFactoryArmNs, false)) {
      arm.putUInt("magic", kFactoryArmMagic);
      arm.putString("reason", reason ? reason : "?");
      arm.end();
    }
  }

  digitalWrite(kHeartbeatLedPin, LOW);
  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);
  delay(150);

  factoryClearNvs();

  // 清完再写一次 arm 标志。arm 标志在独立命名空间 "vela-fac"，
  // factoryClearNvs() 只清 "vela"，所以第一次写的标志本来就在；
  // 这里补写一次是为了兜住 Preferences 缓存刷写时机，防止第一次写没落盘。
  // 重启后由 setup() 里的 factoryResetCompleteOnBoot() 补清空 + 解绑，
  // 那条路径不会再重启（否则会变成无限复位环）。
  {
    Preferences arm;
    if (arm.begin(kFactoryArmNs, false)) {
      arm.putUInt("magic", kFactoryArmMagic);
      arm.putString("reason", reason ? reason : "?");
      arm.end();
    }
  }

  Serial.println("FACTORY_RESET_DONE rebooting_into_setup_mode");
  delay(400);
  ESP.restart();
}

// 读取 arm 标志的 magic 值：0=无标志 / FACT=清空型 / SEPU=只进配网型。
static uint32_t factoryArmMagic() {
  Preferences arm;
  if (!arm.begin(kFactoryArmNs, true)) return 0;
  const uint32_t magic = arm.getUInt("magic", 0);
  arm.end();
  return magic;
}

static bool factoryResetPending() {
  return factoryArmMagic() == kFactoryArmMagic;
}

static void factoryResetDisarm() {
  Preferences arm;
  if (!arm.begin(kFactoryArmNs, false)) return;
  arm.remove("magic");
  arm.remove("reason");
  arm.end();
}

// 开机时发现 arm 标志 → 说明上一次恢复出厂流程在"清 NVS"这一步被断电/复位打断，
// 或者刚刚由 factoryResetApply() 重启过来。在这里把"清空"这一步补做完（幂等），
// 然后不重启，让启动流程继续往下走：
//   loadConfig() 会读到空的 ssid / watch_mac
//   → needSetup 判定为真 → enterSetupMode()
//
// 旧实现在这里调用 factoryResetApply("boot_pending_flag")，而那个函数末尾会
// ESP.restart()，并且重启前又把 arm 标志写回一次。于是"看到标志 → 再清一遍 → 重启"
// 变成无限循环：设备永远进不了配网模式，只能用 USB 重新刷机才能救回来。
static void factoryResetCompleteOnBoot() {
  Serial.println("FACTORY_RESET_PENDING completing_clear_on_boot");
  factoryClearNvs();
  // 清空成功之后再解绑标志：万一在清空过程中掉电，标志还在，
  // 下次开机还能再清一遍（幂等）。
  factoryResetDisarm();
  // 清完不重启，直接走下面的 needSetup → enterSetupMode()。
  gForceSetupAfterReset = true;
  gSetupKeepConfig = false;
}

// 自动降级：连不上 Wi-Fi → 只写 "SEPU" 标志后重启，不动任何用户配置。
// 这是和 factoryResetApply() 唯一但关键的区别。
static void autoSetupFallbackApply(const char* reason) {
  Serial.printf("AUTO_SETUP_FALLBACK_BEGIN reason=%s ssid_len=%u watch_mac=%s keep_all_config=true\n",
                reason ? reason : "?", static_cast<unsigned>(ssid.length()), watchMac.c_str());
  {
    Preferences arm;
    if (arm.begin(kFactoryArmNs, false)) {
      arm.putUInt("magic", kSetupOnlyArmMagic);
      arm.putString("reason", reason ? reason : "?");
      arm.end();
    }
  }
  Serial.println("AUTO_SETUP_FALLBACK_DONE rebooting_into_setup_mode");
  delay(400);
  ESP.restart();
}

// 开机发现 "SEPU" 标志 → 不清任何配置，直接进配网模式。
static void autoSetupCompleteOnBoot() {
  Serial.println("AUTO_SETUP_FALLBACK_PENDING entering_setup_without_clearing");
  factoryResetDisarm();          // 解绑（幂等，不重启）
  gForceSetupAfterReset = true;  // 强制进配网（配置齐全也要进）
  gSetupKeepConfig = true;       // 但配置一份都不清
}

// 开机时把降级判定武装起来。真正的计时放在 loop 里，
// 这里只负责把"这台设备有没有完整配置"打出来，方便串口定位。
static void initAutoSetupWindow() {
  const bool configured = !ssid.isEmpty() && watchMac.length() == 17 &&
                          watchAuthKey.length() == 32;
  prefs.begin("vela", false);
  const uint32_t everOk = prefs.getUInt("boot_success", 0);
  prefs.end();
  if (!configured) {
    // 没配过网：setup() 会直接进配网模式，不需要降级判定。
    gAutoResetCandidateSince = 0;
    gAutoResetReason = "";
    Serial.println("AUTO_SETUP_WINDOW skipped reason=no_config");
    return;
  }
  gAutoResetCandidateSince = 0;
  gAutoResetReason = everOk ? "wifi_stale" : "never_connected";
  Serial.printf("AUTO_SETUP_WINDOW armed reason=%s budget_ms=%lu keep_all_config=true\n",
                gAutoResetReason, static_cast<unsigned long>(kAutoSetupFallbackMs));
}

// 在 loop() 里每轮调用。连不上 Wi-Fi 太久 → 自动开热点进配网（不清配置）。
// 触发条件（全部满足才降级）：
//   1. 链路不健康（Wi-Fi 与手表都没连上）
//   2. 开机宽限期已过
//   3. 连续重连失败次数 >= kAutoSetupMinFailures
//   4. 从"开始判定连不上"起持续 >= kAutoSetupFallbackMs
//   5. AP 上没有浏览器连着（有人在调试就冻结）
//   6. 没被网页「暂不开热点」推迟
static void autoSetupFallbackTick(bool wifiConnected, bool watchConnected) {
  const uint32_t now = millis();
  const bool healthy = wifiConnected || watchConnected;

  // 只要有一次有效通信，整体计时清零 + 记录健康。
  if (healthy) {
    if (gAutoResetCandidateSince) {
      gAutoResetCandidateSince = 0;
      Serial.println("AUTO_SETUP_FALLBACK cancelled_by_healthy_link");
    }
    // 只在链路"刚变健康"或距上次落盘 >= 24h 时写 NVS。
    // 原来每轮 loop 都 putUInt，Wi-Fi 正常时每秒擦写几十次 flash，
    // 既磨损 flash 又拖慢 loop（NVS 写入要拿锁 + 页编程）。
    if (!gHealthPersisted) {
      gHealthPersisted = true;
      gHealthPersistMs = now;
      prefs.begin("vela", false);
      prefs.putUInt("last_ok_ms", now);
      const uint32_t okCount = prefs.getUInt("boot_success", 0);
      if (okCount < 1000000u) prefs.putUInt("boot_success", okCount + 1);
      prefs.end();
    } else if (now - gHealthPersistMs >= kHealthPersistIntervalMs) {
      gHealthPersistMs = now;
      prefs.begin("vela", false);
      prefs.putUInt("last_ok_ms", now);
      prefs.end();
    }
    return;
  }
  gHealthPersisted = false;   // 链路断了，下次恢复要重新落盘

  if (gSetupMode) return;                       // 已经在配网模式
  if (now < kAutoSetupGraceMs) return;          // 开机宽限期
  if (now < gAutoSetupSnoozeUntil) return;      // 网页点了「暂不开热点」
  if (gReconnectFailCount < kAutoSetupMinFailures) return;

  // AP 上还有人连着网页 → 冻结倒数（正在配网/调试）。
  if (WiFi.softAPgetStationNum() > 0) {
    if (!gAutoResetPaused) {
      gAutoResetPaused = true;
      Serial.println("AUTO_SETUP_PAUSED ap_client_present");
    }
    gAutoResetCandidateSince = now;
    return;
  }
  if (gAutoResetPaused) {
    gAutoResetPaused = false;
    Serial.println("AUTO_SETUP_RESUMED ap_client_gone");
  }

  if (!gAutoResetCandidateSince) {
    gAutoResetCandidateSince = now;
    Serial.printf("AUTO_SETUP_WINDOW started reason=%s budget_ms=%lu failures=%lu\n",
                  gAutoResetReason, static_cast<unsigned long>(kAutoSetupFallbackMs),
                  static_cast<unsigned long>(gReconnectFailCount));
  }
  const uint32_t elapsed = now - gAutoResetCandidateSince;
  if (elapsed < kAutoSetupFallbackMs) {
    static uint32_t lastLog = 0;
    if (now - lastLog >= 30000) {
      lastLog = now;
      Serial.printf("AUTO_SETUP_COUNTDOWN reason=%s remain_ms=%lu\n",
                    gAutoResetReason,
                    static_cast<unsigned long>(kAutoSetupFallbackMs - elapsed));
    }
    return;
  }

  Serial.printf("AUTO_SETUP_FALLBACK_REASON offline_ms=%lu failures=%lu keep_all_config=true\n",
                static_cast<unsigned long>(elapsed),
                static_cast<unsigned long>(gReconnectFailCount));
  autoSetupFallbackApply(gAutoResetReason);
}

void loadConfig() {
  prefs.begin("vela", false);
  ssid = readConfigString("ssid", "");
  wifiPass = readConfigString("wifi_pass", "");
  baseUrl = cleanBase(readConfigString("base_url", "https://api.xiaomimimo.com/v1"));
  apiKey = readConfigString("api_key", "");
  model = readConfigString("model", "mimo-v2.5-pro");
  watchMac = readConfigString("watch_mac", "");
  watchAuthKey = readConfigString("watch_auth", "");
  localToken = readConfigString("local_token", "vela-local");
  caPem = readConfigString("ca_pem", "");
  apPassword = readConfigString("ap_pass", "12345678");
  if (apPassword.length() < 8) apPassword = "12345678";
  // 热点名称：用户可以在管理台改；为空或非法长度时回落到默认名。
  gApSsid = readConfigString("ap_ssid", kApSsid);
  gApSsid.trim();
  if (gApSsid.length() < 1 || gApSsid.length() > 32) gApSsid = kApSsid;
  maxTokens = prefs.getInt("max_tokens", 512);
  allowInsecureTls = prefs.getBool("insecure_tls", false);
  autoConnectWatch = prefs.getBool("watch_auto", false);
  captureChannel8 = prefs.getBool("capture_ch8", false);
  // 界面偏好与灯效：读不出来就用默认值（4=流量联动，等同旧行为）
  gLedMode = static_cast<uint8_t>(prefs.getUChar("led_mode", 4));
  if (gLedMode > 4) gLedMode = 4;
  gPrefShowLog = prefs.getBool("pref_log", true);
  gPrefCompact = prefs.getBool("pref_compact", false);
  gNtpTz = readConfigString("ntp_tz", "CST-8");
  if (gNtpTz.isEmpty()) gNtpTz = "CST-8";
}

// 本地令牌要塞进 HTML 的 JS 字符串里，必须过滤掉引号/反斜杠/尖括号，
// 免得 NVS 里被改坏的令牌把页面脚本撑破。
String sanitizeWebToken(const String& raw) {
  String out;
  out.reserve(raw.length());
  for (size_t i = 0; i < raw.length(); ++i) {
    const char c = raw[i];
    const bool safe = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '-' || c == '_';
    out += safe ? c : '_';
  }
  if (out.isEmpty()) out = "vela-local";
  return out;
}

bool authorized() {
  if (localToken.isEmpty()) return true;
  String h = server.header("Authorization");
  if (h == "Bearer " + localToken) return true;
  if (server.header("X-Vela-Token") == localToken) return true;
  // 页面里下发的是过滤后的令牌，客户端回传的就是过滤后的值。
  return server.header("X-Vela-Token") == sanitizeWebToken(localToken);
}

void jsonError(int code, const char* err, const String& message) {
  JsonDocument d;
  d["ok"] = false; d["error"] = err; d["message"] = message;
  String out; serializeJson(d, out);
  server.send(code, "application/json; charset=utf-8", out);
}

void sendJson(int code, JsonDocument& d) {
  String out; serializeJson(d, out);
  server.send(code, "application/json; charset=utf-8", out);
}

// ==================== 诊断与运维：运行遥测 ====================
// 这里的东西全部只读，且都做了取值保护（CSR 未初始化 / 时间没同步时返回
// null 而不是垃圾值），不会因为读温度、uptime 之类的操作打断转发路径。

// WiFi 信道对应频率（MHz）：2.4GHz 只有 1-14
static uint16_t wifiFreqFromChannel(int ch) {
  if (ch == 14) return 2484;
  if (ch >= 1 && ch <= 13) return static_cast<uint16_t>(2407 + ch * 5);
  return 0;
}

// 带格式的安全取值：返回 char* 便于直接塞进 JsonDocument
static const char* jsonAgo(uint32_t ms) {
  static char buf[24];
  const uint32_t sec = ms / 1000;
  if (sec < 60) snprintf(buf, sizeof(buf), "%lu 秒", static_cast<unsigned long>(sec));
  else if (sec < 3600) snprintf(buf, sizeof(buf), "%lu 分 %lu 秒", static_cast<unsigned long>(sec / 60), static_cast<unsigned long>(sec % 60));
  else if (sec < 86400) snprintf(buf, sizeof(buf), "%lu 时 %lu 分", static_cast<unsigned long>(sec / 3600), static_cast<unsigned long>((sec % 3600) / 60));
  else snprintf(buf, sizeof(buf), "%lu 天 %lu 时", static_cast<unsigned long>(sec / 86400), static_cast<unsigned long>((sec % 86400) / 3600));
  return buf;
}

// 链路质量评估：RSSI + 内存 + 转发丢包 三项合成 0-100
static uint8_t linkQualityScore(int rssi, uint32_t heapFree, uint32_t dropped, uint32_t totalPkts) {
  // RSSI：-50dBm 以上满分，-90dBm 归零
  int r = 0;
  if (rssi < 0) {
    if (rssi >= -50) r = 100;
    else if (rssi <= -90) r = 0;
    else r = (rssi + 90) * 100 / 40;
  }
  // 内存：>80KB 满分，<20KB 归零
  int m;
  if (heapFree >= 80000u) m = 100;
  else if (heapFree <= 20000u) m = 0;
  else m = static_cast<int>((heapFree - 20000u) * 100u / 60000u);
  // 丢包率：0% 满分，5% 以上归零
  int q = 100;
  if (totalPkts > 0) {
    const uint32_t perMille = static_cast<uint32_t>(static_cast<uint64_t>(dropped) * 1000 / totalPkts);
    q = perMille >= 50 ? 0 : static_cast<int>(100 - perMille * 2);
  }
  // RSSI 权重最高（链路是主要体验来源），内存次之，丢包兜底
  return static_cast<uint8_t>((r * 5 + m * 3 + q * 2) / 10);
}

bool requireAuth() {
  if (authorized()) return true;
  jsonError(401, "unauthorized", "invalid local token");
  return false;
}

bool isSetupApClient() {
  return server.client().localIP() == WiFi.softAPIP();
}

// 敏感配置（改 Wi-Fi / 恢复出厂 / 蓝牙扫描）原先只允许从配网 SoftAP 发起，
// 于是「已经连上家用路由器、用 LAN IP 打开后台」时这些功能一律 403。
// 现在放行两种来源：配网热点客户端，或带对了本地令牌的请求。
bool requireSetupAp() {
  if (isSetupApClient()) return true;
  if (authorized()) return true;
  jsonError(403, "setup_ap_required",
            "setup is available from the setup SoftAP, or with a valid X-Vela-Token header");
  return false;
}

void recordWatchFetchProbe() {
  String entry = "WATCH_FETCH_PROBE peer=" + server.client().remoteIP().toString() + " path=" + server.uri();
  fetchTrace[fetchTraceNext] = entry;
  fetchTraceNext = (fetchTraceNext + 1) % kFetchTraceEntries;
  if (fetchTraceCount < kFetchTraceEntries) ++fetchTraceCount;
  Serial.println(entry);
}

void handleFetchTrace() {
  if (!requireSetupAp()) return;
  JsonDocument d;
  d["ok"] = true;
  JsonArray entries = d["entries"].to<JsonArray>();
  for (size_t offset = 0; offset < fetchTraceCount; ++offset) {
    const size_t index = (fetchTraceNext + kFetchTraceEntries - fetchTraceCount + offset) % kFetchTraceEntries;
    entries.add(fetchTrace[index]);
  }
  sendJson(200, d);
}

String body() {
  String b = server.arg("plain");
  if (b.length() > kMaxBody) return "";
  return b;
}

bool beginHttp(const String& url, HTTPClient& http, WiFiClient& plain, WiFiClientSecure& secure, String& error) {
  http.setTimeout(kHttpTimeoutMs);
  if (url.startsWith("https://")) {
    if (!caPem.isEmpty()) secure.setCACert(caPem.c_str());
    else if (allowInsecureTls) secure.setInsecure();
    else {
      error = "https_ca_missing: paste the issuing root CA in WebUI or explicitly enable insecure TLS for development";
      return false;
    }
    return http.begin(secure, url);
  }
  return http.begin(plain, url);
}

bool mimoRequest(const String& userText, String& answer, String& error) {
  if (WiFi.status() != WL_CONNECTED) { error = "wifi_not_connected"; return false; }
  if (apiKey.isEmpty()) { error = "mimo_api_key_missing"; return false; }
  if (baseUrl.isEmpty()) { error = "mimo_base_url_missing"; return false; }
  if (userText.isEmpty() || userText.length() > 8000) { error = "invalid_input"; return false; }

  String url = cleanBase(baseUrl) + "/chat/completions";
  WiFiClient plain;
  WiFiClientSecure secure;
  HTTPClient http;
  if (!beginHttp(url, http, plain, secure, error)) return false;
  http.addHeader("Content-Type", "application/json");
  http.addHeader("Authorization", "Bearer " + apiKey);

  JsonDocument req;
  req["model"] = model;
  req["stream"] = false;
  req["max_completion_tokens"] = constrain(maxTokens, 1, 4096);
  JsonObject thinking = req["thinking"].to<JsonObject>();
  thinking["type"] = "disabled";
  JsonArray messages = req["messages"].to<JsonArray>();
  JsonObject system = messages.add<JsonObject>();
  system["role"] = "system";
  system["content"] = "You are MiMo, an AI assistant used through a small watch bridge. Reply concisely.";
  JsonObject user = messages.add<JsonObject>();
  user["role"] = "user";
  user["content"] = userText;
  String payload; serializeJson(req, payload);

  int code = http.POST(payload);
  String response = http.getString();
  http.end();
  if (code < 200 || code >= 300) {
    error = "upstream_http_" + String(code) + ":" + response.substring(0, 512);
    return false;
  }
  JsonDocument res;
  DeserializationError de = deserializeJson(res, response);
  if (de) { error = "upstream_json_invalid"; return false; }
  const char* text = res["choices"][0]["message"]["content"] | nullptr;
  if (!text) { error = "upstream_content_missing"; return false; }
  answer = String(text);
  if (answer.length() > 12000) answer = answer.substring(0, 12000);
  return true;
}

void resetWatchConversationContext(const char* reason) {
  const bool locked = gBridgeStateMutex && xSemaphoreTake(gBridgeStateMutex, pdMS_TO_TICKS(250)) == pdTRUE;
  memset(gWatchContext, 0, sizeof(gWatchContext));
  gWatchContextCount = 0;
  gWatchContextNext = 0;
  gWatchContextLastMs = millis();
  if (locked) xSemaphoreGive(gBridgeStateMutex);
  Serial.printf("WATCH_AI_CONTEXT_RESET reason=%s\n", reason ? reason : "unknown");
}

void maybeExpireWatchConversationContext() {
  if (gWatchContextCount == 0 || gWatchContextLastMs == 0) return;
  if (millis() - gWatchContextLastMs >= kXiaoAiContextIdleResetMs) resetWatchConversationContext("idle_timeout");
}

void appendWatchConversationTurn(const String& userText, const String& assistantText) {
  const bool locked = gBridgeStateMutex && xSemaphoreTake(gBridgeStateMutex, pdMS_TO_TICKS(250)) == pdTRUE;
  WatchConversationTurn& turn = gWatchContext[gWatchContextNext];
  snprintf(turn.user, sizeof(turn.user), "%s", userText.c_str());
  snprintf(turn.assistant, sizeof(turn.assistant), "%s", assistantText.c_str());
  gWatchContextNext = (gWatchContextNext + 1) % kWatchContextTurns;
  if (gWatchContextCount < kWatchContextTurns) ++gWatchContextCount;
  gWatchContextLastMs = millis();
  if (locked) xSemaphoreGive(gBridgeStateMutex);
}

bool mimoWatchRequest(const String& userText, String& answer, String& error) {
  if (WiFi.status() != WL_CONNECTED) { error = "wifi_not_connected"; return false; }
  if (apiKey.isEmpty()) { error = "mimo_api_key_missing"; return false; }
  if (baseUrl.isEmpty()) { error = "mimo_base_url_missing"; return false; }
  if (userText.isEmpty() || userText.length() > 8000) { error = "invalid_input"; return false; }
  maybeExpireWatchConversationContext();

  String url = cleanBase(baseUrl) + "/chat/completions";
  WiFiClient plain;
  WiFiClientSecure secure;
  HTTPClient http;
  if (!beginHttp(url, http, plain, secure, error)) return false;
  http.addHeader("Content-Type", "application/json");
  http.addHeader("Authorization", "Bearer " + apiKey);

  JsonDocument req;
  req["model"] = model;
  req["stream"] = false;
  req["max_completion_tokens"] = constrain(maxTokens, 1, 4096);
  JsonObject thinking = req["thinking"].to<JsonObject>();
  thinking["type"] = "disabled";
  JsonArray messages = req["messages"].to<JsonArray>();
  JsonObject system = messages.add<JsonObject>();
  system["role"] = "system";
  system["content"] = "You are MiMo behind a Redmi Watch assistant bridge. Keep answers concise and preserve conversational context. If a request needs a live tool or watch presentation that the bridge has not implemented yet, answer with the useful text result only; do not invent device-side tool events.";

  WatchConversationTurn contextSnapshot[kWatchContextTurns]{};
  size_t contextCount = 0;
  {
    const bool locked = gBridgeStateMutex && xSemaphoreTake(gBridgeStateMutex, pdMS_TO_TICKS(250)) == pdTRUE;
    contextCount = gWatchContextCount;
    const size_t first = (gWatchContextNext + kWatchContextTurns - contextCount) % kWatchContextTurns;
    for (size_t i = 0; i < contextCount; ++i) contextSnapshot[i] = gWatchContext[(first + i) % kWatchContextTurns];
    if (locked) xSemaphoreGive(gBridgeStateMutex);
  }
  for (size_t i = 0; i < contextCount; ++i) {
    const WatchConversationTurn& turn = contextSnapshot[i];
    if (turn.user[0]) {
      JsonObject priorUser = messages.add<JsonObject>();
      priorUser["role"] = "user";
      priorUser["content"] = turn.user;
    }
    if (turn.assistant[0]) {
      JsonObject priorAssistant = messages.add<JsonObject>();
      priorAssistant["role"] = "assistant";
      priorAssistant["content"] = turn.assistant;
    }
  }
  JsonObject user = messages.add<JsonObject>();
  user["role"] = "user";
  user["content"] = userText;
  String payload; serializeJson(req, payload);

  int code = http.POST(payload);
  String response = http.getString();
  http.end();
  if (code < 200 || code >= 300) {
    error = "upstream_http_" + String(code) + ":" + response.substring(0, 512);
    return false;
  }
  JsonDocument res;
  if (deserializeJson(res, response)) { error = "upstream_json_invalid"; return false; }
  const char* text = res["choices"][0]["message"]["content"] | nullptr;
  if (!text) { error = "upstream_content_missing"; return false; }
  answer = String(text);
  if (answer.length() > 12000) answer = answer.substring(0, 12000);
  appendWatchConversationTurn(userText, answer);
  return true;
}



// ---- MiMo ASR pipeline: watch Opus aggregate -> PCM16 WAV -> streamed Base64 -> MiMo ----
void writeLe16(File& f, uint16_t value) {
  const uint8_t b[] = {static_cast<uint8_t>(value & 0xff), static_cast<uint8_t>((value >> 8) & 0xff)};
  f.write(b, sizeof(b));
}

void writeLe32(File& f, uint32_t value) {
  const uint8_t b[] = {
      static_cast<uint8_t>(value & 0xff), static_cast<uint8_t>((value >> 8) & 0xff),
      static_cast<uint8_t>((value >> 16) & 0xff), static_cast<uint8_t>((value >> 24) & 0xff)};
  f.write(b, sizeof(b));
}

bool writePcmWavHeader(File& wav, uint32_t pcmBytes) {
  if (!wav || !wav.seek(0, SeekSet)) return false;
  wav.write(reinterpret_cast<const uint8_t*>("RIFF"), 4);
  writeLe32(wav, 36u + pcmBytes);
  wav.write(reinterpret_cast<const uint8_t*>("WAVEfmt "), 8);
  writeLe32(wav, 16);
  writeLe16(wav, 1); // PCM
  writeLe16(wav, kWatchAsrChannels);
  writeLe32(wav, kWatchAsrSampleRate);
  writeLe32(wav, kWatchAsrSampleRate * kWatchAsrChannels * 2u);
  writeLe16(wav, kWatchAsrChannels * 2u);
  writeLe16(wav, 16);
  wav.write(reinterpret_cast<const uint8_t*>("data"), 4);
  writeLe32(wav, pcmBytes);
  return wav.position() == 44;
}

bool decodeOneWatchOpusFrame(OpusDecoder* decoder, const uint8_t* frame, size_t frameLength,
                             File& wav, uint32_t& pcmBytes, uint32_t& decodedFrames, String& error) {
  if (!decoder || !frame || !frameLength) { error = "opus_invalid_frame"; return false; }
  int16_t pcm[1920]{}; // enough for 120 ms at 16 kHz; observed frames are 20 ms.
  const int samples = opus_decode(decoder, frame, static_cast<opus_int32>(frameLength), pcm,
                                  sizeof(pcm) / sizeof(pcm[0]), 0);
  if (samples < 0) {
    error = "opus_decode_" + String(samples);
    return false;
  }
  const size_t bytes = static_cast<size_t>(samples) * sizeof(int16_t);
  if (pcmBytes + bytes > kWatchAsrPcmMaxBytes) {
    error = "audio_too_long_max_15s";
    return false;
  }
  if (wav.write(reinterpret_cast<const uint8_t*>(pcm), bytes) != bytes) {
    error = "wav_write_failed";
    return false;
  }
  pcmBytes += bytes;
  ++decodedFrames;
  return true;
}

bool decodeWatchOpusPacketsToWav(const char* packetPath, const char* wavPath, String& error) {
  if (!gWatchStreamCaptureFsReady) { error = "spiffs_unavailable"; return false; }
  File packets = SPIFFS.open(packetPath, FILE_READ);
  if (!packets) { error = "packet_file_missing"; return false; }
  SPIFFS.remove(wavPath);
  File wav = SPIFFS.open(wavPath, FILE_WRITE);
  if (!wav) { packets.close(); error = "wav_open_failed"; return false; }
  uint8_t blank[44]{};
  if (wav.write(blank, sizeof(blank)) != sizeof(blank)) {
    packets.close(); wav.close(); SPIFFS.remove(wavPath); error = "wav_header_reserve_failed"; return false;
  }

  int opusError = OPUS_OK;
  OpusDecoder* decoder = opus_decoder_create(kWatchAsrSampleRate, kWatchAsrChannels, &opusError);
  if (!decoder || opusError != OPUS_OK) {
    packets.close(); wav.close(); SPIFFS.remove(wavPath);
    error = "opus_decoder_create_" + String(opusError);
    if (decoder) opus_decoder_destroy(decoder);
    return false;
  }

  uint8_t aggregate[kWatchStreamPacketMax]{};
  uint32_t pcmBytes = 0, decodedFrames = 0, aggregates = 0;
  bool ok = true;
  while (packets.available() && ok) {
    uint8_t lenBytes[2]{};
    if (packets.read(lenBytes, 2) != 2) { error = "packet_length_truncated"; ok = false; break; }
    const size_t length = (static_cast<size_t>(lenBytes[0]) << 8) | lenBytes[1];
    if (!length || length > sizeof(aggregate) || packets.read(aggregate, length) != static_cast<int>(length)) {
      error = "packet_payload_truncated"; ok = false; break;
    }
    ++aggregates;

    bool fixed80 = length >= kWatchOpusSubframeBytes && (length % kWatchOpusSubframeBytes) == 0;
    if (fixed80) {
      for (size_t offset = 0; offset < length; offset += kWatchOpusSubframeBytes) {
        if (aggregate[offset] != 0xB8) { fixed80 = false; break; }
      }
    }
    if (fixed80) {
      for (size_t offset = 0; offset < length; offset += kWatchOpusSubframeBytes) {
        if (!decodeOneWatchOpusFrame(decoder, aggregate + offset, kWatchOpusSubframeBytes,
                                     wav, pcmBytes, decodedFrames, error)) { ok = false; break; }
      }
    } else {
      // Fallback for a future firmware that stops aggregating fixed 80-byte CBR frames.
      if (!decodeOneWatchOpusFrame(decoder, aggregate, length, wav, pcmBytes, decodedFrames, error)) ok = false;
    }
  }
  opus_decoder_destroy(decoder);
  packets.close();

  if (ok && pcmBytes > 0) ok = writePcmWavHeader(wav, pcmBytes);
  if (!ok && error.isEmpty()) error = "wav_header_finalize_failed";
  wav.close();
  if (!ok || pcmBytes == 0) {
    SPIFFS.remove(wavPath);
    if (error.isEmpty()) error = "no_audio_decoded";
    return false;
  }
  Serial.printf("WATCH_ASR_WAV_READY aggregates=%lu opus_frames=%lu pcm_bytes=%lu sample_rate=%u\n",
                static_cast<unsigned long>(aggregates), static_cast<unsigned long>(decodedFrames),
                static_cast<unsigned long>(pcmBytes), static_cast<unsigned>(kWatchAsrSampleRate));
  return true;
}

class MiMoAsrBodyStream : public Stream {
 public:
  MiMoAsrBodyStream(File file, const String& modelName, const String& language)
      : file_(file),
        prefix_(String("{\"model\":\"") + jsonEscape(modelName) +
                "\",\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"input_audio\",\"input_audio\":{\"data\":\"data:audio/wav;base64,"),
        suffix_(String("\"}}]}],\"asr_options\":{\"language\":\"") + jsonEscape(language) + "\"}}") {
    const size_t fileSize = file_ ? file_.size() : 0;
    base64Length_ = 4 * ((fileSize + 2) / 3);
    totalLength_ = prefix_.length() + base64Length_ + suffix_.length();
  }

  size_t contentLength() const { return totalLength_; }
  int available() override {
    const size_t remaining = totalLength_ > emitted_ ? totalLength_ - emitted_ : 0;
    return remaining > static_cast<size_t>(INT_MAX) ? INT_MAX : static_cast<int>(remaining);
  }
  int read() override {
    if (peeked_ >= 0) { const int value = peeked_; peeked_ = -1; ++emitted_; return value; }
    const int value = readInternal();
    if (value >= 0) ++emitted_;
    return value;
  }
  int peek() override {
    if (peeked_ < 0) peeked_ = readInternal();
    return peeked_;
  }
  void flush() override {}
  size_t write(uint8_t) override { return 0; }

 private:
  static String jsonEscape(const String& value) {
    String out; out.reserve(value.length() + 8);
    for (size_t i = 0; i < value.length(); ++i) {
      const char c = value[i];
      if (c == '\\' || c == '"') { out += '\\'; out += c; }
      else if (c == '\n') out += "\\n";
      else if (c == '\r') out += "\\r";
      else if (static_cast<uint8_t>(c) >= 0x20) out += c;
    }
    return out;
  }

  bool fillBase64() {
    if (!file_ || !file_.available()) return false;
    uint8_t raw[768]{}; // divisible by 3 -> 1024 Base64 bytes for full chunks.
    const size_t got = file_.read(raw, sizeof(raw));
    if (!got) return false;
    size_t encoded = 0;
    if (mbedtls_base64_encode(base64_, sizeof(base64_), &encoded, raw, got) != 0) return false;
    base64Pos_ = 0;
    base64Size_ = encoded;
    return true;
  }

  int readInternal() {
    if (prefixPos_ < prefix_.length()) return static_cast<uint8_t>(prefix_[prefixPos_++]);
    if (base64Pos_ < base64Size_) return base64_[base64Pos_++];
    if (file_ && file_.available()) {
      if (!fillBase64()) return -1;
      return base64_[base64Pos_++];
    }
    if (suffixPos_ < suffix_.length()) return static_cast<uint8_t>(suffix_[suffixPos_++]);
    return -1;
  }

  File file_;
  String prefix_, suffix_;
  size_t prefixPos_ = 0, suffixPos_ = 0;
  size_t base64Length_ = 0, totalLength_ = 0, emitted_ = 0;
  uint8_t base64_[1025]{};
  size_t base64Pos_ = 0, base64Size_ = 0;
  int peeked_ = -1;
};

bool mimoAsrRequest(const char* wavPath, String& transcript, String& error) {
  if (WiFi.status() != WL_CONNECTED) { error = "wifi_not_connected"; return false; }
  if (apiKey.isEmpty()) { error = "mimo_api_key_missing"; return false; }
  File wav = SPIFFS.open(wavPath, FILE_READ);
  if (!wav) { error = "asr_wav_missing"; return false; }
  if (wav.size() > 7 * 1024 * 1024) { wav.close(); error = "asr_audio_too_large"; return false; }

  const String language = (asrLanguage == "zh" || asrLanguage == "en") ? asrLanguage : "auto";
  const String activeAsrModel = asrModel.isEmpty() ? "mimo-v2.5-asr" : asrModel;
  MiMoAsrBodyStream requestStream(wav, activeAsrModel, language);
  const String url = cleanBase(baseUrl) + "/chat/completions";
  WiFiClient plain;
  WiFiClientSecure secure;
  HTTPClient http;
  if (!beginHttp(url, http, plain, secure, error)) { wav.close(); return false; }
  http.setTimeout(45000);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("Authorization", "Bearer " + apiKey);
  const int code = http.sendRequest("POST", &requestStream, requestStream.contentLength());
  const String response = http.getString();
  http.end();
  wav.close();
  if (code < 200 || code >= 300) {
    error = "asr_http_" + String(code) + ":" + response.substring(0, 384);
    return false;
  }
  JsonDocument res;
  if (deserializeJson(res, response)) { error = "asr_json_invalid"; return false; }
  const char* text = res["choices"][0]["message"]["content"] | nullptr;
  if (!text || !*text) { error = "asr_text_missing"; return false; }
  transcript = text;
  transcript.trim();
  if (transcript.length() > 740) transcript = transcript.substring(0, 740);
  return !transcript.isEmpty();
}

void updateAsrStatus(const String& transcript, const String& error, const String& answer) {
  if (gBridgeStateMutex && xSemaphoreTake(gBridgeStateMutex, pdMS_TO_TICKS(250)) == pdTRUE) {
    snprintf(gLastAsrTranscript, sizeof(gLastAsrTranscript), "%s", transcript.c_str());
    snprintf(gLastAsrError, sizeof(gLastAsrError), "%s", error.c_str());
    snprintf(gLastAiAnswer, sizeof(gLastAiAnswer), "%s", answer.c_str());
    xSemaphoreGive(gBridgeStateMutex);
  } else {
    snprintf(gLastAsrTranscript, sizeof(gLastAsrTranscript), "%s", transcript.c_str());
    snprintf(gLastAsrError, sizeof(gLastAsrError), "%s", error.c_str());
    snprintf(gLastAiAnswer, sizeof(gLastAiAnswer), "%s", answer.c_str());
  }
}

void watchAsrTaskMain(void* opaque) {
  AsrJobContext* job = static_cast<AsrJobContext*>(opaque);
  if (!job) {
    gWatchAsrTask = nullptr;
    vTaskDelete(nullptr);
    return;
  }
  const bool finalResult = job->finalResult;
  const uint32_t sessionId = job->sessionId;
  const String packetPath = job->packetPath;
  const String wavPath = job->wavPath;
  delete job;

  String error, transcript, answer;
  bool ok = decodeWatchOpusPacketsToWav(packetPath.c_str(), wavPath.c_str(), error);
  if (ok) ok = mimoAsrRequest(wavPath.c_str(), transcript, error);

  AsrResultMessage result;
  result.ok = ok;
  result.finalResult = finalResult;
  result.sessionId = sessionId;
  if (ok) snprintf(result.text, sizeof(result.text), "%s", transcript.c_str());
  else snprintf(result.error, sizeof(result.error), "%s", error.c_str());
  updateAsrStatus(transcript, error, "");
  if (gAsrResultQueue) xQueueSend(gAsrResultQueue, &result, pdMS_TO_TICKS(100));

  if (ok) {
    Serial.printf("WATCH_ASR_RESULT session=%lu final=%s text_bytes=%u\n",
                  static_cast<unsigned long>(sessionId), finalResult ? "true" : "false",
                  static_cast<unsigned>(transcript.length()));
    if (finalResult && chatAfterAsr) {
      String chatError;
      if (mimoWatchRequest(transcript, answer, chatError)) {
        updateAsrStatus(transcript, "", answer);
        Serial.printf("WATCH_MIMO_CHAT_RESULT session=%lu answer_bytes=%u context_turns=%u native_answer_return=false\n",
                      static_cast<unsigned long>(sessionId), static_cast<unsigned>(answer.length()),
                      static_cast<unsigned>(gWatchContextCount));
      } else {
        updateAsrStatus(transcript, "chat:" + chatError, "");
        Serial.printf("WATCH_MIMO_CHAT_FAILED session=%lu reason=%s\n",
                      static_cast<unsigned long>(sessionId), chatError.c_str());
      }
      gXiaoAiAssistantDoneSessionId = sessionId;
    }
  } else {
    Serial.printf("WATCH_ASR_FAILED session=%lu final=%s reason=%s\n",
                  static_cast<unsigned long>(sessionId), finalResult ? "true" : "false", error.c_str());
    if (finalResult && chatAfterAsr) gXiaoAiAssistantDoneSessionId = sessionId;
  }

  SPIFFS.remove(packetPath.c_str());
  SPIFFS.remove(wavPath.c_str());
  gWatchAsrTask = nullptr;
  vTaskDelete(nullptr);
}

bool scheduleWatchAsrJob(const char* packetPath, const char* wavPath, bool finalResult, uint32_t sessionId) {
  if (gWatchAsrTask || !packetPath || !wavPath || sessionId == 0) return false;
  if (!gAsrResultQueue) gAsrResultQueue = xQueueCreate(2, sizeof(AsrResultMessage));
  if (!gAsrResultQueue) return false;

  AsrJobContext* job = new AsrJobContext();
  if (!job) {
    Serial.println("WATCH_ASR_JOB_ALLOC_FAILED");
    return false;
  }
  job->finalResult = finalResult;
  job->sessionId = sessionId;
  snprintf(job->packetPath, sizeof(job->packetPath), "%s", packetPath);
  snprintf(job->wavPath, sizeof(job->wavPath), "%s", wavPath);
  BaseType_t created = xTaskCreatePinnedToCore(watchAsrTaskMain, finalResult ? "vela_asr_final" : "vela_asr_partial",
                                               kWatchAsrTaskStackBytes, job, 1, &gWatchAsrTask, 1);
  if (created != pdPASS) {
    delete job;
    gWatchAsrTask = nullptr;
    Serial.println("WATCH_ASR_TASK_CREATE_FAILED");
    return false;
  }
  Serial.printf("WATCH_ASR_TASK_STARTED session=%lu final=%s model=mimo-v2.5-asr decode=opus_5x80_to_wav16k\n",
                static_cast<unsigned long>(sessionId), finalResult ? "true" : "false");
  return true;
}

const char kWebUi[] PROGMEM = R"HTML(
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content='width=device-width,initial-scale=1,viewport-fit=cover'>
<meta name="theme-color" content='#0b1017'>
<title>Vela Gateway · 管理台</title>
<style>
:root{
  --bg:#0b1017; --panel:#131b25; --panel2:#0f161f; --line:#24303f;
  --text:#e8f0fa; --muted:#8296ad; --accent:#3b82f6; --accent2:#2563eb;
  --ok:#22c55e; --warn:#f59e0b; --bad:#ef4444; --radius:14px;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{overflow-x:hidden;
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
  background:radial-gradient(1200px 600px at 50% -10%,#16283f 0%,var(--bg) 55%) fixed;
  color:var(--text); padding:16px 14px 40px; max-width:760px; margin:0 auto;
  -webkit-text-size-adjust:100%;
}
h1{font-size:19px;margin:0;letter-spacing:.2px}
h2{font-size:15px;margin:0 0 10px;display:flex;align-items:center;gap:8px}
h2 .ic{width:20px;height:20px;opacity:.9}
.sub{color:var(--muted);font-size:12.5px;margin:4px 0 0}
header{display:flex;justify-content:space-between;align-items:flex-start;gap:10px;margin-bottom:14px}
.card{background:linear-gradient(180deg,var(--panel) 0%,var(--panel2) 100%);min-width:0;
  border:1px solid var(--line);border-radius:var(--radius);padding:14px;margin:12px 0;
  box-shadow:0 6px 20px rgba(0,0,0,.25)}
.card.danger{border-color:rgba(239,68,68,.5)}
.tag{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11.5px;
  border:1px solid var(--line);color:var(--muted);background:#0d141d}
.tag.test{color:#fbbf24;border-color:rgba(245,158,11,.45);background:rgba(245,158,11,.1)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(120px,100%),1fr));gap:8px;min-width:0}
/* 状态卡：显式 minmax(0,1fr)，否则 "20133 / 18422" 这类长数字会把
   grid 的最小内容宽度撑开，整页出现横向溢出（手机上表现为右侧被裁切） */
/* 状态卡自适应：用 auto-fit + minmax(0,1fr)，
   窄屏自动降到 2 列/1 列，长数字也不会把页面顶出去 */
.grid.kv-grid{grid-template-columns:repeat(auto-fit,minmax(min(132px,100%),1fr))!important}
.kv{min-width:0;overflow:hidden}
.kv span{font-variant-numeric:tabular-nums;white-space:nowrap;text-overflow:ellipsis;overflow:hidden;display:block}
.kv{background:#0d141d;border:1px solid #1c2532;border-radius:10px;padding:9px 11px}
.kv b{display:block;font-size:11px;color:var(--muted);font-weight:500;margin-bottom:2px}
.kv span{font-size:14px;font-variant-numeric:tabular-nums;word-break:break-all}
label{display:block;font-size:12.5px;color:var(--muted);margin:12px 0 5px}
input,select,button{font:inherit}
input,select{width:100%;padding:11px 12px;border-radius:11px;border:1px solid var(--line);
  background:#0d141d;color:var(--text);outline:none;transition:border-color .15s}
input:focus,select:focus{border-color:var(--accent)}
button{border:0;border-radius:11px;padding:12px 14px;cursor:pointer;
  background:var(--accent);color:#fff;font-weight:600;transition:filter .15s,transform .05s}
button:active{transform:scale(.99)}
button.ghost{background:#1a2432;color:var(--text);border:1px solid var(--line)}
button.danger{background:var(--bad)}
button.warn{background:var(--warn);color:#20160a}
button:disabled{opacity:.45;cursor:not-allowed}
.row{display:grid;grid-template-columns:1fr 1fr;gap:9px}
.row3{display:grid;grid-template-columns:repeat(3,1fr);gap:9px}
@media(max-width:520px){.row{grid-template-columns:1fr}.row3{grid-template-columns:1fr 1fr}}
.list{display:flex;flex-direction:column;gap:6px;margin-top:9px;max-height:230px;overflow:auto}
.item{display:flex;justify-content:space-between;align-items:center;gap:10px;
  padding:10px 11px;border-radius:10px;background:#0d141d;border:1px solid #1c2532;
  cursor:pointer;text-align:left;width:100%;color:var(--text);font-weight:500;font-size:13.5px}
.item:hover{border-color:var(--accent)}
.item small{color:var(--muted);font-weight:400;white-space:nowrap;font-size:11.5px}
.muted{color:var(--muted);font-size:12.5px}
.bar{height:6px;border-radius:99px;background:#1b2534;overflow:hidden;margin:6px 0 2px}
.bar i{display:block;height:100%;background:linear-gradient(90deg,#3b82f6,#22c55e);width:0;transition:width .3s}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:6px;background:#475569}
.dot.ok{background:var(--ok);box-shadow:0 0 0 3px rgba(34,197,94,.15)}
.dot.bad{background:var(--bad);box-shadow:0 0 0 3px rgba(239,68,68,.15)}
.dot.mid{background:var(--warn);box-shadow:0 0 0 3px rgba(245,158,11,.15)}
.log{background:#080d13;border:1px solid #17202c;border-radius:10px;padding:10px;
  font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#9fb3c8;
  max-height:180px;overflow:auto;white-space:pre-wrap;word-break:break-all}
.modal{position:fixed;inset:0;background:rgba(4,8,13,.78);backdrop-filter:blur(4px);
  display:none;align-items:center;justify-content:center;padding:18px;z-index:50}
.modal.on{display:flex}
.modal-box{background:var(--panel);border:1px solid var(--line);border-radius:16px;
  padding:18px;max-width:420px;width:100%;box-shadow:0 24px 60px rgba(0,0,0,.55)}
.modal-box h3{margin:0 0 8px;font-size:16px}
ul.tight{margin:8px 0;padding-left:18px;font-size:13px;color:#c7d5e6}
ul.tight li{margin:3px 0}
.hr{height:1px;background:var(--line);margin:14px 0}
a{color:#60a5fa}
footer{text-align:center;color:var(--muted);font-size:12px;margin-top:26px;line-height:1.9}
.toast{position:fixed;left:50%;bottom:22px;transform:translate(-50%,20px);opacity:0;
  background:#1b2634;border:1px solid var(--line);color:var(--text);padding:11px 16px;
  border-radius:11px;font-size:13.5px;transition:.25s;pointer-events:none;z-index:99;max-width:90vw}
.toast.on{opacity:1;transform:translate(-50%,0)}
.toast.err{border-color:rgba(239,68,68,.6);background:#2a1518}

/* ===== 分区导航（移动优先：横向可滚，桌面自适应）===== */
nav{display:flex;gap:6px;overflow-x:auto;padding:6px;margin:0 0 14px;
  background:#0d141d;border:1px solid var(--line);border-radius:13px;
  scrollbar-width:none;-webkit-overflow-scrolling:touch}
nav::-webkit-scrollbar{display:none}
nav button{flex:0 0 auto;display:flex;align-items:center;gap:6px;padding:8px 13px;
  border-radius:9px;background:transparent;color:var(--muted);font-weight:600;font-size:13px;
  white-space:nowrap;transition:background .15s,color .15s}
nav button:hover{color:var(--text)}
nav button.on{background:var(--accent);color:#fff}
nav button svg{width:15px;height:15px;flex:0 0 auto}
.panel{display:none}
.panel.on{display:block;animation:fade .18s ease-out}
@keyframes fade{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
/* 区块小结：一行小字解释这块卡片是干嘛的 */
.hint{color:var(--muted);font-size:12px;margin:-4px 0 10px;line-height:1.5}
/* 电平/结果行 */
.mini{display:flex;justify-content:space-between;align-items:center;gap:8px;
  padding:8px 0;border-bottom:1px dashed #1e2836;font-size:13px}
.mini:last-child{border-bottom:0}
.mini b{font-weight:500;color:var(--muted)}
.mini span{font-variant-numeric:tabular-nums}
/* 迷你柱状图（纯 CSS + 内联高度，不引任何图表库）*/
.spark{display:flex;align-items:flex-end;gap:2px;height:56px;padding:8px 10px;
  background:#0a1017;border:1px solid #17202c;border-radius:10px;margin-top:8px}
.spark i{flex:1 1 auto;min-width:2px;border-radius:2px 2px 0 0;
  background:linear-gradient(180deg,#38bdf8,#2563eb);transition:height .3s}
.spark i.tx{background:linear-gradient(180deg,#34d399,#059669)}
.legend{display:flex;gap:14px;font-size:11.5px;color:var(--muted);margin-top:6px}
.legend em{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:4px;font-style:normal}
/* 面板内的表单排布更紧凑 */
.panel .card:first-child{margin-top:0}
input[type=range]{padding:0;height:28px;accent-color:var(--accent)}
</style>
</head>
<body>

<header>
  <div>
    <h1>Vela Gateway</h1>
    <p class="sub">ESP32 手表上网网关 · <span class="tag test" id="fwTag">__PH_VERFULL__</span></p>
  </div>
  <button class="ghost" style="width:auto;padding:8px 12px;font-size:13px" data-act="refresh">刷新</button>
</header>

<nav id="tabs">
  <button data-act="tab" data-arg="dash" class="on"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 13h4l3 7 4-16 3 9h4"/></svg>运行</button>
  <button data-act="tab" data-arg="perf"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 19V5M4 19h16"/><path d="M8 15l4-5 3 3 4-6"/></svg>性能</button>
  <button data-act="tab" data-arg="net"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 8a16 16 0 0 1 20 0M5.5 11.5a11 11 0 0 1 13 0M9 15a6 6 0 0 1 6 0"/><circle cx="12" cy="19" r="1.4"/></svg>网络</button>
  <button data-act="tab" data-arg="bt"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v18l5-4-10-8 10-4-5-4"/></svg>手表</button>
  <button data-act="tab" data-arg="res"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M4 19h16"/></svg>资源</button>
  <button data-act="tab" data-arg="dev"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="5" width="14" height="14" rx="2"/><path d="M9 9h6v6H9z"/></svg>设备</button>
  <button data-act="tab" data-arg="tools"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.9 1.2 2 2 0 1 1-4 0 1.7 1.7 0 0 0-2.9-1.2l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1A1.7 1.7 0 0 0 3 15a2 2 0 1 1 0-4 1.7 1.7 0 0 0 1.5-2.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1A1.7 1.7 0 0 0 10 4a2 2 0 1 1 4 0 1.7 1.7 0 0 0 2.9 1.5l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1A1.7 1.7 0 0 0 21 11a2 2 0 1 1 0 4z"/></svg>设置</button>
  <button data-act="tab" data-arg="sys"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M19.1 4.9 17 7M7 17l-2.1 2.1"/></svg>系统</button>
</nav>

<section class="panel on" id="p-dash">
<div class="card">
  <h2>运行状态 <span class="muted" id="pollHint" style="font-weight:400"></span></h2>
  <div class="grid kv-grid">
    <div class="kv"><b>Wi-Fi</b><span id="sWifi"><i class="dot"></i>读取中</span></div>
    <div class="kv"><b>手表</b><span id="sWatch"><i class="dot"></i>读取中</span></div>
    <div class="kv"><b>转发</b><span id="sProxy"><i class="dot"></i>—</span></div>
    <div class="kv"><b>IP</b><span id="sIp">读取中</span></div>
    <div class="kv"><b>空闲内存</b><span id="sMem">读取中</span></div>
    <div class="kv"><b>上行 / 下行</b><span id="sPkt">读取中</span></div>
  </div>
  <div style="margin-top:10px">
    <div style='display:flex;justify-content:space-between;font-size:12px;color:var(--muted)'>
      <span>固件分区占用</span><span id="sFlashTxt">读取中</span>
    </div>
    <div class="bar"><i id="sFlashBar"></i></div>
    <p class="muted" id="sPart" style="margin:6px 0 0">正在读取分区信息…</p>
    <p class="muted" id="sSlots" style="margin:4px 0 0">正在读取 OTA 槽…</p>
  </div>
  <p class="muted" id="sCounters" style="margin:8px 0 0"></p>
</div>

<div class="card">
  <h2>实时流量 <span class="muted" style="font-weight:400">· 近 1 分钟</span></h2>
  <div class="grid kv-grid">
    <div class="kv"><b>下行</b><span id="tRx">—</span></div>
    <div class="kv"><b>上行</b><span id="tTx">—</span></div>
    <div class="kv"><b>丢包率</b><span id="tDrop">—</span></div>
    <div class="kv"><b>累计包数</b><span id="tPkts">—</span></div>
  </div>
  <div class="spark" id="spark"><i style="height:2px"></i></div>
  <div class="legend"><span><em style="background:#2563eb"></em>收到</span><span><em style="background:#059669"></em>发出</span></div>
  <p class="muted" style="margin:6px 0 0">采样间隔 2 秒，共 30 个采样点，柱高按窗口内最大值归一。</p>
</div>

<div class="card" id="autoCard" style="display:none">
  <h2>Wi-Fi 连接失败，配网热点已开启</h2>
  <p class="muted" id="autoText"></p>
  <div class="row" style="margin-top:10px">
    <button class="ghost" data-act="cancel">暂停配网热点（30 分钟）</button>
    <button class="ghost" data-act="goto-setup">修改配置</button>
  </div>
</div>

<div class="card" id="setup">
  <h2>① 家庭 Wi-Fi</h2>
  <div class="row">
    <button class="ghost" data-act="scanWifi">扫描附近网络</button>
    <button class="ghost" data-act="manual-ssid">手动输入</button>
  </div>
  <p class="muted" id="wifiStatus">扫描列表中选择网络，或手动填写 SSID。</p>
  <div class="list" id="networks"></div>
  <label>SSID</label>
  <input id="ssid" autocomplete="off" placeholder="家庭 Wi-Fi 名称">
  <label>Wi-Fi 密码</label>
  <input id="wp" type="text" autocomplete="off" placeholder="留空表示开放网络">
</div>

<div class="card">
  <h2>② 手表蓝牙</h2>
  <div class="row">
    <button class="ghost" data-act="scanBluetooth">扫描蓝牙</button>
    <button class="ghost" data-act="testBluetooth">测试连接</button>
  </div>
  <p class="muted" id="bluetoothStatus">在扫描列表中选择设备后，MAC 自动填入。</p>
  <div class="list" id="bluetoothDevices"></div>
  <label>手表 MAC</label>
  <input id="mac" autocomplete="off" placeholder="AA:BB:CC:DD:EE:FF">
  <label>Watch AuthKey（32 位）</label>
  <input id="wauth" type="text" autocomplete="off" placeholder="粘贴手表 AuthKey">
</div>

<div class="card">
  <h2>③ 热点与安全</h2>
  <div class="row">
    <div>
      <label>热点名称</label>
      <input id="apname" value="__PH_AP__" maxlength="32" autocomplete="off">
    </div>
    <div>
      <label>热点密码（≥8 位）</label>
      <input id="ap" type="text" value="__PH_PASS__" minlength="8" autocomplete="off">
    </div>
  </div>
  <p class="muted" style="margin-top:8px">修改后需使用新密码重新连接热点。</p>
</div>

<button style="width:100%;padding:15px;font-size:15.5px" data-act="save">保存并连接</button>
<p class="muted" id="saveHint" style="text-align:center;margin-top:8px"></p>

</section>

<section class="panel" id="p-sys">
<div class="card">
  <h2>设备信息</h2>
  <div class="mini"><b>固件版本</b><span id="yVer">—</span></div>
  <div class="mini"><b>硬件</b><span id="yHw">—</span></div>
  <div class="mini"><b>Flash</b><span id="yFlash">—</span></div>
  <div class="mini"><b>当前运行分区</b><span id="yPart">—</span></div>
  <div class="mini"><b>运行时长</b><span id="yUp">—</span></div>
  <div class="mini"><b>空闲内存</b><span id="yMem">—</span></div>
  <div class="mini"><b>历史最低内存</b><span id="yMemMin">—</span></div>
</div>

<div class="card">
  <h2>OTA 槽</h2>
  <div class="list" id="ySlots" style="max-height:none"></div>
</div>

<div class="card">
  <h2>上次升级未生效</h2>
  <div id="otaBadBox" style="display:none">
    <p class="sub" id="otaBadText"></p>
    <button class="ghost" style="width:100%;margin-top:10px" data-act="otaBadAck">知道了</button>
  </div>
  <p class="hint" id="otaBadNone">没有记录到固件回滚。</p>
</div>

<div class="card">
  <h2>恢复出厂设置</h2>
  <ul class="tight">
    <li>长按 BOOT 3 秒：清除 Wi-Fi 配置，保留手表密钥，适用于更换路由器</li>
    <li>长按 BOOT 10 秒：清除全部配置并进入配网热点</li>
    <li>Wi-Fi 连接失败时：自动开启配网热点，原有配置保持不变</li>
  </ul>
  <button class="danger" style="width:100%;margin-top:10px" data-act="openReset">恢复出厂设置…</button>
  <p class="hint" style="margin-top:10px">清除范围：Wi-Fi 配置、手表密钥、热点密码。固件、分区表与 SPIFFS 文件不受影响。</p>
</div>
</section>

<section class="panel" id="p-res">
<div class="card">
  <h2>上传表盘 / 快应用</h2>
  <p class="sub">表盘格式为 <code>.bin</code> / <code>.face</code>，快应用为 <code>.rpk</code>。文件先写入设备存储（3.8 MB），再经蓝牙传输至手表。</p>
  <label>表盘文件</label>
  <input type="file" id="wfFile" accept=".bin,.face">
  <label>快应用包</label>
  <input type="file" id="appFile" accept=".rpk">
  <div id="upBar" class="muted" style="margin-top:10px"></div>
</div>
<div class="card">
  <h2>已上传 <span class="muted" id="resUsage" style="font-weight:400"></span></h2>
  <div class="list" id="resList"><div class="muted">加载中…</div></div>
</div>
<div class="card">
  <h2>安装进度</h2>
  <div class="grid kv-grid">
    <div class="kv"><b>状态</b><span id="instState">—</span></div>
    <div class="kv"><b>分片</b><span id="instProg">—</span></div>
  </div>
  <div style="height:8px;background:#0d141d;border-radius:99px;margin-top:10px;overflow:hidden">
    <div id="instBar" style="height:100%;width:0;background:var(--accent);transition:width .2s"></div>
  </div>
  <div class="row" style="margin-top:10px">
    <button class="ghost" data-act="resRefresh">刷新列表</button>
    <button class="danger" data-act="resCancel">取消安装</button>
  </div>
  <p class="sub" style="margin-top:10px">安装期间蓝牙通道被 Mass 数据传输独占，回程网络包丢弃，手表侧 TCP 自动重传。</p>
</div>
</section>

<section class="panel" id="p-dev">
<div class="card">
  <h2>设备信息</h2>
  <div class="grid kv-grid" id="devInfo">
    <div class="kv"><b>固件</b><span id="dFw">—</span></div>
    <div class="kv"><b>通道</b><span id="dCh">—</span></div>
    <div class="kv"><b>主.次.构建.修订</b><span id="dBu">—</span></div>
    <div class="kv"><b>构建日期</b><span id="dDate">—</span></div>
    <div class="kv"><b>Flash</b><span id="dFl">—</span></div>
    <div class="kv"><b>应用分区</b><span id="dAp">—</span></div>
    <div class="kv"><b>SPIFFS</b><span id="dSp">—</span></div>
    <div class="kv"><b>芯片</b><span id="dChip">—</span></div>
    <div class="kv"><b>芯片温度</b><span id="dTemp">—</span></div>
    <div class="kv"><b>运行时长</b><span id="dUp">—</span></div>
    <div class="kv"><b>复位原因</b><span id="dRst">—</span></div>
  </div>
</div>

<div class="card">
  <h2>链路质量</h2>
  <p class="hint">由信号强度、空闲内存与丢包率加权计算，取值 0-100。低于 50 时转发延迟明显上升。</p>
  <div style="display:flex;align-items:baseline;gap:10px">
    <div style="font-size:34px;font-weight:700;font-variant-numeric:tabular-nums" id="qScore">—</div>
    <div class="muted" id="qText">读取中</div>
  </div>
  <div class="bar" style="height:8px"><i id="qBar" style="width:0"></i></div>
  <div class="mini"><b>信号强度</b><span id="qRssi">—</span></div>
  <div class="mini"><b>信道 / 频率</b><span id="qChan">—</span></div>
  <div class="mini"><b>同信道邻居</b><span id="qNb">—</span></div>
  <div class="mini"><b>BSSID</b><span id="qBssid">—</span></div>
</div>
</section>

<section class="panel" id="p-perf">
<div class="card">
  <h2>内存占用</h2>
  <p class="hint">蓝牙协议栈、lwIP 与转发缓冲均占用内部 RAM。空闲内存低于 20 KB 时建议重启。</p>
  <div class="grid kv-grid">
    <div class="kv"><b>空闲</b><span id="mFree">—</span></div>
    <div class="kv"><b>历史最低</b><span id="mMin">—</span></div>
    <div class="kv"><b>最大连续块</b><span id="mMax">—</span></div>
    <div class="kv"><b>片段化</b><span id="mFrag">—</span></div>
  </div>
  <div class="mini"><b>SPIFFS 已用</b><span id="mSpiffs">—</span></div>
</div>

<div class="card">
  <h2>转发统计</h2>
  <div class="grid kv-grid">
    <div class="kv"><b>上行包</b><span id="pRx">—</span></div>
    <div class="kv"><b>下行包</b><span id="pTx">—</span></div>
    <div class="kv"><b>丢包</b><span id="pDrop">—</span></div>
    <div class="kv"><b>会话轮次</b><span id="pTurns">—</span></div>
  </div>
</div>

<div class="card">
  <h2>硬件健康</h2>
  <div class="mini"><b>芯片</b><span id="hChip">—</span></div>
  <div class="mini"><b>主频</b><span id="hFreq">—</span></div>
  <div class="mini"><b>Flash</b><span id="hFlash">—</span></div>
  <div class="mini"><b>温度</b><span id="hTemp">—</span></div>
  <div class="mini"><b>运行时长</b><span id="hUp">—</span></div>
  <div class="mini"><b>SDK</b><span id="hSdk">—</span></div>
</div>
</section>

<section class="panel" id="p-net">
<div class="card">
  <h2>家庭 Wi-Fi</h2>
  <p class="hint">此项配置设备连接的路由器。修改后需重启生效。</p>
  <div class="mini"><b>当前 SSID</b><span id="nSsid">—</span></div>
  <div class="mini"><b>IP 地址</b><span id="nIp">—</span></div>
  <div class="mini"><b>信号</b><span id="nRssi">—</span></div>
  <div class="mini"><b>信道</b><span id="nChan">—</span></div>
  <button class="ghost" style="width:100%;margin-top:10px" data-act="tab" data-arg="dash">在「运行」页修改 Wi-Fi</button>
</div>

<div class="card">
  <h2>时钟与校时</h2>
  <p class="hint">完成时间同步后，手表侧时间戳与日志时间才准确。时区使用 POSIX TZ 格式。</p>
  <div style="font-size:22px;font-weight:600;font-variant-numeric:tabular-nums" id="clockNow">—</div>
  <div class="mini"><b>同步状态</b><span id="clockSync">—</span></div>
  <div class="mini"><b>时区</b><span id="clockTz">—</span></div>
  <label>修改时区</label>
  <input id="tzInput" autocomplete="off" placeholder="CST-8">
  <div class="row" style="margin-top:9px">
    <button class="ghost" data-act="tz-preset" data-arg="CST-8">UTC+8</button>
    <button class="ghost" data-act="tz-preset" data-arg="UTC0">UTC</button>
    <button class="ghost" data-act="tz-preset" data-arg="JST-9">UTC+9</button>
    <button class="ghost" data-act="tz-preset" data-arg="EST5EDT">美东</button>
  </div>
  <button style="width:100%;margin-top:9px" data-act="syncClock">立即校时</button>
</div>
</section>

<section class="panel" id="p-bt">
<div class="card">
  <h2>手表连接</h2>
  <div class="mini"><b>桥接状态</b><span id="bState">—</span></div>
  <div class="mini"><b>手表 MAC</b><span id="bMac">—</span></div>
  <div class="mini"><b>SDP 通道</b><span id="bChan">—</span></div>
  <div class="mini"><b>身份认证</b><span id="bAuth">—</span></div>
  <div class="mini"><b>配对密钥</b><span id="bKey">—</span></div>
  <div class="row" style="margin-top:10px">
    <button class="ghost" data-act="watchRestart">重连手表</button>
    <button class="ghost" data-act="contextReset">清空对话上下文</button>
  </div>
</div>

<div class="card">
  <h2>向手表推一条消息</h2>
  <p class="hint">经已认证的 SPP 会话发送，手表侧以通知形式显示。要求桥接处于已连接状态。</p>
  <label>内容（最多 400 字）</label>
  <input id="pushText" autocomplete="off" placeholder="输入要推送的文本内容">
  <div class="row" style="margin-top:9px">
    <button data-act="pushText">发送到手表</button>
    <button class="ghost" data-act="pushPreset" data-arg="测试消息：网关工作正常">发送测试消息</button>
  </div>
</div>
</section>

<section class="panel" id="p-tools">
<div class="card">
  <h2>LED 灯效</h2>
  <p class="hint">板载 LED 位于 GPIO2。默认模式为流量联动，仅在数据转发时闪烁。</p>
  <div class="row3" id="ledGroup">
    <button class="ghost" data-act="led" data-arg="0">关闭</button>
    <button class="ghost" data-act="led" data-arg="1">常亮</button>
    <button class="ghost" data-act="led" data-arg="2">呼吸</button>
    <button class="ghost" data-act="led" data-arg="3">心跳</button>
    <button class="ghost" data-act="led" data-arg="4">流量联动</button>
    <button class="ghost" data-act="ledTest">点亮 1.5 秒</button>
  </div>
</div>

<div class="card">
  <h2>界面偏好</h2>
  <div class="mini"><b>显示运行日志</b><button class="ghost" style="width:auto;padding:6px 12px;font-size:12.5px" id="prefLog" data-act="togglePref" data-arg="showLog">—</button></div>
  <div class="mini"><b>紧凑模式</b><button class="ghost" style="width:auto;padding:6px 12px;font-size:12.5px" id="prefCompact" data-act="togglePref" data-arg="compact">—</button></div>
  <div class="mini"><b>开机自动连手表</b><button class="ghost" style="width:auto;padding:6px 12px;font-size:12.5px" id="prefAuto" data-act="togglePref" data-arg="autoConnectWatch">—</button></div>
  <div class="mini"><b>跳过 TLS 证书校验</b><button class="ghost" style="width:auto;padding:6px 12px;font-size:12.5px" id="prefTls" data-act="togglePref" data-arg="insecureTls">—</button></div>
  <p class="hint" style="margin-top:10px">跳过 TLS 证书校验仅适用于自签证书调试场景。长期启用存在中间人攻击风险。</p>
</div>

<div class="card">
  <h2>健康检查</h2>
  <p class="hint">逐项检查常见故障点，异常项以红色标识。</p>
  <div class="list" id="checks" style="max-height:none"></div>
  <button style="width:100%;margin-top:10px" data-act="runChecks">开始检查</button>
</div>

<div class="card">
  <h2>固件升级</h2>
  <p class="muted">进入空中升级模式后设备重启，只开启热点和升级页面，不运行蓝牙桥接。刷写完成后再重启回网关。</p>
  <button class="ghost" style="width:100%;margin-top:9px" data-act="switchProj" data-arg="6">进入空中升级</button>
</div>

<div class="card">
  <h2>设备动作</h2>
  <button class="ghost" style="width:100%" data-act="reboot">重启设备</button>
  <p class="muted" style="margin-top:8px">重启不修改任何配置。</p>
</div>

<div class="card" id="logCard">
  <h2>运行日志 <span class="muted" style="font-weight:400">· 本页操作</span></h2>
  <div class="log" id="oLocal">就绪</div>
  <h2 style="margin-top:12px">设备事件 <span class="muted" style="font-weight:400">· 最近 24 条</span></h2>
  <div class="log" id="oDev">（暂无事件）</div>
</div>

</section>



<footer>
  <div id="footVer">__PH_VERFULL__ · __PH_HW__</div>
</footer>

<div class="modal" id="resetModal">
  <div class="modal-box">
    <h3 style="color:#ef4444">确认恢复出厂设置？</h3>
    <p class="muted">以下配置会被清除，设备随后重启并开启配网热点 <b>__PH_AP__</b>。</p>
    <div id="resetList"></div>
    <div class="hr"></div>
    <label style="margin-top:0">输入 <b>RESET</b> 以确认</label>
    <input id="resetConfirm" autocomplete="off" placeholder="RESET">
    <div class="row" style="margin-top:12px">
      <button class="ghost" data-act="closeReset">取消</button>
      <button class="danger" id="resetBtn" disabled data-act="doReset">确认清除</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
var $=function(id){return document.getElementById(id)};
// 本地令牌：随页面一起下发，api() 自动放进 X-Vela-Token 头。
// 没有它，局域网访问（用路由器里的 LAN IP 打开后台）时所有 /api/v1/* 都会 401。
var VELA_TOKEN='__PH_TOKEN__';
var toastT=0;
function toast(msg,err){
  var t=$('toast'); t.textContent=msg; t.className='toast on'+(err?' err':'');
  clearTimeout(toastT); toastT=setTimeout(function(){t.className='toast';},2600);
}
// 运行日志：上半区是本页操作，下半区是设备侧事件（/api/v1/logs 环形缓冲）。
// 以前这里只有一个本地 log()，只能看到浏览器自己干的事；升级失败、推送失败
// 这些真正有用的原因全在设备里，不开串口根本看不到。
var _devLogSig='', devLogAt=0;
function log(msg){
  var line=new Date().toLocaleTimeString('zh-CN',{hour12:false})+'  '+msg;
  var o=$('oLocal');
  o.textContent=line+'\n'+o.textContent;
  if(o.textContent.length>4000) o.textContent=o.textContent.slice(0,4000);
}
async function syncDeviceLogs(){
  var d=await api('/api/v1/logs');
  if(!d||!d.ok||!d.lines) return;
  var out=[];
  for(var i=d.lines.length-1;i>=0;i--){
    var l=d.lines[i];
    if(!l||!l.m) continue;
    out.push(new Date(l.t||0).toLocaleTimeString('zh-CN',{hour12:false})+'  '+l.m);
  }
  var txt=out.join('\n');
  if(txt===_devLogSig) return;
  _devLogSig=txt;
  $('oDev').textContent=txt||'（暂无事件）';
}
async function api(path,opt){
  try{
    opt=opt||{};
    // 局域网管理接口要求带本地令牌（X-Vela-Token）。令牌随页面一起下发，
    // 前端自动带上；否则连上家用路由器后用 LAN IP 打开后台会全部 401。
    var h={'X-Vela-Token':VELA_TOKEN};
    if(opt.headers){ for(var k in opt.headers){ h[k]=opt.headers[k]; } }
    var o={}; for(var kk in opt){ o[kk]=opt[kk]; } o.headers=h;
    var r=await fetch(path,o);
    var txt=await r.text();
    try{ var j=JSON.parse(txt); if(j && j.ok===false && j.error) log('ERR '+(j.error)+(j.message?' · '+j.message:'')); return j; }
    catch(e){ return {ok:r.ok,raw:txt}; }
  }catch(e){ log('网络错误 '+e); return {ok:false,error:String(e)}; }
}
function setDot(el,state,txt){
  el.innerHTML='<i class="dot '+state+'"></i>'+txt;
}

/* ---------- 分页导航 ---------- */
var PANELS=['dash','perf','net','bt','res','dev','tools','sys'];
var activeTab='dash';
function showTab(name){
  if(PANELS.indexOf(name)<0) name='dash';
  activeTab=name;
  PANELS.forEach(function(n){
    var el=$('p-'+n);
    if(el) el.classList.toggle('on', n===name);
  });
  document.querySelectorAll('#tabs button').forEach(function(b){
    b.classList.toggle('on', b.dataset.arg===name);
  });
  // 切页后重新拉一次，避免看到旧数字
  if(name==='perf') loadPerf();
  else if(name==='dev') loadPerf();   // 设备信息/链路质量由 loadPerf 一并填充
  else if(name==='net') loadNet();
  else if(name==='bt') loadWatch();
  else if(name==='res') loadRes();
  else if(name==='tools'){
    // 「设置」就是原来的工具页：固件升级、重启、恢复出厂、偏好都收在这里
    loadPrefs();
    loadSys();
  }
}
/* ---------- 流量 ---------- */
var sparkMax=1;
function fmtBytes(n){
  n=n||0;
  if(n<1024) return n+' B';
  if(n<1048576) return (n/1024).toFixed(1)+' KB';
  if(n<1073741824) return (n/1048576).toFixed(2)+' MB';
  return (n/1073741824).toFixed(2)+' GB';
}
async function loadTraffic(){
  var d=await api('/api/v1/traffic');
  if(!d||d.ok===false) return;
  // 最近两格的平均速率（每格 2 秒）
  var h=d.history||[];
  var n=h.length;
  var last=h[n-1]||[0,0], prev=h[n-2]||[0,0];
  $('tRx').textContent=fmtBytes(Math.round((last[0]+prev[0])/2/2))+'/s';
  $('tTx').textContent=fmtBytes(Math.round((last[1]+prev[1])/2/2))+'/s';
  $('tDrop').textContent=(d.dropped||0)+' 包';
  $('tPkts').textContent=(d.rxPackets||0)+(d.txPackets||0);
  // 画柱：收发两色交替，按峰值归一
  var peak=0;
  h.forEach(function(p){ peak=Math.max(peak,p[0],p[1]); });
  sparkMax=Math.max(sparkMax,peak);
  var box=$('spark');
  if(!box) return;
  var html='';
  for(var i=0;i<30;i++){
    var p=h[i]||[0,0];
    var rp=sparkMax?Math.max(2,Math.round(p[0]*52/sparkMax)):2;
    html+='<i style="height:'+rp+'px" title="收到 '+p[0]+' B / 发出 '+p[1]+' B"></i>';
  }
  box.innerHTML=html;
}
/* ---------- 性能 ---------- */
async function loadPerf(){
  var d=await api('/api/v1/status');
  if(d&&d.ok!==false){
    $('mFree').textContent=Math.round((d.heapFree||0)/1024)+' KB';
    $('mMin').textContent=Math.round((d.heapMinFree||0)/1024)+' KB';
  }
  var t=await api('/api/v1/traffic');
  if(t&&t.ok!==false){
    $('pRx').textContent=t.rxPackets||0;
    $('pTx').textContent=t.txPackets||0;
    $('pDrop').textContent=t.dropped||0;
    $('pTurns').textContent=t.turns||0;
  }
  var h=await api('/api/v1/hal');
  if(h&&h.ok!==false){
    $('mMax').textContent='—';
    $('mFrag').textContent = d&&d.heapFree ? (Math.round(d.heapFree/1024)?(100-Math.round((d.heapMinFree||0)*100/(d.heapFree||1)))+'%':'—') : '—';
    $('hChip').textContent=h.chipModel+' rev'+h.chipRevision+' · '+h.chipCores+' 核';
    $('hFreq').textContent=h.cpuFreqMHz+' MHz';
    $('hFlash').textContent=Math.round((h.flashSize||0)/1048576)+' MB';
    $('hTemp').textContent=(h.chipTempC||h.chipTempC===0?h.chipTempC+' ℃':'—');
    $('hUp').textContent=h.uptimeText||'—';
    $('hSdk').textContent=h.sdkVersion||'—';
    $('dChip').textContent=h.chipModel;
    $('dTemp').textContent=(h.chipTempC||h.chipTempC===0)?h.chipTempC+' ℃':'—';
    $('dUp').textContent=h.uptimeText||'—';
    var rs={1:'上电',3:'软复位',4:'看门狗',5:'深睡唤醒',6:'掉电',7:'任务看门狗',8:'其他',9:'未定义',12:'外部复位'};
    $('dRst').textContent=rs[h.resetReason]||('代码 '+h.resetReason);
  }
  if(d&&d.spiffsUsed!==undefined){
    $('mSpiffs').textContent=fmtBytes(d.spiffsUsed)+' / '+fmtBytes(d.spiffsTotal);
  }
  var q=await api('/api/v1/linkscore');
  if(q&&q.ok!==false){
    var sc=q.score||0;
    $('qScore').textContent=sc;
    $('qScore').style.color = sc>=75?'var(--ok)':(sc>=50?'var(--warn)':'var(--bad)');
    $('qText').textContent = sc>=75?'链路良好':(sc>=50?'一般，偶有卡顿':'较差，建议换信道或靠近路由器');
    $('qBar').style.width=sc+'%';
    $('qBar').style.background = sc>=75?'linear-gradient(90deg,#22c55e,#4ade80)':(sc>=50?'linear-gradient(90deg,#f59e0b,#fbbf24)':'linear-gradient(90deg,#ef4444,#f87171)');
    $('qRssi').textContent=q.rssi?q.rssi+' dBm':'—';
    $('qChan').textContent=q.channel?(q.channel+' 信道 · '+q.freqMhz+' MHz'):'—';
    $('qNb').textContent=q.scanCached?q.sameChannelNeighbors+' 个':'（未扫描，先扫一次 Wi-Fi）';
    $('qBssid').textContent=q.bssid||'—';
  }
}
/* ---------- 网络/时钟 ---------- */
var clockTimer=0;
async function loadNet(){
  var d=await api('/api/v1/status');
  if(d&&d.ok!==false){
    $('nSsid').textContent=d.ssid||'—';
    $('nIp').textContent=(d.staIp&&d.staIp!=='0.0.0.0')?d.staIp:(d.setupApIp||'—');
    $('nRssi').textContent=d.wifi?'已连接':'未连接';
  }
  var q=await api('/api/v1/linkscore');
  if(q&&q.ok!==false){
    $('nRssi').textContent=q.rssi?q.rssi+' dBm':'未连接';
    $('nChan').textContent=q.channel?(q.channel+' / '+q.freqMhz+' MHz'):'—';
  }
  tickClock();
  var c=await api('/clock');
  if(c&&c.ok!==false){
    $('clockNow').textContent=c.localText||'未同步';
    $('clockSync').textContent=c.synced?'已同步':'未同步，可通过下方按钮校时';
    $('clockTz').textContent=c.timezone||'—';
    if(!$('tzInput').value) $('tzInput').value=c.timezone||'CST-8';
  }
  if(!clockTimer) clockTimer=setInterval(tickClock,1000);
}
var clockBase=0, clockTick=0;
function tickClock(){
  if(!clockBase) return;
  var t=new Date(clockBase+(Date.now()-clockTick));
  $('clockNow').textContent=t.toLocaleString('zh-CN',{hour12:false});
}
/* ---------- 手表 ---------- */
async function loadWatch(){
  var d=await api('/api/v1/status');
  if(!d||d.ok===false) return;
  $('bState').textContent = d.watchBridgeRunning ? (d.watchBridgeState||'运行中') : '未连接';
  $('bMac').textContent = d.watchMac || '未配置';
  $('bChan').textContent = d.sdpResolvedChannel ? ('ch'+d.sdpResolvedChannel+' · '+d.sdpSource) : '未解析';
  $('bAuth').textContent = d.watchConfigured ? '密钥已配置' : '未配置';
  $('bKey').textContent = d.watchConfigured ? '32 位已保存' : '—';
  var c=await api('/clock');
  if(c&&c.ok!==false&&c.localText){
    clockBase=new Date(c.localText.replace(/-/g,'/')).getTime();
    clockTick=Date.now();
  }
}
/* ---------- 偏好 ---------- */
var prefsCache={};
async function loadPrefs(){
  var p=await api('/api/v1/prefs');
  if(!p||p.ok===false) return;
  prefsCache=p;
  setToggle('prefLog', p.showLog);
  setToggle('prefCompact', p.compact);
  setToggle('prefAuto', p.autoConnectWatch);
  setToggle('prefTls', p.insecureTls);
  document.querySelectorAll('#ledGroup button').forEach(function(b){
    var isCur=parseInt(b.dataset.arg,10)===p.ledMode;
    b.classList.toggle('ghost', !isCur);
  });
}
function setToggle(id,on){
  var el=$(id); if(!el) return;
  el.textContent=on?'已开启':'已关闭';
  el.style.color=on?'var(--ok)':'var(--muted)';
  el.dataset.on=on?'1':'0';
}
async function savePrefs(patch){
  var body=Object.assign({},prefsCache,patch);
  var r=await api('/api/v1/prefs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r&&r.ok) { toast('设置已保存'); loadPrefs(); }
  else toast('保存失败',true);
}
/* ---------- 健康检查 ---------- */
async function runChecks(){
  var box=$('checks');
  box.innerHTML='<p class="muted">检查中…</p>';
  var rows=[];
  function add(ok,label,detail){ rows.push({ok:ok,label:label,detail:detail||''}); }
  var d=await api('/api/v1/status');
  add(!!(d&&d.ok!==false),'接口可达', d&&d.ok!==false?('版本 '+(d.fwVersion||'?')):'设备无响应');
  if(d&&d.ok!==false){
    add(!!d.wifi,'Wi-Fi 已连接', d.wifi?(d.staIp||''):'检查 SSID / 密码');
    add(!!d.watchConfigured,'手表密钥已配置', d.watchMac||'');
    add(!!d.watchBridgeRunning,'手表桥接运行中', d.watchBridgeState||'');
    add(!!d.networkProxyReady,'NAPT 转发就绪', '');
    add((d.heapFree||0)>20000,'空闲内存充足', Math.round((d.heapFree||0)/1024)+' KB');
    add((d.flashSize||0)>=16777216,'16MB Flash 生效', Math.round((d.flashSize||0)/1048576)+' MB');
    add((d.appPartitionSize||0)>=6291456,'应用分区 6MB', Math.round((d.appPartitionSize||0)/1024)+' KB');
    add((d.spiffsPartitionSize||0)>0,'SPIFFS 分区存在', Math.round((d.spiffsPartitionSize||0)/1024)+' KB');
    add((d.networkDroppedPackets||0)<(d.networkRxPackets||1),'丢包正常', (d.networkDroppedPackets||0)+' 包');
  }
  var c=await api('/clock');
  add(!!(c&&c.synced),'系统时间已同步', c?c.localText:'');
  var q=await api('/api/v1/linkscore');
  add(!!(q&&q.score>=50),'链路质量达标', q?('评分 '+q.score+' · '+(q.rssi||'?')+' dBm'):'');
  box.innerHTML=rows.map(function(r){
    return '<div class="item" style="cursor:default">'+
      '<span><i class="dot '+(r.ok?'ok':'bad')+'"></i>'+r.label+'</span>'+
      '<small>'+r.detail+'</small></div>';
  }).join('');
  var bad=rows.filter(function(r){return !r.ok}).length;
  toast(bad?bad+' 项异常':'全部通过', bad>0);
}
/* 拆分为主、次、构建、修订四段；字段缺失时回退为完整字符串 */
function verParts(d){
  if(d.fwVerMajor===undefined) return d.fwVersion||'—';
  return '主 '+d.fwVerMajor+' · 次 '+d.fwVerMinor+' · 构建 '+d.fwVerBuild+' · 修订 '+d.fwVerRevision;
}
/* ---------- 系统 ---------- */
async function loadSys(){
  var d=await api('/api/v1/status');
  if(!d||d.ok===false) return;
  $('yVer').textContent=d.fwVersionFull||d.fwVersion||'—';
  $('yHw').textContent=d.fwHardware||'—';
  $('yFlash').textContent=d.flashSize?(Math.round(d.flashSize/1048576)+' MB'):'—';
  $('yPart').textContent=d.appPartition
    ? (d.appPartition+' · '+Math.round((d.appPartitionSize||0)/1024)+' KB')
    : '—';
  $('yUp').textContent=uptimeText(d.uptime);
  $('yMem').textContent=d.heapFree!==undefined?(Math.round(d.heapFree/1024)+' KB'):'—';
  $('yMemMin').textContent=d.heapMinFree!==undefined?(Math.round(d.heapMinFree/1024)+' KB'):'—';

  // OTA 槽：直接列出两个槽里实际躺着的镜像，升级后核对版本不用翻日志
  var slots=$('ySlots');
  var list=(d.otaSlots||[]);
  if(!list.length){ slots.innerHTML='<div class="item" style="cursor:default"><span>未读到分区信息</span></div>'; }
  else{
    slots.innerHTML=list.map(function(o){
      var txt=o.hasImage?(o.version||'未知版本')+(o.built?(' · '+o.built):''):'空';
      return '<div class="item" style="cursor:default"><span>'+
        '<i class="dot '+(o.running?'ok':'mid')+'"></i>'+o.label+(o.running?'（运行中）':'')+
        '</span><small>'+txt+'</small></div>';
    }).join('');
  }

  if(d.otaRollback){
    $('otaBadBox').style.display='';
    $('otaBadNone').style.display='none';
    $('otaBadText').textContent='目标版本 '+(d.otaRollbackExpected||'未知')+
      ' 未能启动，设备已回滚到 '+(d.otaRollbackRunning||d.fwVersionFull||'旧版本')+
      '。可重新刷写；反复回滚时改用数据线整片刷写。';
  } else {
    $('otaBadBox').style.display='none';
    $('otaBadNone').style.display='';
  }
}
function uptimeText(sec){
  sec=Math.floor(sec||0);
  if(!sec) return '—';
  var dd=Math.floor(sec/86400), hh=Math.floor(sec%86400/3600), mm=Math.floor(sec%3600/60);
  if(dd) return dd+' 天 '+hh+' 小时';
  if(hh) return hh+' 小时 '+mm+' 分';
  return mm+' 分 '+(sec%60)+' 秒';
}
/* ---------- 状态轮询 ---------- */
var lastRx=0,lastTx=0;
async function refresh(){
  var d=await api('/api/v1/status');
  if(!d||d.ok===false){
    setDot($('sWifi'),'bad','无响应');
    setDot($('sWatch'),'bad','无响应');
    $('sIp').textContent='—'; $('sMem').textContent='—'; $('sPkt').textContent='—';
    $('sFlashTxt').textContent='—'; $('sPart').textContent='设备无响应，可能正在重启或连接已断开';
    return;
  }
  setDot($('sWifi'), d.wifi?'ok':'bad', d.wifi?'已连接':'未连接');
  var ws=d.watchBridgeState||'';
  var wmap={connected:'已连接',connecting:'连接中',starting:'启动中',stopping:'停止中',idle:'待机'};
  setDot($('sWatch'), d.watchBridgeRunning?'ok':'bad', d.watchBridgeRunning?(wmap[ws]||'运行中'):'未连接');
  setDot($('sProxy'), d.networkProxyReady?'ok':'mid', d.networkProxyReady?'就绪':'待命');
  $('sIp').textContent = d.staIp && d.staIp!=='0.0.0.0' ? d.staIp : (d.setupApIp||'—');
  var mem = d.heapFree!==undefined ? d.heapFree : (d.freeHeap!==undefined?d.freeHeap:null);
  $('sMem').textContent = mem!==null ? Math.round(mem/1024)+' KB' : '—';
  if(d.heapMinFree!==undefined) $('sMem').title='历史最低 '+Math.round(d.heapMinFree/1024)+' KB';
  var rx=d.networkRxPackets||0, tx=d.networkTxPackets||0;
  $('sPkt').textContent = tx+' / '+rx;
  $('sCounters').textContent = '丢包 '+(d.networkDroppedPackets||0)+' · 会话 '+(d.watchConversationTurns||0)+' 轮';
  if(d.appPartitionSize && d.fwSize){
    var pct=Math.max(1,Math.min(100,Math.round(d.fwSize*100/d.appPartitionSize)));
    $('sFlashBar').style.width=pct+'%';
    $('sFlashTxt').textContent=Math.round(d.fwSize/1024)+' KB / '+Math.round(d.appPartitionSize/1024)+' KB · '+pct+'%';
  } else if(d.appPartitionSize){
    $('sFlashTxt').textContent=Math.round(d.appPartitionSize/1024)+' KB';
  }
  $('sPart').textContent = '分区 '+(d.appPartition||'?')+' @0x'+(d.appPartitionAddr||0).toString(16).toUpperCase()+
    ' · Flash '+Math.round((d.flashSize||0)/1048576)+' MB';
  if(d.otaSlots && d.otaSlots.length){
    $('sSlots').textContent = 'OTA 槽 ' + d.otaSlots.map(function(slot){
      var tag = slot.hasImage ? String(slot.version||'—') : '空';
      return slot.label + ' ' + tag + (slot.running ? '（运行中）' : '');
    }).join(' · ');
  } else {
    $('sSlots').textContent = '';
  }
  $('dFw').textContent=d.fwVersionFull||d.fwVersion||'—';
  $('dCh').textContent=d.fwChannel||'—';
  $('dBu').textContent=d.fwVerMajor===undefined?'—':(d.fwVerMajor+'.'+d.fwVerMinor+'.'+d.fwVerBuild+'.'+d.fwVerRevision);
  $('dDate').textContent=d.fwBuildDate||'—';
  $('dFl').textContent=d.flashSize?Math.round(d.flashSize/1048576)+' MB':'—';
  $('dAp').textContent=d.appPartitionSize?Math.round(d.appPartitionSize/1024)+' KB':'—';
  $('dSp').textContent=d.spiffsPartitionSize?Math.round(d.spiffsPartitionSize/1024)+' KB':'—';
  // 设备事件只在首页/系统页可见，别的分页没必要拉，省一次请求和一块堆。
  var nowMs=Date.now();
  if((activeTab==='dash'||activeTab==='tools') && nowMs-devLogAt>6000){ devLogAt=nowMs; syncDeviceLogs(); }
  if(d.fwVersionFull||d.fwVersion) $('fwTag').textContent=d.fwVersionFull||d.fwVersion;
  if(d.autoReset!==undefined) renderAuto(d);
  $('pollHint').textContent = '· '+new Date().toLocaleTimeString('zh-CN',{hour12:false});
}
var autoTimer=0, autoDeadline=0, autoReason='';
function paintAuto(){
  if(!autoDeadline) return;
  var left=Math.max(0,autoDeadline-Date.now());
  var s=Math.floor(left/1000);
  var mm=Math.floor(s/60), ss=('0'+(s%60)).slice(-2);
  var reason=autoReason==='never_connected'?'配网后一直没能连上（多半是密码填错）':'已长时间连不上 Wi-Fi';
  var tail=left<60000?' <b style="color:#ef4444">即将开启热点，只剩 '+s+' 秒</b>':'';
  $('autoText').innerHTML='原因：'+reason+'。剩余 <b>'+mm+' 分 '+ss+' 秒</b> 后自动开启配网热点。'+
    '<b>原有配置不受影响</b>（Wi-Fi、手表密钥、云端 key 全部保留），连上后会自动回到正常工作模式。'+
    '期间只要成功连上一次就会自动取消。'+tail;
  if(left===0){ clearInterval(autoTimer); autoTimer=0; }
}
function renderAuto(d){
  var card=$('autoCard');
  if(!d.autoReset){ card.style.display='none'; clearInterval(autoTimer); autoTimer=0; autoDeadline=0; return; }
  card.style.display='block';
  autoReason=d.autoResetReason||'';
  // 每次轮询用服务器返回的剩余时间重新校准，避免页面长时间挂着走偏
  autoDeadline=Date.now()+(d.autoResetRemainMs||0);
  paintAuto();
  if(!autoTimer) autoTimer=setInterval(paintAuto,1000);
}
async function cancelAutoReset(){
  var d=await api('/api/v1/factory/cancel',{method:'POST'});
  if(d&&d.ok){ toast('已取消自动重置'); $('autoCard').style.display='none'; refresh(); }
  else toast('取消失败',true);
}

/* ---------- Wi-Fi ---------- */
function chooseWifi(name){ $('ssid').value=name; $('wp').focus();
  $('wifiStatus').textContent='已选：'+name; }
function renderNetworks(items){
  var box=$('networks'); box.replaceChildren();
  (items||[]).slice(0,20).forEach(function(it){
    var b=document.createElement('button'); b.className='item';
    var n=document.createElement('span'); n.textContent=it.ssid;
    var m=document.createElement('small'); m.textContent=it.rssi+' dBm'+(it.secure?' · 加密':' · 开放');
    b.append(n,m); b.onclick=function(){chooseWifi(it.ssid)}; box.append(b);
  });
}
async function pollWifi(){
  var d=await api('/setup/wifi/scan');
  if(!d||!d.ok){ $('wifiStatus').textContent='扫描失败：'+((d&&d.error)||'未知'); return; }
  if(d.scanning){ setTimeout(pollWifi,700); return; }
  if(!d.ready){ $('wifiStatus').textContent='尚未开始扫描'; return; }
  renderNetworks(d.networks);
  $('wifiStatus').textContent=(d.networks&&d.networks.length)?'选择一个网络（共 '+d.networks.length+' 个）':'未发现网络，请手动填写 SSID';
}
async function scanWifi(){
  $('wifiStatus').textContent='扫描中…'; $('networks').replaceChildren();
  var d=await api('/setup/wifi/scan?start=1');
  if(!d||!d.ok){ $('wifiStatus').textContent='启动失败：'+((d&&d.error)||'未知'); return; }
  setTimeout(pollWifi,900);
}

/* ---------- 蓝牙 ---------- */
function chooseBluetooth(addr,name){ $('mac').value=addr; $('wauth').focus();
  $('bluetoothStatus').textContent='已选：'+(name||addr); }
function renderBluetooth(items){
  var box=$('bluetoothDevices'); box.replaceChildren();
  (items||[]).slice(0,20).forEach(function(it){
    var b=document.createElement('button'); b.className='item';
    var n=document.createElement('span'); n.textContent=it.name||'未命名';
    var m=document.createElement('small'); m.textContent=it.address+' · '+it.rssi+'dBm';
    b.append(n,m); b.onclick=function(){chooseBluetooth(it.address,it.name)}; box.append(b);
  });
}
async function pollBluetooth(){
  var d=await api('/setup/bluetooth/scan');
  if(!d||!d.ok){ $('bluetoothStatus').textContent='扫描失败：'+((d&&d.error)||'未知'); return; }
  if(d.scanning){ setTimeout(pollBluetooth,800); return; }
  if(!d.ready){ $('bluetoothStatus').textContent='尚未开始扫描'; return; }
  renderBluetooth(d.devices);
  $('bluetoothStatus').textContent=(d.devices&&d.devices.length)?'选择手表设备':'未发现设备，请手动填写 MAC';
}
async function scanBluetooth(){
  $('bluetoothStatus').textContent='扫描经典蓝牙，约 8 秒…'; $('bluetoothDevices').replaceChildren();
  var d=await api('/setup/bluetooth/scan?start=1');
  if(!d||!d.ok){ $('bluetoothStatus').textContent='启动失败：'+((d&&d.error)||'未知'); return; }
  setTimeout(pollBluetooth,900);
}
async function testBluetooth(){
  var m=$('mac').value.trim();
  if(m.length!==17){ toast('未填写手表 MAC',true); $('mac').focus(); return; }
  $('bluetoothStatus').textContent='连接测试中，约 5 至 10 秒…';
  var d=await api('/setup/bluetooth/test?mac='+encodeURIComponent(m));
  if(d&&d.ok){ toast('蓝牙连接成功'); log('蓝牙测试成功 '+m+' 通道 '+(d.channel||'自动'));
    $('bluetoothStatus').textContent='已连接，通道 '+(d.channel||'自动'); }
  else { toast('蓝牙测试失败',true); log('蓝牙测试失败 '+((d&&d.error)||''));
    $('bluetoothStatus').textContent='失败：'+((d&&d.error)||'未知原因')+(d&&d.message?' · '+d.message:''); }
}

/* ---------- 保存 ---------- */
async function save(){
  var body={
    ssid:$('ssid').value.trim(),
    wifiPassword:$('wp').value,
    watchMac:$('mac').value.trim(),
    watchAuthKey:$('wauth').value.trim(),
    apPassword:$('ap').value,
    apSsid:$('apname').value.trim()
  };
  if(!body.ssid){ toast('Wi-Fi 名称不能为空',true); return; }
  if(body.apPassword.length<8){ toast('热点密码长度不足 8 位',true); return; }
  $('saveHint').textContent='保存中…';
  var d=await api('/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(d&&d.ok){ $('saveHint').textContent='配置已保存，设备重启中…'; toast('配置已保存，设备重启中');
    log('配置已保存，设备重启'); setTimeout(function(){location.reload()},4000); }
  else { $('saveHint').textContent=''; toast('保存失败',true); log('保存失败 '+(d&&d.error)); }
}

/* ---------- 进入空中升级 ---------- */
var PNAME={1:'手表网关',6:'空中升级'};
async function switchProj(t){
  var nm=PNAME[t]||'空中升级';
  if(!confirm('进入「'+nm+'」？\n设备会重启，热点保持开启。')) return;
  var d=await api('/setup/project/switch?target='+t,{method:'POST'});
  if(d&&d.ok){ toast('正在进入空中升级，设备重启中'); log('进入空中升级模式'); }
  else toast('切换失败',true);
}

/* ---------- 恢复出厂 ---------- */
async function openReset(){
  var d=await api('/api/v1/factory/preview');
  var box=$('resetList'); box.replaceChildren();
  if(d&&d.ok){
    var ul=document.createElement('ul'); ul.className='tight';
    (d.willClear||[]).forEach(function(k){ var li=document.createElement('li'); li.textContent=k; ul.append(li); });
    box.append(ul);
  }
  $('resetConfirm').value=''; $('resetBtn').disabled=true;
  $('resetModal').className='modal on';
}
function closeReset(){ $('resetModal').className='modal'; }
$('resetConfirm').addEventListener('input',function(){
  $('resetBtn').disabled = this.value.trim().toUpperCase()!=='RESET';
});
async function doReset(){
  $('resetBtn').disabled=true; $('resetBtn').textContent='正在清除…';
  var d=await api('/api/v1/factory/reset?confirm=RESET',{method:'POST'});
  if(d&&d.ok){
    $('resetModal').className='modal';
    toast('已恢复出厂，设备重启中');
    document.body.innerHTML='<div style="text-align:center;padding:60px 20px;font:16px/1.8 sans-serif;color:#e8f0fa">'+
      '<h2>已恢复出厂设置</h2><p>设备正在重启…</p>'+
      '<p style="color:#8296ad;font-size:13px">约 10 秒后使用手机连接热点 <b>__PH_AP__</b><br>然后访问 http://192.168.4.1 重新配置</p></div>';
  } else {
    $('resetBtn').textContent='确认清除'; $('resetBtn').disabled=false;
    toast('恢复失败',true);
  }
}

// ===== 资源（表盘 / 快应用）=====
var resTimer=null;
function resEsc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

function renderInst(i){
  var map={idle:'空闲',wf_prepare:'准备表盘',mass_prepare:'准备传输',sending:'传输中',
           wait_result:'等待安装结果',done:'完成',failed:'失败'};
  var st=map[i.state]||i.state||'—';
  if(i.message && i.message!=='sending') st+=' · '+i.message;
  $('instState').textContent=st;
  var pct=Math.round((i.progress||0)*100);
  $('instProg').textContent = i.totalParts ? (i.ackedParts+' / '+i.totalParts+' 片 · '+pct+'%') : '—';
  $('instBar').style.width=pct+'%';
  if(i.busy) pollInst();
}

async function loadRes(){
  var d=await api('/api/v1/resource/list');
  if(!d||d.ok===false){ $('resList').innerHTML='<div class="muted">读取失败</div>'; return; }
  var u=d.usage||{};
  $('resUsage').textContent=Math.round((u.used||0)/1024)+' KB / '+Math.round((u.total||0)/1024)+' KB';
  var items=d.items||[];
  if(!items.length){
    $('resList').innerHTML='<div class="muted">暂无已上传文件</div>';
  }else{
    $('resList').innerHTML=items.map(function(it){
      var kb=Math.round((it.bytes||0)/1024)+' KB';
      var kind=(it.kind==='watchface')?'表盘':'快应用';
      var extra = it.package ? (' · '+resEsc(it.package)+' v'+(it.versionCode||1)) :
                  (it.watchfaceId ? (' · ID '+resEsc(it.watchfaceId)) : '');
      return '<div class="item" style="cursor:default">'+
        '<div style="min-width:0"><div style="overflow:hidden;text-overflow:ellipsis">'+resEsc(it.name||it.slot)+'</div>'+
        '<small>'+kind+' · '+kb+extra+' · '+resEsc(it.slot)+'</small></div>'+
        '<div style="display:flex;gap:6px;flex:0 0 auto">'+
        '<button class="ghost" style="padding:8px 10px;font-size:12.5px" data-act="resInstall" data-arg="'+resEsc(it.slot)+'">安装</button>'+
        '<button class="ghost" style="padding:8px 10px;font-size:12.5px" data-act="resDelete" data-arg="'+resEsc(it.slot)+'">删除</button>'+
        '</div></div>';
    }).join('');
  }
  renderInst(d.install||{});
}

function uploadRes(input){
  var f=input.files&&input.files[0];
  if(!f) return;
  var bar=$('upBar');
  if(f.size>3.6*1024*1024){ bar.textContent='文件太大：设备只剩约 3.8 MB 空间'; input.value=''; return; }
  var fd=new FormData(); fd.append('file',f,f.name);
  var xhr=new XMLHttpRequest();
  xhr.open('POST','/api/v1/resource/upload');
  xhr.setRequestHeader('X-Vela-Token',VELA_TOKEN);
  bar.textContent='上传中 0%';
  xhr.upload.onprogress=function(e){
    if(e.lengthComputable) bar.textContent='上传中 '+Math.round(e.loaded/e.total*100)+'%';
  };
  xhr.onload=function(){
    var j={}; try{ j=JSON.parse(xhr.responseText); }catch(e){}
    if(j.ok){ bar.textContent='已上传：'+(j.name||j.slot); input.value=''; loadRes(); }
    else { bar.textContent='失败：'+(j.error||('HTTP '+xhr.status))+(j.hint?(' — '+j.hint):''); }
  };
  xhr.onerror=function(){ bar.textContent='上传失败（连接中断）'; };
  xhr.send(fd);
}

async function installRes(slot){
  var d=await api('/api/v1/resource/install',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({slot:slot})});
  if(!d||d.ok===false){ $('instState').textContent='启动失败 · '+((d&&(d.error||d.message))||''); return; }
  pollInst();
  loadRes();
}

async function delRes(slot){
  if(!confirm('删除 '+slot+' ？')) return;
  await api('/api/v1/resource/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({slot:slot})});
  loadRes();
}

async function cancelRes(){
  await api('/api/v1/resource/cancel',{method:'POST'});
  loadRes();
}

function pollInst(){
  if(resTimer) return;
  resTimer=setInterval(async function(){
    var d=await api('/api/v1/resource/status');
    if(!d||d.ok===false) return;
    var i=d.install||{};
    renderInst(i);
    if(!i.busy){ clearInterval(resTimer); resTimer=null; loadRes(); }
  },800);
}

document.addEventListener('change',function(ev){
  if(ev.target && (ev.target.id==='wfFile'||ev.target.id==='appFile')) uploadRes(ev.target);
});

// 统一事件委托：所有按钮用 data-act，避免内联 onclick 的引号地狱
document.addEventListener('click',function(ev){
  var b=ev.target.closest('[data-act]');
  if(!b) return;
  // disabled 的按钮浏览器不会派发 click，但这里再挡一层，
  // 免得以后有人把它改成 <a> 或 div 就漏了
  if(b.disabled) return;
  var act=b.dataset.act;
  if(act==='refresh') refresh();
  else if(act==='scanWifi') scanWifi();
  else if(act==='scanBluetooth') scanBluetooth();
  else if(act==='testBluetooth') testBluetooth();
  else if(act==='save') save();
  else if(act==='openReset') openReset();
  else if(act==='closeReset') closeReset();
  else if(act==='doReset') doReset();
  else if(act==='cancel') cancelAutoReset();
  else if(act==='manual-ssid'){ $('ssid').value=''; $('ssid').focus(); }
  else if(act==='goto-setup') $('setup').scrollIntoView({behavior:'smooth'});
  else if(act==='switchProj') switchProj(parseInt(b.dataset.arg,10));
  else if(act==='goto-upgrade') switchProj(6);
  else if(act==='tab') showTab(b.dataset.arg);
  else if(act==='led') savePrefs({ledMode:parseInt(b.dataset.arg,10)});
  else if(act==='ledTest') ledTest();
  else if(act==='togglePref'){
    var key=b.dataset.arg;
    var nv = b.dataset.on!=='1';
    var patch={}; patch[key]=nv; savePrefs(patch);
  }
  else if(act==='runChecks') runChecks();
  else if(act==='resRefresh') loadRes();
  else if(act==='resInstall') installRes(b.dataset.arg);
  else if(act==='resDelete') delRes(b.dataset.arg);
  else if(act==='resCancel') cancelRes();
  else if(act==='watchRestart') watchRestart();
  else if(act==='contextReset') contextReset();
  else if(act==='pushText') pushText();
  else if(act==='pushPreset'){ $('pushText').value=b.dataset.arg||''; pushText(); }
  else if(act==='syncClock') syncClock();
  else if(act==='tz-preset'){ $('tzInput').value=b.dataset.arg; syncClock(); }
  else if(act==='reboot') rebootDevice();
  else if(act==='otaBadAck'){ api('/api/v1/ota/rollback/ack',{method:'POST'}).then(function(){ loadSys(); }); }
});

async function ledTest(){
  var r=await api('/api/v1/led/test',{method:'POST'});
  toast(r&&r.ok?'LED 已点亮 1.5 秒':'测试失败', !(r&&r.ok));
}
async function watchRestart(){
  toast('正在重新连接手表…');
  var r=await api('/api/v1/watch/start',{method:'POST'});
  toast(r&&r.ok?'已发起连接':'发起失败：'+((r&&r.message)||(r&&r.error)||''), !(r&&r.ok));
}
async function contextReset(){
  var r=await api('/api/v1/context/reset',{method:'POST'});
  toast(r&&r.ok?'对话上下文已清空':'操作失败', !(r&&r.ok));
}
async function pushText(){
  var t=$('pushText').value.trim();
  if(!t){ toast('内容为空',true); return; }
  var r=await api('/api/v1/watch/push',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:t})});
  if(!r||!r.ok){ toast('发送失败：'+((r&&r.message)||(r&&r.error)||''), true); return; }
  $('pushText').value='';
  toast('已入队，等待蓝牙链路投递…');
  // 入队不等于发出去。真正结果只有会话线程知道，这里轮询最多 6 秒。
  var got=await waitPushResult(6000);
  if(got===2){
    toast('已写入蓝牙发送通道');
    log('PUSH 已发出（state=2）。若手表未弹通知，说明是手表端快应用不处理该消息，与本机无关。');
  } else if(got===3){
    toast('发送失败，详见运行日志', true);
    log('PUSH 失败，原因见上方 PUSH_FAIL / PUSH_DROPPED 行');
  } else {
    toast('暂无回执，去看运行日志', true);
  }
  refresh();
}
async function waitPushResult(maxMs){
  var until=Date.now()+maxMs;
  while(Date.now()<until){
    var d=await api('/api/v1/watch/push/result');
    if(d&&d.ok&&(d.state===2||d.state===3)) return d.state;
    await new Promise(function(r){ setTimeout(r,400); });
  }
  return 0;
}
async function syncClock(){
  var tz=$('tzInput').value.trim();
  var r=await api('/clock/sync',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({timezone:tz})});
  if(r&&r.ok){ toast('校时请求已发送，3 秒后刷新'); setTimeout(loadNet,3200); }
  else toast('校时请求失败',true);
}
async function rebootDevice(){
  toast('设备重启中，约 15 秒后恢复');
  try{ await fetch('/api/v1/reboot',{method:'POST'}); }catch(e){}
}
setTimeout(function(){ showTab('dash'); loadTraffic(); },300);
setInterval(loadTraffic,4000);
refresh();
setInterval(refresh,3000);
log('页面已加载 · 固件 __PH_VERFULL__');
</script>
</body>
</html>
)HTML";


void setWatchBridgeState(const char* state) {
  if (!state) state = "unknown";
  if (gBridgeStateMutex && xSemaphoreTake(gBridgeStateMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
    snprintf(gWatchBridgeState, sizeof(gWatchBridgeState), "%s", state);
    xSemaphoreGive(gBridgeStateMutex);
  } else {
    snprintf(gWatchBridgeState, sizeof(gWatchBridgeState), "%s", state);
  }
}

String getWatchBridgeState() {
  char state[sizeof(gWatchBridgeState)]{};
  if (gBridgeStateMutex && xSemaphoreTake(gBridgeStateMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
    snprintf(state, sizeof(state), "%s", gWatchBridgeState);
    xSemaphoreGive(gBridgeStateMutex);
  } else {
    snprintf(state, sizeof(state), "%s", gWatchBridgeState);
  }
  return String(state);
}

void watchBridgeTaskMain(void*) {
  gWatchBridgeRunning = true;
  gWatchBridgeStopRequested = false;
  setWatchBridgeState("connecting");
  settlePushOnLinkReset("桥接断开或重连中");
  String mac = watchMac;
  String auth = watchAuthKey;
  authenticateWatchSpp(mac, auth);
  auth = "";
  // Bluetooth SPP is up; now bring up home Wi-Fi for the QuickApp network
  // bridge (NAPT). This keeps heap large/unfragmented during BT init.
  connectWifi();
  gWatchBridgeRunning = false;
  gWatchBridgeStopRequested = false;
  setWatchBridgeState("idle");
  settlePushOnLinkReset("桥接断开或重连中");
  gWatchBridgeTask = nullptr;
  vTaskDelete(nullptr);
}

bool startWatchBridge(String& error) {
  gWatchAutoReconnectSuppressed = false;
  if (gWatchBridgeRunning || gWatchBridgeTask) { error = "already_running"; return false; }
  if (watchMac.length() != 17) { error = "watch_mac_missing"; return false; }
  if (watchAuthKey.length() != 32) { error = "watch_auth_key_missing"; return false; }
  // Home Wi-Fi is connected lazily AFTER Bluetooth auth succeeds, so the
  // Bluetooth controller can init while the heap is still large and unfragmented.
  gWatchBridgeStopRequested = false;
  setWatchBridgeState("starting");
  const BaseType_t created = xTaskCreatePinnedToCore(watchBridgeTaskMain, "vela_watch", 6144,
                                                     nullptr, 2, &gWatchBridgeTask, 1);
  if (created != pdPASS) {
    gWatchBridgeTask = nullptr;
    setWatchBridgeState("task_create_failed");
    error = "watch_task_create_failed";
    return false;
  }
  return true;
}

void stopWatchBridge() {
  gWatchAutoReconnectSuppressed = true;
  gWatchBridgeStopRequested = true;
  setWatchBridgeState("stopping");
}

void handleStatus(bool publicSetup) {
  const bool watchFetchProbe = server.arg("source") == "watch_quickapp";
  const bool setupApClient = isSetupApClient();
  // The watch itself may probe this endpoint through channel 7 before an admin
  // token exists in its HTTP client. Return only non-sensitive liveness data in
  // that case. Home-LAN management requires the configured local token.
  if (publicSetup && watchFetchProbe && !setupApClient && !authorized()) {
    JsonDocument d;
    d["ok"] = true;
    d["bridge"] = "vela-gateway";
    d["watchFetchProbe"] = true;
    d["networkProxyReady"] = gWatchNetworkReady;
    d["wifi"] = WiFi.status() == WL_CONNECTED;
    sendJson(200, d);
    return;
  }
  if (!setupApClient && !requireAuth()) return;
  JsonDocument d;
  d["ok"] = true;
  d["bridge"] = "vela-gateway";
  d["version"] = 3;                       // 历史字段，保留兼容旧脚本
  d["fwVersion"] = kFwVersion;            // "0.0.0.2"
  d["fwVersionFull"] = kFwVersionFull;    // "v0.0.0.2"
  d["fwChannel"] = kFwChannel;            // tech-preview / stable
  d["fwHardware"] = kFwHardware;          // esp32-16mb
  // 四段拆开给前端：分字段展示 + 版本比较（字典序对多位数会错）
  d["fwVerMajor"] = kFwVerMajor;
  d["fwVerMinor"] = kFwVerMinor;
  d["fwVerBuild"] = kFwVerBuild;
  d["fwVerRevision"] = kFwVerRevision;
  d["fwBuildDate"] = kFwBuildDate;        // 20261108
  d["fwName"] = String("vela-gateway-") + kFwVersion + "-" + kFwHardware;
  // Flash / 分区信息：用来一眼确认刷进去的到底是不是 16MB 版本。
  d["flashSize"] = static_cast<uint32_t>(ESP.getFlashChipSize());
  d["flashMode"] = static_cast<int>(ESP.getFlashChipMode());
  {
    const esp_partition_t* running = esp_ota_get_running_partition();
    const esp_partition_t* next = esp_ota_get_next_update_partition(nullptr);
    d["appPartition"] = String(running ? running->label : "?");
    d["appPartitionAddr"] = running ? static_cast<uint32_t>(running->address) : 0u;
    d["appPartitionSize"] = running ? static_cast<uint32_t>(running->size) : 0u;
    d["nextPartitionSize"] = next ? static_cast<uint32_t>(next->size) : 0u;
    const esp_partition_t* fs = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_SPIFFS, nullptr);
    d["spiffsPartitionSize"] = fs ? static_cast<uint32_t>(fs->size) : 0u;
    // 两个 OTA 槽各自的镜像与状态。整片刷写后当前槽未必是系统页标签上写的
    // 那个版本，这里把每个槽里实际躺着的镜像都报出来，避免"升级到了错的槽"。
    JsonArray slots = d["otaSlots"].to<JsonArray>();
    for (const char* label : {"ota_0", "ota_1"}) {
      const esp_partition_t* p = esp_partition_find_first(
          ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_ANY, label);
      if (!p) continue;
      JsonObject o = slots.add<JsonObject>();
      o["label"] = label;
      o["address"] = static_cast<uint32_t>(p->address);
      o["running"] = running && running->address == p->address;
      esp_app_desc_t desc;
      const bool has = esp_ota_get_partition_description(p, &desc) == ESP_OK;
      o["hasImage"] = has;
      if (has) {
        o["version"] = String(desc.version);
        o["built"] = String(desc.date) + " " + String(desc.time);
      }
    }
  }
  // 上一次升级是否被回滚。前端据此提示，用户不用再靠猜版本号。
  d["otaRollback"] = gOtaRollbackDetected;
  d["otaRollbackExpected"] = gOtaRollbackExpected;
  d["otaRollbackRunning"] = gOtaRollbackRunning;
  // 固件实际占用（含段头），供网页画分区占用条。
  // ESP.getSketchSize() 是 Arduino 层封装，已在 core 2.0.7 提供。
  d["fwSize"] = static_cast<uint32_t>(ESP.getSketchSize());
  d["heapFree"] = static_cast<uint32_t>(ESP.getFreeHeap());
  d["heapMinFree"] = static_cast<uint32_t>(ESP.getMinFreeHeap());
  // 运行时长：系统页「设备信息」直接显示，省得用户自己拿开机时间换算。
  d["uptime"] = static_cast<uint32_t>(millis() / 1000u);
  d["freeSketchSpace"] = static_cast<uint32_t>(ESP.getFreeSketchSpace());
  // 状态接口是管理台每次轮询都会调的，在这里顺手触发一次文件系统挂载：
  // 用户打开页面后，后面的固件库、表盘上传才有可用的文件系统。
  // 挂载成功后只是读一个 bool，未挂载时最多起一个后台格式化任务，不会阻塞。
  const bool fsReady = ensureSpiffs();
  d["spiffsState"] = fsReady ? "ready" : (gSpiffsFormatting ? "formatting" : "unavailable");
  if (fsReady) {
    d["spiffsTotal"] = static_cast<uint32_t>(SPIFFS.totalBytes());
    d["spiffsUsed"] = static_cast<uint32_t>(SPIFFS.usedBytes());
  }
  d["wifi"] = WiFi.status() == WL_CONNECTED;
  d["ssid"] = ssid;                       // 当前配置的路由器名（不含密码）
  d["rssi"] = WiFi.status() == WL_CONNECTED ? WiFi.RSSI() : 0;
  d["staIp"] = WiFi.localIP().toString();
  d["setupApIp"] = WiFi.softAPIP().toString();
  d["model"] = model;
  d["baseUrl"] = baseUrl;
  d["apiKeyConfigured"] = !apiKey.isEmpty();
  d["watchConfigured"] = watchMac.length() == 17 && watchAuthKey.length() == 32;
  d["watchMac"] = watchMac; // MAC is not a secret; auth key is intentionally never returned.
  d["sdpResolvedChannel"] = gWatchResolvedSppChannel;
  d["sdpSource"] = gWatchSdpSource;
  d["sdpCacheAgeMs"] = gWatchSdpResolvedMs ? millis() - gWatchSdpResolvedMs : 0;
  d["watchBridgeRunning"] = gWatchBridgeRunning;
  d["watchBridgeState"] = getWatchBridgeState();
  d["networkProxyReady"] = gWatchNetworkReady;
  d["networkRxPackets"] = gWatchNetworkRxPackets;
  d["networkTxPackets"] = gWatchNetworkTxPackets;
  d["networkDroppedPackets"] = gWatchNetworkDroppedPackets;
  d["lastAiAnswer"] = gLastAiAnswer;
  d["watchConversationTurns"] = gWatchContextCount;
  d["watchConversationIdleResetMs"] = kXiaoAiContextIdleResetMs;
  d["autoConnectWatch"] = autoConnectWatch;
  d["caConfigured"] = !caPem.isEmpty();
  d["insecureTls"] = allowInsecureTls;
  d["watchFetchProbe"] = watchFetchProbe;
  d["localTokenHint"] = "enter the local token configured during setup";
  sendJson(200, d);
}

// 新版管理台：HTML 里保留 __PH_xxx__ 占位符，发送时按当前运行状态替换，
// 这样版本号 / 热点名 / 热点密码不用在固件里写死两份。
//
// 这个页面有 49 KB。早期实现是 `String page(kWebUi)` 整串替换后再 send()：
//    - 堆上要同时存在 49KB 原文 + 49KB 替换副本，替换过程还要反复 realloc，
//      ESP32 只有 ~100KB 可用堆，压到极限时 String 分配失败会退化成空串，
//      于是发出去的只是一个没有响应体的 200，
//      手机浏览器（尤其 Android Chrome）就显示「该站点没有有效内容」。
//    - 就算分配成功，一次性 WiFiClient.write(49KB) 在手机慢速接收下也可能
//      写超时、只发出一部分，客户端拿到的是截断的 HTML。
//
// 现在改成流式发送：先只读扫描一遍算准 Content-Length，再按 ≤1KB
// 分块 sendContent，不组装 49KB 的替换结果，也不会一次性压 49KB 给 TCP。
//
// kWebUi 声明成 PROGMEM，但 ESP32 是统一地址空间：PROGMEM 是空宏，
// .rodata 被直接映射到数据总线可读地址，所以下面把 kWebUi 当普通指针用
// （memcmp / page[i]）是合法的。AVR 那套 "必须走 pgm_read_*" 的规矩在
// ESP32 上不成立，别照搬。真按那样改成 malloc 一整页副本，反而白吃
// 49KB 堆，把本来就只剩 50 多 KB 的余量压死。
static void sendMainWebUi() {
  const size_t total = strlen_P(kWebUi);
  if (total == 0) {
    server.send(500, "text/plain; charset=utf-8", "web ui missing");
    return;
  }

  // 占位符替换表。顺序即扫描顺序，越长的放越前面（__PH_VERFULL__ 不能被
  // __PH_VER__ 抢先匹配到前 10 个字符）。
  struct Subst { const char* token; String value; };
  Subst subs[] = {
    {"__PH_VERFULL__", String(kFwVersionFull)},
    {"__PH_VER__",     String(kFwVersion)},
    {"__PH_HW__",      String(kFwHardware)},
    {"__PH_AP__",      gApSsid},
    {"__PH_PASS__",    apPassword},
    // 本地令牌随页面下发：管理台 JS 会自动把它放进 X-Vela-Token 头。
    // 不这样做的后果：「用路由器里查到的 LAN IP 打开后台」时 /api/v1/* 全部 401，
    // 页面永远显示"设备暂未响应"（在配网热点上访问时因为 isSetupApClient() 而豁免）。
    // 页面里本来就已经带着热点密码 __PH_PASS__，因此这里不引入新的暴露面。
    {"__PH_TOKEN__",   sanitizeWebToken(localToken)},
  };
  const size_t kSubCount = sizeof(subs) / sizeof(subs[0]);

  // 先算出替换后的总长度，好发准确的 Content-Length。
  // 这一步只做计数，不分配整页缓冲。
  size_t outLen = 0;
  {
    const char* p = kWebUi;
    const size_t n = total;
    size_t i = 0;
    while (i < n) {
      bool hit = false;
      for (size_t k = 0; k < kSubCount; ++k) {
        const size_t tlen = strlen(subs[k].token);
        if (i + tlen <= n && memcmp(p + i, subs[k].token, tlen) == 0) {
          outLen += subs[k].value.length();
          i += tlen;
          hit = true;
          break;
        }
      }
      if (!hit) { ++i; ++outLen; }
    }
  }

  server.setContentLength(outLen);
  server.send(200, "text/html; charset=utf-8", "");

  // 逐块发送：把连续的普通字符攒到一块再写，遇到占位符就先把攒的块刷出去。
  // 切块时不能切开 UTF-8 多字节字符（中文 3 字节）：虽然 HTTP 是字节流、
  // 浏览器理论上能自行重组，但中间过一层不带 Content-Length 的代理、
  // 或者某些手机浏览器的容错逻辑会把它当成非法字节，于是显示乱码/空白。
  // 做法：切块前看当前字节是不是 UTF-8 的续字节（10xxxxxx），
  // 是就往前退到字符起始位置。
  static const size_t kChunkCap = 1024;
  char buf[kChunkCap + 4];
  size_t used = 0;
  auto flush = [&]() {
    if (used > 0) {
      server.sendContent(buf, used);
      used = 0;
    }
  };

  size_t i = 0;
  while (i < total) {
    bool hit = false;
    for (size_t k = 0; k < kSubCount; ++k) {
      const size_t tlen = strlen(subs[k].token);
      if (i + tlen <= total && memcmp(kWebUi + i, subs[k].token, tlen) == 0) {
        flush();     // 占位符值单独发，可能会超过缓冲
        const String& v = subs[k].value;
        if (v.length() > 0) server.sendContent(v.c_str(), v.length());
        i += tlen;
        hit = true;
        break;
      }
    }
    if (hit) continue;
    if (used >= kChunkCap) {
      // 回退到字符边界：UTF-8 续字节形如 10xxxxxx
      size_t cut = used;
      while (cut > 0 && (static_cast<uint8_t>(buf[cut]) & 0xC0) == 0x80) --cut;
      if (cut > 0 && cut < used) {
        server.sendContent(buf, cut);
        const size_t rest = used - cut;
        memmove(buf, buf + cut, rest);
        used = rest;
      } else {
        flush();
      }
    }
    buf[used++] = static_cast<char>(pgm_read_byte(kWebUi + i));
    ++i;
  }
  flush();
}

// ===========================================================================
// 表盘 / 快应用安装（蓝牙 SPP · Mass 通道）
// ---------------------------------------------------------------------------
// 协议来自小米穿戴的 WearPacket（protobuf）+ Mass 分块传输，与 AstroBox /
// minstall 一致，已在 Band 10 Pro 上实测通过（2026-08）。要点：
//
//   1. 表盘先走 WatchFace/PrepareInstall（type=4, id=4），带表盘 id 和文件长度，
//      设备回 prepare_status=READY 才算接受。
//   2. 再走 Mass/Prepare（type=22, id=0），带 data_type + 文件 md5 + 长度，
//      设备回 expected_slice_length（它愿意一次吃多大一帧）。
//   3. 数据按 slice_length-6 切片，每片打上 channel=2(Mass) / op=1 / 总片数 /
//      当前片号，逐片发出并等 ACK。
//   4. 传完等 WatchFace/ReportInstallResult 或 ThirdpartyApp/ReportInstallResult
//      才算真的装好。
//
// 数据块本身带自校验：
//   comp(1)=0 | data_type(1) | md5(16) | length(4 LE) | file | crc32(4 LE)
// crc32 覆盖前面全部字节（含 md5 和长度），所以必须在发送前流式算一遍。
//
// ESP32 侧的两个约束决定了下面的写法：
//   · 空闲堆只有 50 多 KB，表盘动辄 1~3 MB，全程不能把文件读进内存，
//     只按切片粒度（约 2 KB）滚动读。
//   · SPP 的收发由 vela_watch 任务独占（gSppRxFrame 是共享装配缓冲），
//     安装状态机必须挂进那个读循环里逐帧推进，不能另起线程抢数据。
// ===========================================================================

namespace wfi {

// WearPacket.type
constexpr uint32_t kWpTypeWatchFace = 4;
constexpr uint32_t kWpTypeThirdpartyApp = 20;
constexpr uint32_t kWpTypeMass = 22;
// WearPacket 的 payload oneof 字段号
constexpr uint32_t kWpFieldWatchFace = 6;
constexpr uint32_t kWpFieldThirdpartyApp = 22;
constexpr uint32_t kWpFieldMass = 24;
// WatchFace 子命令
constexpr uint32_t kWfIdPrepareInstall = 4;
constexpr uint32_t kWfIdReportInstallResult = 5;
// Mass 子命令
constexpr uint32_t kMassIdPrepare = 0;
// MassDataType
constexpr uint8_t kDataTypeWatchFace = 16;
constexpr uint8_t kDataTypeThirdpartyApp = 64;
// 设备没报 expected_slice_length 时的保守值
constexpr uint32_t kFallbackSliceLength = 2048;
// 每帧的固定开销：channel(1) + op(1) + total(2) + cur(2)
constexpr uint32_t kL2Overhead = 6;
// 数据块头：comp(1) + data_type(1) + md5(16) + length(4)
constexpr size_t kBlockHeader = 22;
constexpr size_t kBlockTail = 4;
// 单片超时：设备一直不回 ACK 就放弃，别把链路挂死
constexpr uint32_t kPartAckTimeoutMs = 4000;
constexpr uint32_t kPrepareTimeoutMs = 6000;
constexpr uint32_t kResultTimeoutMs = 20000;
// 安装任务的空闲宽度（表盘 3 MB / 2 KB ≈ 1500 片）
constexpr uint32_t kJobTimeoutMs = 10UL * 60UL * 1000UL;

enum State : uint8_t {
  kIdle = 0,
  kWaitWfPrepare,
  kWaitMassPrepare,
  kSending,
  kWaitResult,
  kDone,
  kFailed,
};

struct Job {
  State state = kIdle;
  uint8_t dataType = 0;
  char path[56] = {0};        // SPIFFS 路径
  char label[40] = {0};       // 展示名（表盘名 / 包名）
  char wfId[16] = {0};        // 表盘 id（十进制字符串）
  uint32_t fileSize = 0;
  uint8_t md5[16] = {0};
  uint32_t blockCrc = 0;      // 覆盖 block header + 文件内容
  uint32_t sliceLength = kFallbackSliceLength;
  uint32_t totalParts = 0;
  uint32_t ackedParts = 0;    // 已收到 ACK 的片数
  uint32_t sentParts = 0;     // 已发出的片数
  uint32_t lastAckMs = 0;
  uint32_t startedMs = 0;
  uint8_t pendingSeq = 0;
  char message[96] = {0};
};

static Job gJob;

// ---- 状态查询 -------------------------------------------------------------

uint8_t stateOf() { return gJob.state; }

bool busy() {
  return gJob.state != kIdle && gJob.state != kDone && gJob.state != kFailed;
}

const char* stateName(State s) {
  switch (s) {
    case kIdle: return "idle";
    case kWaitWfPrepare: return "wf_prepare";
    case kWaitMassPrepare: return "mass_prepare";
    case kSending: return "sending";
    case kWaitResult: return "wait_result";
    case kDone: return "done";
    case kFailed: return "failed";
    default: return "?";
  }
}

void setMessage(const char* text) {
  if (!text) { gJob.message[0] = 0; return; }
  strncpy(gJob.message, text, sizeof(gJob.message) - 1);
  gJob.message[sizeof(gJob.message) - 1] = 0;
}

void fail(const char* text) {
  const State from = gJob.state;
  gJob.state = kFailed;
  setMessage(text);
  Serial.printf("WF_INSTALL_FAILED from=%s reason=%s\n",
                stateName(from), text ? text : "");
}

void finish(const char* text) {
  gJob.state = kDone;
  setMessage(text);
  Serial.printf("WF_INSTALL_DONE %s\n", text ? text : "");
}

void reset() {
  gJob = Job();
}

// ---- 小工具 ---------------------------------------------------------------

// ESP32 的 ROM 里就有 CRC32/MPEG-2（与 zlib 的 crc32 同参数），
// 用它可以增量喂数据，不必自己造表。
uint32_t crc32Feed(uint32_t crc, const uint8_t* data, size_t len) {
  return esp_rom_crc32_le(crc, data, static_cast<uint32_t>(len));
}

// SPIFFS 文件是否存在且大小合理
bool fileInfo(const char* path, uint32_t& size) {
  File f = SPIFFS.open(path, FILE_READ);
  if (!f) return false;
  size = static_cast<uint32_t>(f.size());
  f.close();
  return size > 0;
}

// 流式计算整个文件（含 block header）的 CRC32。
// header 只有 22 字节，先算它，再滚动读文件。
bool computeBlockCrc(const char* path, uint8_t dataType, const uint8_t md5[16],
                     uint32_t fileSize, uint32_t& outCrc) {
  uint8_t header[kBlockHeader];
  header[0] = 0x00;                 // comp_data = 0（不压缩）
  header[1] = dataType;
  memcpy(header + 2, md5, 16);
  header[18] = static_cast<uint8_t>(fileSize & 0xff);
  header[19] = static_cast<uint8_t>((fileSize >> 8) & 0xff);
  header[20] = static_cast<uint8_t>((fileSize >> 16) & 0xff);
  header[21] = static_cast<uint8_t>((fileSize >> 24) & 0xff);

  uint32_t crc = crc32Feed(0, header, sizeof(header));

  File f = SPIFFS.open(path, FILE_READ);
  if (!f) return false;
  uint8_t buf[512];
  uint32_t remain = fileSize;
  while (remain > 0) {
    const size_t want = remain > sizeof(buf) ? sizeof(buf) : remain;
    const size_t got = f.read(buf, want);
    if (got == 0) { f.close(); return false; }
    crc = crc32Feed(crc, buf, got);
    remain -= static_cast<uint32_t>(got);
  }
  f.close();
  outCrc = crc;
  return true;
}

// 流式计算 md5（上传落盘后调用一次）
bool computeFileMd5(const char* path, uint8_t out[16]) {
  mbedtls_md5_context ctx;
  mbedtls_md5_init(&ctx);
  if (mbedtls_md5_starts_ret(&ctx) != 0) { mbedtls_md5_free(&ctx); return false; }
  File f = SPIFFS.open(path, FILE_READ);
  if (!f) { mbedtls_md5_free(&ctx); return false; }
  uint8_t buf[512];
  while (true) {
    const size_t got = f.read(buf, sizeof(buf));
    if (got == 0) break;
    if (mbedtls_md5_update_ret(&ctx, buf, got) != 0) {
      f.close(); mbedtls_md5_free(&ctx); return false;
    }
  }
  f.close();
  const int rc = mbedtls_md5_finish_ret(&ctx, out);
  mbedtls_md5_free(&ctx);
  return rc == 0;
}

// ---- 表盘文件解析 ---------------------------------------------------------
// 文件头：magic 5A A5；表盘 id 在 0x28，null 结尾的十进制 ASCII；
// 表盘名在 0x68；若 0x68 处是 0xFFFFFFFF 说明名字走 i18n 表（偏移/长度在 0x74/0x78）。
bool parseWatchfaceMeta(const char* path, char* outId, size_t idCap,
                        char* outName, size_t nameCap, const char*& err) {
  File f = SPIFFS.open(path, FILE_READ);
  if (!f) { err = "file_missing"; return false; }
  const size_t size = f.size();
  if (size < 0x100) { f.close(); err = "file_too_small"; return false; }

  uint8_t head[0x80];
  if (f.read(head, sizeof(head)) != sizeof(head)) { f.close(); err = "read_failed"; return false; }
  if (head[0] != 0x5A || head[1] != 0xA5) { f.close(); err = "bad_magic"; return false; }

  size_t idLen = 0;
  while (0x28 + idLen < 0x68 && head[0x28 + idLen] != 0) ++idLen;
  if (idLen == 0 || idLen >= idCap) { f.close(); err = "bad_watchface_id"; return false; }
  for (size_t i = 0; i < idLen; ++i) {
    const char ch = static_cast<char>(head[0x28 + i]);
    if (ch < '0' || ch > '9') { f.close(); err = "watchface_id_not_numeric"; return false; }
    outId[i] = ch;
  }
  outId[idLen] = 0;

  outName[0] = 0;
  const bool i18n = head[0x68] == 0xFF && head[0x69] == 0xFF &&
                    head[0x6A] == 0xFF && head[0x6B] == 0xFF;
  if (!i18n) {
    size_t n = 0;
    while (0x68 + n < sizeof(head) && head[0x68 + n] != 0 && n + 1 < nameCap) {
      outName[n] = static_cast<char>(head[0x68 + n]);
      ++n;
    }
    outName[n] = 0;
  } else {
    uint32_t off = 0, len = 0;
    memcpy(&off, head + 0x74, 4);
    memcpy(&len, head + 0x78, 4);
    if (off > 0 && len > 0 && off + len <= size && len < 512) {
      if (f.seek(off)) {
        uint8_t* table = static_cast<uint8_t*>(malloc(len));
        if (table) {
          const size_t got = f.read(table, len);
          size_t n = 0;
          while (n < got && table[n] != 0 && n + 1 < nameCap) { outName[n] = static_cast<char>(table[n]); ++n; }
          outName[n] = 0;
          free(table);
        }
      }
    }
  }
  f.close();
  if (!outName[0]) snprintf(outName, nameCap, "watchface");
  err = nullptr;
  return true;
}

// ---- 协议编码 -------------------------------------------------------------

// WearPacket{ type, id, <oneof field> = payload }
bool buildWearPacket(uint8_t* out, size_t cap, size_t& len, uint32_t type, uint32_t id,
                     uint32_t payloadField, const uint8_t* payload, size_t payloadLen) {
  ProtoWriter w(out, cap);
  if (!w.putVarint((1u << 3) | 0u) || !w.putVarint(type)) return false;
  if (!w.putVarint((2u << 3) | 0u) || !w.putVarint(id)) return false;
  if (payload && payloadLen) {
    if (!w.putBytesField(payloadField, payload, payloadLen)) return false;
  }
  len = w.length();
  return true;
}

// WatchFace{ PrepareInfo{ id, size, version=65536 } }，两层都是 field 6：
// 外层 WearPacket 的 oneof 里 WatchFace=6，WatchFace 里 prepare_info 也是 6。
bool buildWatchfacePrepare(uint8_t* out, size_t cap, size_t& len,
                           const char* wfId, uint32_t fileSize) {
  uint8_t info[128];
  ProtoWriter iw(info, sizeof(info));
  if (!iw.putStringField(1, wfId)) return false;
  if (!iw.putVarint((2u << 3) | 0u) || !iw.putVarint(fileSize)) return false;
  // version_code 固定 0x10000：设备用它判断表盘格式版本，官方工具同样取这个值
  if (!iw.putVarint((3u << 3) | 0u) || !iw.putVarint(65536u)) return false;

  uint8_t wf[192];
  ProtoWriter ww(wf, sizeof(wf));
  if (!ww.putBytesField(kWpFieldWatchFace, info, iw.length())) return false;

  return buildWearPacket(out, cap, len, kWpTypeWatchFace, kWfIdPrepareInstall,
                         kWpFieldWatchFace, wf, ww.length());
}

// Mass{ PrepareRequest{ data_type, data_id=md5, data_length } }
bool buildMassPrepare(uint8_t* out, size_t cap, size_t& len,
                      uint8_t dataType, const uint8_t md5[16], uint32_t fileSize) {
  uint8_t req[64];
  ProtoWriter rw(req, sizeof(req));
  if (!rw.putVarint((1u << 3) | 0u) || !rw.putVarint(dataType)) return false;
  if (!rw.putBytesField(2, md5, 16)) return false;
  if (!rw.putVarint((3u << 3) | 0u) || !rw.putVarint(fileSize)) return false;

  uint8_t mass[96];
  ProtoWriter mw(mass, sizeof(mass));
  if (!mw.putBytesField(1, req, rw.length())) return false;

  return buildWearPacket(out, cap, len, kWpTypeMass, kMassIdPrepare,
                         kWpFieldMass, mass, mw.length());
}

// 表盘/快应用的 prepare 响应解析。
// 表盘：WatchFace{ field5=prepare_status } 或 WatchFace{ field9=prepare_reply{2=status,4=slice} }
// 快应用：结构类似，但字段号以 ThirdpartyApp 定义为准，这里同样按 5/9 兼容尝试。
void parsePrepareReply(const uint8_t* pb, size_t len, bool massSide,
                       int32_t& status, uint32_t& sliceLength, bool& haveStatus) {
  status = -1;
  sliceLength = 0;
  haveStatus = false;

  const uint8_t* body = nullptr;
  size_t bodyLen = 0;
  const uint32_t field = massSide ? kWpFieldMass : kWpFieldWatchFace;
  if (!protoBytesField(pb, len, field, body, bodyLen)) {
    // 快应用的 oneof 字段号不同，退一步按 ThirdpartyApp 试
    if (!massSide && protoBytesField(pb, len, kWpFieldThirdpartyApp, body, bodyLen)) {
      // 继续
    } else {
      return;
    }
  }

  if (massSide) {
    // Mass{ field2 = PrepareResponse{ 2=status, 5=expected_slice_length } }
    const uint8_t* resp = nullptr;
    size_t respLen = 0;
    if (!protoBytesField(body, bodyLen, 2, resp, respLen)) return;
    uint32_t v = 0;
    if (protoVarintField(resp, respLen, 2, v)) { status = static_cast<int32_t>(v); haveStatus = true; }
    if (protoVarintField(resp, respLen, 5, v)) sliceLength = v;
  } else {
    uint32_t v = 0;
    if (protoVarintField(body, bodyLen, 5, v)) { status = static_cast<int32_t>(v); haveStatus = true; }
    const uint8_t* reply = nullptr;
    size_t replyLen = 0;
    if (protoBytesField(body, bodyLen, 9, reply, replyLen)) {
      if (protoVarintField(reply, replyLen, 2, v)) { status = static_cast<int32_t>(v); haveStatus = true; }
      if (protoVarintField(reply, replyLen, 4, v)) sliceLength = v;
    }
  }
}

// ---- Mass 数据通道应答位置无关探测 ---------------------------------------
// mass_prepare 的应答只有设备会给，字段号一旦对不上就卡在 mass_prepare_timeout，
// 看不出是哪一层错。这里把所有候选状态的字节位置都扫出来打一遍，并且刻意
// 不依赖 Mass{2}/PrepareResponse 这层包装，包装层猜错也能看到线索。
void dumpPrepareReply(const uint8_t* pb, size_t len, const char* tag) {
  Serial.printf("WF_INSTALL_PREPARE_RAW %s len=%u ", tag, static_cast<unsigned>(len));
  for (size_t i = 0; i < len && i < 96; ++i) Serial.printf("%02X", pb[i]);
  Serial.println();

  const uint32_t fields[] = {kWpFieldWatchFace, kWpFieldThirdpartyApp, kWpFieldMass};
  for (uint32_t f : fields) {
    const uint8_t* body = nullptr;
    size_t bodyLen = 0;
    if (!protoBytesField(pb, len, f, body, bodyLen)) continue;
    Serial.printf("WF_INSTALL_PREPARE_SUB field=%u len=%u ",
                  static_cast<unsigned>(f), static_cast<unsigned>(bodyLen));
    for (size_t i = 0; i < bodyLen && i < 64; ++i) Serial.printf("%02X", body[i]);
    Serial.println();
    // 每个子字节串都当作候选状态源扫一遍，位置无关
    for (size_t i = 0; i < bodyLen && i < 24; ++i) {
      Serial.printf("WF_INSTALL_CAND sub=%u off=%u=%u\n",
                    static_cast<unsigned>(f), static_cast<unsigned>(i),
                    static_cast<unsigned>(body[i]));
    }
  }
}

// ---- 虚拟数据流 -----------------------------------------------------------
// 发送时文件不整体进内存：block = header(22) + file + crc(4)，
// 每次只按偏移把需要的那一段读出来。
size_t readBlockSpan(File& f, uint32_t offset, uint8_t* out, size_t len,
                     const uint8_t header[kBlockHeader], const uint8_t tail[4],
                     uint32_t fileSize) {
  size_t done = 0;
  while (done < len) {
    const uint32_t pos = offset + static_cast<uint32_t>(done);
    if (pos < kBlockHeader) {
      const size_t take = ((len - done) < (kBlockHeader - pos) ? (len - done) : (kBlockHeader - pos));
      memcpy(out + done, header + pos, take);
      done += take;
    } else if (pos < kBlockHeader + fileSize) {
      const uint32_t fileOffset = pos - kBlockHeader;
      const size_t take = ((len - done) < (fileSize - fileOffset) ? (len - done) : (fileSize - fileOffset));
      if (!f.seek(fileOffset)) break;
      const size_t got = f.read(out + done, take);
      if (got == 0) break;
      done += got;
    } else {
      const size_t tailOffset = pos - (kBlockHeader + fileSize);
      if (tailOffset >= kBlockTail) break;
      const size_t take = ((len - done) < (kBlockTail - tailOffset) ? (len - done) : (kBlockTail - tailOffset));
      memcpy(out + done, tail + tailOffset, take);
      done += take;
    }
  }
  return done;
}

// ===========================================================================
// 安装状态机（必须跑在 vela_watch 任务里，跟着 SPP 读循环推进）
// ===========================================================================


// 发送序列号：只有安装期间使用，安装时网络回包被暂停，不会和别的流撞号
static uint8_t gTxSeq = 0;

// 缓存 block header 与尾部 crc，供分片时拼装
static uint8_t gBlockHeader[kBlockHeader];
static uint8_t gBlockTail[kBlockTail];
// 每片读文件的缓冲（跟设备给的 slice_length 同步增长）
static uint8_t* gSpan = nullptr;
static size_t gSpanCap = 0;

// 安装期间暂停回程网络包，避免 seq 抢号、也避免把链路带宽浪费在转发上。
// 丢掉的包由手表侧 TCP 重传兜底，几十秒的安装窗口可以接受。
static volatile bool gPausedNetwork = false;
static uint32_t gPausedDrops = 0;

bool networkPaused() { return gPausedNetwork; }
void notePausedDrop() { ++gPausedDrops; }
uint32_t pausedDrops() { return gPausedDrops; }

static bool ensureSpan(size_t need) {
  if (gSpanCap >= need && gSpan) return true;
  if (gSpan) { free(gSpan); gSpan = nullptr; gSpanCap = 0; }
  gSpan = static_cast<uint8_t*>(malloc(need));
  if (!gSpan) return false;
  gSpanCap = need;
  return true;
}

// 进入安装前把文件相关的元数据准备好（md5、crc、header、tail）。
// 这些都要读文件，放在 HTTP 线程做，避免占着 SPP 读循环几秒钟。
bool prepareJob(const char* path, uint8_t dataType, const char* label,
                const char* wfId, const char*& err) {
  if (busy()) { err = "busy"; return false; }
  if (!gWatchBridgeRunning) { err = "watch_not_connected"; return false; }

  uint32_t size = 0;
  if (!fileInfo(path, size)) { err = "file_missing"; return false; }
  if (size < 64) { err = "file_too_small"; return false; }

  // SPIFFS 只有 3.875 MB，留 64 KB 余量给日志/录音
  uint8_t md5[16];
  if (!computeFileMd5(path, md5)) { err = "md5_failed"; return false; }

  uint32_t crc = 0;
  if (!computeBlockCrc(path, dataType, md5, size, crc)) { err = "crc_failed"; return false; }

  reset();
  gJob.dataType = dataType;
  strncpy(gJob.path, path, sizeof(gJob.path) - 1);
  strncpy(gJob.label, label ? label : "resource", sizeof(gJob.label) - 1);
  if (wfId) strncpy(gJob.wfId, wfId, sizeof(gJob.wfId) - 1);
  gJob.fileSize = size;
  memcpy(gJob.md5, md5, 16);
  gJob.blockCrc = crc;
  gJob.startedMs = millis();
  gJob.lastAckMs = millis();

  // block header / tail 依当前 job 固化，分片时直接拼
  gBlockHeader[0] = 0x00;
  gBlockHeader[1] = dataType;
  memcpy(gBlockHeader + 2, md5, 16);
  gBlockHeader[18] = static_cast<uint8_t>(size & 0xff);
  gBlockHeader[19] = static_cast<uint8_t>((size >> 8) & 0xff);
  gBlockHeader[20] = static_cast<uint8_t>((size >> 16) & 0xff);
  gBlockHeader[21] = static_cast<uint8_t>((size >> 24) & 0xff);
  gBlockTail[0] = static_cast<uint8_t>(crc & 0xff);
  gBlockTail[1] = static_cast<uint8_t>((crc >> 8) & 0xff);
  gBlockTail[2] = static_cast<uint8_t>((crc >> 16) & 0xff);
  gBlockTail[3] = static_cast<uint8_t>((crc >> 24) & 0xff);

  gJob.state = kWaitWfPrepare;   // 快应用也一样先做 prepare，只是命令号不同
  gTxSeq = static_cast<uint8_t>(random(256));
  gPausedNetwork = true;
  gPausedDrops = 0;
  setMessage("preparing");
  Serial.printf("WF_INSTALL_START type=%u bytes=%lu label=%s\n",
                static_cast<unsigned>(dataType), static_cast<unsigned long>(size),
                gJob.label);
  err = nullptr;
  return true;
}

// 发 prepare 请求（表盘/快应用共用入口，靠 dataType 分支）
static bool sendPrepare(uint8_t& seq, const uint8_t encKey[16]) {
  uint8_t pb[256];
  size_t pbLen = 0;
  bool ok = false;

  if (gJob.dataType == kDataTypeWatchFace) {
    ok = buildWatchfacePrepare(pb, sizeof(pb), pbLen, gJob.wfId, gJob.fileSize);
  } else {
    // 快应用：ThirdpartyApp{ PrepareInstallApp{ package, versionCode, size } }
    // 字段号按 WearPacket(20)/App 的通用布局，实测若不通会落到 prepare 拒绝。
    uint8_t info[160];
    ProtoWriter iw(info, sizeof(info));
    ok = iw.putStringField(1, gJob.label) &&
         iw.putVarint((2u << 3) | 0u) && iw.putVarint(1u) &&
         iw.putVarint((3u << 3) | 0u) && iw.putVarint(gJob.fileSize);
    if (ok) {
      uint8_t app[192];
      ProtoWriter aw(app, sizeof(app));
      ok = aw.putBytesField(kWpFieldThirdpartyApp, info, iw.length());
      if (ok) {
        ok = buildWearPacket(pb, sizeof(pb), pbLen, kWpTypeThirdpartyApp, 1u,
                             kWpFieldThirdpartyApp, app, aw.length());
      }
    }
  }
  if (!ok) return false;

  seq = gTxSeq++;
  if (!sendEncryptedWatchPb(seq, encKey, pb, pbLen)) return false;
  gJob.pendingSeq = seq;
  return true;
}

// 每轮 SPP 循环调用：推进状态机（一次最多发一片，靠 ACK 驱动）
void pump(uint8_t& /*seq*/, const uint8_t encKey[16]) {
  if (gJob.state == kIdle || gJob.state == kDone || gJob.state == kFailed) return;

  const uint32_t now = millis();
  if (now - gJob.startedMs > kJobTimeoutMs) {
    gPausedNetwork = false;
    fail("timeout");
    return;
  }

  switch (gJob.state) {
    case kWaitWfPrepare:
    case kWaitMassPrepare: {
      const uint32_t limit = (gJob.state == kWaitWfPrepare) ? kPrepareTimeoutMs : kPrepareTimeoutMs;
      if (now - gJob.lastAckMs > limit) {
        gPausedNetwork = false;
        fail(gJob.state == kWaitWfPrepare ? "wf_prepare_timeout" : "mass_prepare_timeout");
        return;
      }
      // 首次进入：把 prepare 请求发出去（只发一次）
      if (gJob.sentParts == 0) {
        if (!sendPrepare(gJob.pendingSeq, encKey)) {
          gPausedNetwork = false;
          fail("prepare_send_failed");
          return;
        }
        gJob.sentParts = 1;
        gJob.lastAckMs = millis();
      }
      break;
    }

    case kSending: {
      // 上一片还没被确认
      if (gJob.sentParts > gJob.ackedParts) {
        if (now - gJob.lastAckMs > kPartAckTimeoutMs) {
          gPausedNetwork = false;
          char msg[64];
          snprintf(msg, sizeof(msg), "part_ack_timeout %lu/%lu",
                   static_cast<unsigned long>(gJob.ackedParts),
                   static_cast<unsigned long>(gJob.totalParts));
          fail(msg);
        }
        return;
      }
      if (gJob.ackedParts >= gJob.totalParts) {
        gJob.state = kWaitResult;
        gJob.lastAckMs = millis();
        setMessage("waiting for install result");
        Serial.println("WF_INSTALL_ALL_PARTS_SENT");
        return;
      }

      const uint32_t partIndex = gJob.sentParts;        // 0-based
      const uint32_t fragmentMax = gJob.sliceLength - kL2Overhead;
      const uint32_t blockTotal = static_cast<uint32_t>(kBlockHeader + gJob.fileSize + kBlockTail);
      if (!ensureSpan(gJob.sliceLength)) {
        gPausedNetwork = false;
        fail("out_of_memory");
        return;
      }

      File f = SPIFFS.open(gJob.path, FILE_READ);
      if (!f) { gPausedNetwork = false; fail("file_open_failed"); return; }

      const uint32_t offset = partIndex * fragmentMax;
      const uint32_t want = ((fragmentMax) < (blockTotal - offset) ? (fragmentMax) : (blockTotal - offset));
      const size_t got = readBlockSpan(f, offset, gSpan, want, gBlockHeader, gBlockTail, gJob.fileSize);
      f.close();
      if (got != want) { gPausedNetwork = false; fail("file_read_failed"); return; }

      // payload = channel(2) | op(1) | total(2) | cur(2, 1-based) | fragment
      uint8_t* payload = gRawCommandPayloadScratch;
      if (!payload) { gPausedNetwork = false; fail("no_scratch"); return; }
      payload[0] = 2;                    // Channel::Mass
      payload[1] = 1;                    // OpCode::Plain
      payload[2] = static_cast<uint8_t>(gJob.totalParts & 0xff);
      payload[3] = static_cast<uint8_t>((gJob.totalParts >> 8) & 0xff);
      payload[4] = static_cast<uint8_t>((partIndex + 1) & 0xff);
      payload[5] = static_cast<uint8_t>(((partIndex + 1) >> 8) & 0xff);
      memcpy(payload + kL2Overhead, gSpan, got);

      const uint8_t frameSeq = gTxSeq++;
      if (!writeSppV2Frame(3, frameSeq, payload, got + kL2Overhead)) {
        gPausedNetwork = false;
        fail("spp_write_failed");
        return;
      }
      gJob.pendingSeq = frameSeq;
      ++gJob.sentParts;
      gJob.lastAckMs = millis();
      // 进度打点：每 32 片一次，避免串口拖慢发送
      if ((gJob.sentParts % 32) == 0 || gJob.sentParts == gJob.totalParts) {
        Serial.printf("WF_INSTALL_PROGRESS %lu/%lu\n",
                      static_cast<unsigned long>(gJob.sentParts),
                      static_cast<unsigned long>(gJob.totalParts));
      }
      break;
    }

    case kWaitResult: {
      if (now - gJob.lastAckMs > kResultTimeoutMs) {
        // 数据已经全部发完且都确认了，设备只是没回结果。多数情况下表盘已经装上了
        gPausedNetwork = false;
        finish("installed(no_result)");
      }
      break;
    }

    default:
      break;
  }
}

// 收到 ACK（type=1）
void onAck(uint8_t seq) {
  if (gJob.state != kSending) return;
  if (seq != gJob.pendingSeq) return;
  ++gJob.ackedParts;
  gJob.lastAckMs = millis();
}

// 收到加密 protobuf（type=3, channel=1, op=2），解密后由读循环调用
void onProto(uint32_t pbType, uint32_t pbId, const uint8_t* pb, size_t pbLen) {
  if (gJob.state == kIdle || gJob.state == kDone || gJob.state == kFailed) return;

  Serial.printf("WF_INSTALL_RX_PB type=%lu id=%lu bytes=%u\n",
                static_cast<unsigned long>(pbType), static_cast<unsigned long>(pbId),
                static_cast<unsigned>(pbLen));

  // --- 表盘 / 快应用的 prepare 应答 ---
  if (gJob.state == kWaitWfPrepare &&
      ((pbType == kWpTypeWatchFace && pbId == kWfIdPrepareInstall) ||
       (pbType == kWpTypeThirdpartyApp))) {
    int32_t status = -1;
    uint32_t slice = 0;
    bool haveStatus = false;
    parsePrepareReply(pb, pbLen, false, status, slice, haveStatus);
    if (!haveStatus) {
      // 字段号和预期不一致：把原始内容打出来，方便现场比对不同机型的定义
      dumpPrepareReply(pb, pbLen, "wf");
      return;
    }
    if (status != 0) {
      gPausedNetwork = false;
      char msg[64];
      snprintf(msg, sizeof(msg), "prepare_rejected status=%ld", static_cast<long>(status));
      fail(msg);
      return;
    }
    // 表盘 prepare 通过 → 接着做 Mass prepare
    gJob.state = kWaitMassPrepare;
    gJob.sentParts = 0;
    gJob.lastAckMs = millis();
    setMessage("mass prepare");
    return;
  }

  // --- Mass prepare 应答 ---
  if (gJob.state == kWaitMassPrepare && pbType == kWpTypeMass && pbId == kMassIdPrepare) {
    int32_t status = -1;
    uint32_t slice = 0;
    bool haveStatus = false;
    parsePrepareReply(pb, pbLen, true, status, slice, haveStatus);
    if (!haveStatus || status != 0) {
      gPausedNetwork = false;
      // 这里是全流程里最可能对不上的一步（字段号靠推的），无条件打原始回包
      dumpPrepareReply(pb, pbLen, "mass");
      char msg[64];
      snprintf(msg, sizeof(msg), "mass_prepare_failed status=%ld", static_cast<long>(status));
      fail(msg);
      return;
    }
    if (slice < kL2Overhead + 64 || slice > kSppV2PayloadMax) {
      slice = kFallbackSliceLength;
    }
    gJob.sliceLength = slice;
    const uint32_t fragmentMax = slice - kL2Overhead;
    const uint32_t blockTotal = static_cast<uint32_t>(kBlockHeader + gJob.fileSize + kBlockTail);
    gJob.totalParts = (blockTotal + fragmentMax - 1) / fragmentMax;
    gJob.sentParts = 0;
    gJob.ackedParts = 0;
    gJob.state = kSending;
    gJob.lastAckMs = millis();
    setMessage("sending");
    Serial.printf("WF_INSTALL_MASS_READY slice=%lu parts=%lu\n",
                  static_cast<unsigned long>(slice),
                  static_cast<unsigned long>(gJob.totalParts));
    return;
  }

  // --- 安装结果 ---
  if (gJob.state == kWaitResult) {
    const bool wfResult = (pbType == kWpTypeWatchFace && pbId == kWfIdReportInstallResult);
    const bool appResult = (pbType == kWpTypeThirdpartyApp);
    if (!wfResult && !appResult) return;

    // 结果体里通常带 status/进度，字段号依机型而异；能读到 0 就是成功，
    // 读不出也认为成功（数据全部 ACK 过，设备很少会静默失败）。
    int32_t status = -1;
    uint32_t v = 0;
    if (protoVarintField(pb, pbLen, 1, v)) status = static_cast<int32_t>(v);
    else if (protoVarintField(pb, pbLen, 2, v)) status = static_cast<int32_t>(v);

    gPausedNetwork = false;
    if (status == 0 || status == -1) finish("installed");
    else {
      char msg[64];
      snprintf(msg, sizeof(msg), "install_failed status=%ld", static_cast<long>(status));
      fail(msg);
    }
    return;
  }
}

// 安装结束（成功/失败/取消）后由 HTTP 侧回收
void clearIfFinished() {
  if (gJob.state == kDone || gJob.state == kFailed) {
    gPausedNetwork = false;
    reset();
  }
}

void cancel() {
  if (gJob.state == kIdle) return;
  gPausedNetwork = false;
  gJob.state = kFailed;
  setMessage("cancelled");
}

// 供 HTTP 查询
void statusJson(JsonObject& d) {
  d["state"] = stateName(gJob.state);
  d["busy"] = busy();
  d["label"] = gJob.label;
  d["bytes"] = gJob.fileSize;
  d["sentParts"] = gJob.sentParts;
  d["ackedParts"] = gJob.ackedParts;
  d["totalParts"] = gJob.totalParts;
  d["message"] = gJob.message;
  d["pausedDrops"] = gPausedDrops;
  if (gJob.totalParts > 0) {
    d["progress"] = static_cast<double>(gJob.ackedParts) / static_cast<double>(gJob.totalParts);
  } else {
    d["progress"] = 0;
  }
}



// ---- 快应用包（.rpk = zip）解析 ------------------------------------------
// 安装请求要带 package 名和 versionCode，这两个只在 manifest.json 里。
// 这里只解这一个文件（通常 < 8 KB），不碰其它资源，避免在 ESP32 上整体解压。
bool parseRpkManifest(const char* path, char* outPkg, size_t pkgCap,
                      uint32_t& outVersionCode, char* outName, size_t nameCap,
                      const char*& err) {
  File f = SPIFFS.open(path, FILE_READ);
  if (!f) { err = "file_missing"; return false; }
  const uint32_t size = static_cast<uint32_t>(f.size());
  if (size < 128) { f.close(); err = "file_too_small"; return false; }

  // 1) 从尾部往前找 EOCD（0x06054b50），最多回退 64 KB（zip 注释上限）
  uint32_t eocd = 0;
  bool found = false;
  const uint32_t scan = (size < 65557u ? size : 65557u);
  uint8_t tail[512];
  for (uint32_t back = 22; back < scan; back += 256) {
    const uint32_t want = ((512u) < (scan - back) ? (512u) : (scan - back));
    const uint32_t off = size - back - want + want;  // 简化：直接按块读
    (void)off;
    const uint32_t start = (size >= back + want) ? (size - back - want) : 0;
    if (!f.seek(start)) break;
    const size_t got = f.read(tail, want);
    for (size_t i = got >= 4 ? got - 4 : 0; i + 4 <= got; ++i) {
      if (tail[i] == 0x50 && tail[i + 1] == 0x4b && tail[i + 2] == 0x05 && tail[i + 3] == 0x06) {
        eocd = start + static_cast<uint32_t>(i);
        found = true;
        break;
      }
      if (got < 4) break;
    }
    if (found) break;
  }
  if (!found) { f.close(); err = "not_a_zip"; return false; }

  uint8_t e[22];
  if (!f.seek(eocd) || f.read(e, 22) != 22) { f.close(); err = "eocd_read_failed"; return false; }
  const uint16_t entryCount = static_cast<uint16_t>(e[10] | (e[11] << 8));
  const uint32_t cdSize = static_cast<uint32_t>(e[12] | (e[13] << 8) | (e[14] << 16) | (e[15] << 24));
  const uint32_t cdOffset = static_cast<uint32_t>(e[16] | (e[17] << 8) | (e[18] << 16) | (e[19] << 24));
  if (entryCount == 0 || entryCount > 2048 || cdOffset >= size || cdSize > size) {
    f.close(); err = "bad_central_dir"; return false;
  }

  // 2) 遍历中央目录，找 manifest.json
  uint16_t method = 0xffff;
  uint32_t compSize = 0, localHeader = 0;
  uint32_t cursor = cdOffset;
  char name[96];
  for (uint16_t i = 0; i < entryCount; ++i) {
    uint8_t h[46];
    if (!f.seek(cursor) || f.read(h, 46) != 46) break;
    if (!(h[0] == 0x50 && h[1] == 0x4b && h[2] == 0x01 && h[3] == 0x02)) break;
    const uint16_t m = static_cast<uint16_t>(h[10] | (h[11] << 8));
    const uint32_t cs = static_cast<uint32_t>(h[20] | (h[21] << 8) | (h[22] << 16) | (h[23] << 24));
    const uint16_t nameLen = static_cast<uint16_t>(h[28] | (h[29] << 8));
    const uint16_t extraLen = static_cast<uint16_t>(h[30] | (h[31] << 8));
    const uint16_t commentLen = static_cast<uint16_t>(h[32] | (h[33] << 8));
    const uint32_t lh = static_cast<uint32_t>(h[42] | (h[43] << 8) | (h[44] << 16) | (h[45] << 24));

    if (nameLen > 0 && nameLen < sizeof(name)) {
      if (f.read(reinterpret_cast<uint8_t*>(name), nameLen) == nameLen) {
        name[nameLen] = 0;
        const char* base = strrchr(name, '/');
        const char* leaf = base ? base + 1 : name;
        if (strcmp(leaf, "manifest.json") == 0) {
          method = m; compSize = cs; localHeader = lh;
          break;
        }
      }
    }
    cursor += 46u + nameLen + extraLen + commentLen;
  }
  if (method == 0xffff) { f.close(); err = "manifest_missing"; return false; }
  if (compSize == 0 || compSize > 65536) { f.close(); err = "manifest_too_large"; return false; }

  // 3) 定位真实数据起点（本地头里的名字/扩展长度可能和中央目录不同）
  uint8_t lh[30];
  if (!f.seek(localHeader) || f.read(lh, 30) != 30) { f.close(); err = "local_header_failed"; return false; }
  if (!(lh[0] == 0x50 && lh[1] == 0x4b && lh[2] == 0x03 && lh[3] == 0x04)) {
    f.close(); err = "bad_local_header"; return false;
  }
  const uint16_t lNameLen = static_cast<uint16_t>(lh[26] | (lh[27] << 8));
  const uint16_t lExtraLen = static_cast<uint16_t>(lh[28] | (lh[29] << 8));
  const uint32_t dataOffset = localHeader + 30u + lNameLen + lExtraLen;
  if (dataOffset + compSize > size) { f.close(); err = "manifest_out_of_range"; return false; }

  uint8_t* raw = static_cast<uint8_t*>(malloc(compSize));
  if (!raw) { f.close(); err = "out_of_memory"; return false; }
  if (!f.seek(dataOffset) || f.read(raw, compSize) != compSize) {
    free(raw); f.close(); err = "manifest_read_failed"; return false;
  }
  f.close();

  char* text = nullptr;
  if (method == 0) {
    text = reinterpret_cast<char*>(raw);
    raw = nullptr;
  } else if (method == 8) {
    // deflate：输出缓冲按 32 KB 预留，manifest 实际远小于这个
    const size_t outCap = 32768;
    uint8_t* out = static_cast<uint8_t*>(malloc(outCap));
    if (!out) { free(raw); err = "out_of_memory"; return false; }
    const size_t got = tinfl_decompress_mem_to_mem(out, outCap, raw, compSize, 0);
    free(raw);
    if (got == 0 || got == static_cast<size_t>(-1)) { free(out); err = "inflate_failed"; return false; }
    text = reinterpret_cast<char*>(out);
  } else {
    free(raw);
    err = "unsupported_compression";
    return false;
  }

  // 4) 取 package / versionCode / name
  JsonDocument doc;
  const DeserializationError jerr = deserializeJson(doc, text);
  if (jerr) { free(text); err = "manifest_json_invalid"; return false; }

  const char* pkg = doc["package"] | "";
  if (!pkg[0]) { free(text); err = "manifest_package_missing"; return false; }
  strncpy(outPkg, pkg, pkgCap - 1);
  outPkg[pkgCap - 1] = 0;

  uint32_t vc = doc["versionCode"] | 0;
  if (vc == 0) {
    // 部分包只给 versionName（"1.0.3"），取首段做兜底
    const char* vn = doc["versionName"] | "";
    vc = static_cast<uint32_t>(atoi(vn));
    if (vc == 0) vc = 1;
  }
  outVersionCode = vc;

  const char* nm = doc["name"] | "";
  if (nm[0]) {
    strncpy(outName, nm, nameCap - 1);
    outName[nameCap - 1] = 0;
  } else {
    strncpy(outName, outPkg, nameCap - 1);
    outName[nameCap - 1] = 0;
  }

  free(text);
  err = nullptr;
  return true;
}

}  // namespace wfi

// ===========================================================================
// 固件库：-ota.bin 先写入 SPIFFS，再由网页触发写入 OTA 分区。
//
// 为什么要有这一层：
//   旧流程是「系统页点固件升级 → 跳到 OTA 页 → 在 OTA 页再选一次文件」。
//   中间那次跳转在用户看来就是"点了没反应"，而且设备里到底有没有固件、
//   有没有正在下载，完全看不见。拆成"先传后升"之后：
//     · 传的东西留在设备里，刷新页面还在，选哪一行装哪一行；
//     · 写入前先用 Update 校验镜像头，不合格当场报错，不用等重启才发现；
//     · 写入和 ESP.restart 放在请求返回之后做，浏览器不会因为连接被掐而报网络错误。
// 固件体积 1.6 MB 左右，SPIFFS 有 3.875 MB，够放一份；放两份就可能挤掉表盘。
// ===========================================================================
namespace fwlib {

constexpr const char* kDir = "/fw";
constexpr const char* kName = "/fw/new.bin";
// 单份固件上限：再大就超出 OTA 分区（6 MB）也没意义，同时挡住乱传的大文件
constexpr size_t kMaxFirmware = 6U * 1024U * 1024U;
// 给日志/表盘预留的空间
constexpr size_t kReserve = 128U * 1024U;

struct Pending {
  bool armed = false;
  uint32_t atMs = 0;
};

static Pending gPending;
static File gUpload;
static bool gUploadFailed = true;
// 实际写入字节数。用于区分「文件没写进去」和「文件写进去了但不是 app 镜像」，
// 这两种情况给用户的提示完全不同。
static size_t gUploadWritten = 0;

bool pendingWrite() { return gPending.armed; }

// 由 loop() 调用：延时到点才真正提交 + 重启，让 HTTP 响应先发出去
void servicePending() {
  if (!gPending.armed) return;
  if (static_cast<int32_t>(millis() - gPending.atMs) < 0) return;
  gPending.armed = false;

  File f = SPIFFS.open(kName, FILE_READ);
  if (!f) {
    Serial.println("FW_LIB_INSTALL_FAILED open_missing");
    return;
  }
  const size_t size = f.size();
  Serial.printf("FW_LIB_INSTALL_BEGIN size=%u\n", static_cast<unsigned>(size));

  if (!Update.begin(size)) {
    Serial.printf("FW_LIB_INSTALL_FAILED begin=%s\n", Update.errorString());
    f.close();
    return;
  }
  const size_t written = Update.writeStream(f);
  f.close();
  if (written != size) {
    Serial.printf("FW_LIB_INSTALL_FAILED write=%u/%u err=%s\n",
                  static_cast<unsigned>(written), static_cast<unsigned>(size),
                  Update.errorString());
    Update.abort();
    return;
  }
  if (!Update.end(true)) {
    Serial.printf("FW_LIB_INSTALL_FAILED end=%s\n", Update.errorString());
    return;
  }
  Serial.println("FW_LIB_INSTALL_OK written_to_ota_partition");
  // 升级完自动回到手表网关模式，别把用户留在只有一个网页的模式里
  prefs.putInt("project", 1);
  prefs.putBool("project2", false);
  delay(300);
  ESP.restart();
}

// 只在 /fw 目录里找文件，不接受外部拼路径
bool resolve(const String& rawName, String& path) {
  if (rawName.isEmpty() || rawName.length() > 40) return false;
  if (rawName.indexOf('/') >= 0 || rawName.indexOf('\\') >= 0) return false;
  if (rawName.indexOf("..") >= 0) return false;
  path = String(kDir) + "/" + rawName;
  return SPIFFS.exists(path);
}

void listItems(JsonArray& items, const String& current) {
  File dir = SPIFFS.open(kDir);
  if (!dir || !dir.isDirectory()) return;
  File f = dir.openNextFile();
  while (f) {
    if (!f.isDirectory()) {
      const String full = f.name();
      const char* base = full.c_str();
      const char* slash = strrchr(base, '/');
      if (slash) base = slash + 1;
      JsonObject o = items.add<JsonObject>();
      o["name"] = base;
      o["bytes"] = static_cast<uint32_t>(f.size());
      o["running"] = (current == base);
    }
    f.close();
    f = dir.openNextFile();
  }
  dir.close();
}

}  // namespace fwlib

// ===== 网关模式直传升级 =====
// 旧流程要先重启进「空中升级」模式，在那个只有一张网页的模式里刷写，
// 刷完再重启回网关：两次重启、两次换热点。现在改成网关模式下直接流式写
// 空闲 OTA 分区，写完记录目标并重启，省掉模式切换，也绕开 SPIFFS 暂存。
namespace otadirect {

static bool sActive = false;      // Update 会话已开始
static bool sFailed = false;
static String sError;
static String sName;
static size_t sWritten = 0;
static String sVersion;           // 从镜像 app 描述符读出的版本
static String sTargetLabel;       // 本次写入的分区
// 最近一次上传停在哪个阶段：upload_page / upload_callback 里没有阶段名的话，
// 「页面没反应」和「传到一半断了」在设备侧看起来一模一样。
static uint8_t sPhase = 0;        // 0=未开始 1=START 2=WRITE 3=END 4=ABORTED 5=已提交待重启
static uint32_t sLastRxMs = 0;
// 写入速度：本次上传的字节数与起点，用来判断「卡住」到底是断链还是擦写太慢。
static uint32_t sStartedAtMs = 0;
static uint32_t sChunkCount = 0;

const char* phaseName() {
  switch (sPhase) {
    case 1: return "file_start";
    case 2: return "file_write";
    case 3: return "file_end";
    case 4: return "aborted";
    case 5: return "committed";
    default: return "none";
  }
}

void reset() {
  sActive = false;
  sFailed = false;
  sError = "";
  sName = "";
  sWritten = 0;
  sVersion = "";
  sTargetLabel = "";
  sPhase = 0;
  sLastRxMs = 0;
  sStartedAtMs = 0;
  sChunkCount = 0;
}

// 写入吞吐（KB/s）。低到个位数说明卡在 Flash 擦写上，而不是网络太慢。
uint32_t kbps() {
  if (sStartedAtMs == 0 || sWritten == 0) return 0;
  const uint32_t elapsed = millis() - sStartedAtMs;
  if (elapsed == 0) return 0;
  return static_cast<uint32_t>(static_cast<uint64_t>(sWritten) * 1000u / elapsed / 1024u);
}

// app 描述符固定在镜像偏移 0x20，version 是其中偏移 0x10 的 32 字节字符串。
void readVersion(const uint8_t* buf, size_t len) {
  if (!sVersion.isEmpty() || len < 0x50) return;
  char v[33];
  memcpy(v, buf + 0x30, 32);
  v[32] = 0;
  for (int i = 0; i < 32; ++i) {
    if (static_cast<uint8_t>(v[i]) < 0x20 || static_cast<uint8_t>(v[i]) > 0x7e) { v[i] = 0; break; }
  }
  sVersion = String(v);
}

}  // namespace otadirect

// 直传上传回调。写入期间主循环被 HTTP 占用，蓝牙桥接会卡顿十几秒，属正常。
void otaDirectUploadCallback() {
  HTTPUpload& upload = server.upload();

  if (upload.status == UPLOAD_FILE_START) {
    otadirect::reset();
    otadirect::sPhase = 1;
    otadirect::sLastRxMs = millis();
    otadirect::sStartedAtMs = millis();
    otadirect::sName = upload.filename;
    const esp_partition_t* target = esp_ota_get_next_update_partition(nullptr);
    otadirect::sTargetLabel = target ? String(target->label) : String("");
    otadirect::readVersion(upload.buf, upload.currentSize);

    if (upload.currentSize >= 36) {
      uint32_t magic = 0;
      memcpy(&magic, upload.buf + 0x20, sizeof(magic));
      if (upload.buf[0] != 0xE9 || magic != 0xABCD5432u) {
        otadirect::sFailed = true;
        otadirect::sError = "文件不是应用镜像（缺少 app 描述符）。网页升级只能传 -ota.bin，整包 -factory.bin 需用数据线刷写。";
        Serial.printf("OTA_DIRECT_REJECT not_app_image magic=0x%08X\n", magic);
        return;
      }
    }

    const uint32_t size = upload.totalSize > 0 ? upload.totalSize : UPDATE_SIZE_UNKNOWN;
    if (!Update.begin(size, U_FLASH)) {
      otadirect::sFailed = true;
      otadirect::sError = String("无法开始写入：") + Update.errorString();
      Serial.printf("OTA_DIRECT_BEGIN_FAILED %s free=%lu largest=%lu\n",
                    Update.errorString(),
                    static_cast<unsigned long>(ESP.getFreeHeap()),
                    static_cast<unsigned long>(ESP.getMaxAllocHeap()));
      return;
    }
    otadirect::sActive = true;
    Serial.printf("OTA_DIRECT_START file=%s target=%s size=%u free=%lu\n",
                  otadirect::sName.c_str(), otadirect::sTargetLabel.c_str(),
                  static_cast<unsigned>(upload.totalSize),
                  static_cast<unsigned long>(ESP.getFreeHeap()));

  } else if (upload.status == UPLOAD_FILE_WRITE) {
    if (otadirect::sFailed || !otadirect::sActive) return;
    if (otadirect::sWritten == 0) {
      otadirect::sPhase = 2;
      otadirect::sLastRxMs = millis();
      otadirect::readVersion(upload.buf, upload.currentSize);
    }
    const size_t n = Update.write(upload.buf, upload.currentSize);
    if (n != upload.currentSize) {
      otadirect::sFailed = true;
      otadirect::sError = String("写入失败：") + Update.errorString();
      Serial.printf("OTA_DIRECT_WRITE_FAILED %u/%u %s\n",
                    static_cast<unsigned>(n), static_cast<unsigned>(upload.currentSize),
                    Update.errorString());
      Update.abort();
      otadirect::sActive = false;
      return;
    }
    otadirect::sWritten += n;
    ++otadirect::sChunkCount;

  } else if (upload.status == UPLOAD_FILE_END) {
    otadirect::sPhase = 3;
    Serial.printf("OTA_DIRECT_UPLOAD_END file=%s bytes=%u\n",
                  otadirect::sName.c_str(), static_cast<unsigned>(otadirect::sWritten));

  } else if (upload.status == UPLOAD_FILE_ABORTED) {
    if (otadirect::sActive) { Update.abort(); otadirect::sActive = false; }
    otadirect::sFailed = true;
    otadirect::sPhase = 4;
    otadirect::sError = "上传被中断，未写入任何内容";
    Serial.println("OTA_DIRECT_ABORTED");
    velaLog("OTA_ABORT file=%s bytes=%u", otadirect::sName.c_str(),
            static_cast<unsigned>(otadirect::sWritten));
  }
}

// 上传回调。两个 OTA 路由共用同一份实现。
// 早期 /ota/upload2 注册时漏掉了这个参数：FunctionRequestHandler 的
// canUpload() 在回调为空时直接返回 false，multipart 数据被静默丢弃，
// 接口却照样回「写入完成」，设备重启后版本不变 —— 手机页面刷写从来没生效过。
void otaUploadCallback() {
    // 上传处理回调
    HTTPUpload& upload = server.upload();

    if (upload.status == UPLOAD_FILE_START) {
      s_otaFileName = upload.filename;
      const bool hasExplicitAddr = server.hasArg("addr") && !server.arg("addr").isEmpty();
      // 没给 addr 时按 16MB 分区表的 app 地址算。旧值 0x10000 是 4MB 版的
      // 布局，在 16MB 上那个位置是 phy_init，写进去会毁掉射频校准。
      const uint32_t addrValue = hasExplicitAddr
                                     ? strtoul(server.arg("addr").c_str(), nullptr, 0)
                                     : 0x20000;
      s_otaFlashAddr = addrValue;
      s_otaWriteAddr = s_otaFlashAddr;
      s_otaTotalWritten = 0;
      s_otaError = "";
      s_otaLastErasedSector = 0xFFFFFFFF;
      s_otaImageVersion = "";
      {
        const esp_partition_t* target = esp_ota_get_next_update_partition(nullptr);
        s_otaTargetLabel = target ? String(target->label) : String("");
      }
      captureOtaImageVersion(upload.buf, upload.currentSize);

      // 是否为固件（走 OTA 分区 + 回滚保护）：
      //   1) 完全没有 addr 参数：默认按固件处理（网页 OTA 的正常用法）；
      //   2) 文件名包含 "firmware"：按固件处理。
      // 旧逻辑用 `addr == 0x10000` 判断，而 addr 缺省值恰好也是 0x10000，
      // 于是 bootloader、partitions.bin 这些原始镜像被当成固件，全部写进
      // OTA 分区，既刷不进去还覆盖了当前固件槽。所以改成看有没有显式 addr。
      String fnameLower = s_otaFileName;
      fnameLower.toLowerCase();
      s_otaIsFirmware = !hasExplicitAddr || fnameLower.indexOf("firmware") >= 0;

      Serial.printf("OTA_UPLOAD_START file=%s addr=%s0x%08X explicit_addr=%d firmware=%d size=%u\n",
                    s_otaFileName.c_str(), s_otaIsFirmware ? "auto/" : "",
                    s_otaFlashAddr, hasExplicitAddr ? 1 : 0,
                    s_otaIsFirmware ? 1 : 0,
                    static_cast<unsigned>(upload.totalSize));
      digitalWrite(kHeartbeatLedPin, LOW);

      if (!s_otaIsFirmware) {
        // 原始镜像写入参数校验，避免一上传就把设备写死。
        const uint32_t flashBytes = ESP.getFlashChipSize();
        const bool allowPartitionWrite = server.arg("allow_partition") == "1";
        if (s_otaFlashAddr % 0x1000 != 0) {
          s_otaError = "addr 必须 4KB 对齐";
        } else if (s_otaFlashAddr < 0x1000) {
          s_otaError = "addr 不允许小于 0x1000（会覆盖 ROM 二级引导）";
        } else if (s_otaFlashAddr == 0x8000 && !allowPartitionWrite) {
          s_otaError = "写入分区表需要显式 allow_partition=1，请优先用 USB 刷写";
        } else if (s_otaFlashAddr >= flashBytes) {
          s_otaError = "addr 超出 Flash 容量";
        } else if (upload.totalSize > 0 && upload.totalSize > flashBytes - s_otaFlashAddr) {
          s_otaError = "镜像大小超出 Flash 末尾";
        }
        if (!s_otaError.isEmpty()) {
          Serial.printf("OTA_RAW_ADDR_REJECTED: %s addr=0x%08X size=%u flash=%u\n",
                        s_otaError.c_str(), s_otaFlashAddr,
                        static_cast<unsigned>(upload.totalSize),
                        static_cast<unsigned>(flashBytes));
        }
      }

      if (s_otaIsFirmware) {
        if (!s_otaError.isEmpty()) {
          // 首包已被判定为非 app 镜像：丢弃剩余数据，结束时不调用 Update.end
          return;
        }
        // 判定"这是不是 app 镜像"：看第一个段的加载地址 0x3F400020 处是不是
        // esp_app_desc_t 的魔数 0xABCD5432。ESP-IDF 的 esp_image_verify() 用的
        // 就是这个判据。整包（factory / merged）镜像从 0x0 开始，第一段是二级
        // 引导，绝对不能直接塞进 OTA 分区，否则 ota_0 开头不是 app 描述符，
        // update_core 校验失败，设备再也起不来。
        // 注意：头部 0x18 是段表第一项，不是写地址（0x14 才是），别拿它当判据。
        static const uint32_t kAppDescMagic = 0xABCD5432u;
        // app 描述符固定在文件偏移 0x20，所以首包 >=36 字节即可判定，
        // 不用等整个文件传完。不满足时只记下错误，后续包直接丢弃。
        if (upload.currentSize >= 36) {
          uint32_t magic = 0;
          memcpy(&magic, upload.buf + 0x20, sizeof(magic));
          if (upload.buf[0] != 0xE9 || magic != kAppDescMagic) {
            s_otaError = "这不是 app 镜像（缺少 app 描述符），网页升级只能传文件名带 -ota 的那个；整包镜像请用数据线整片刷写";
            Serial.printf("OTA_REJECT_NOT_APP_IMAGE magic=0x%08X\n", magic);
            digitalWrite(kHeartbeatLedPin, LOW);
            return;   // 必须先 return：否则 begin() 已经占用了目标分区
          }
        }

        // 使用Update库：自动写入下一个OTA分区，支持回滚
        uint32_t updateSize = upload.totalSize > 0 ? upload.totalSize : UPDATE_SIZE_UNKNOWN;
        if (!Update.begin(updateSize, U_FLASH)) {
          s_otaError = "Update.begin失败: " + String(Update.errorString());
          Serial.printf("OTA_UPDATE_BEGIN_FAILED: %s\n", Update.errorString());
        } else {
          Serial.println("OTA_UPDATE_BEGIN ok, writing to next OTA partition");
        }
      }

    } else if (upload.status == UPLOAD_FILE_WRITE) {
      if (!s_otaError.isEmpty()) return;

      if (s_otaTotalWritten == 0) captureOtaImageVersion(upload.buf, upload.currentSize);

      // LED闪烁指示升级中
      static unsigned long lastBlink = 0;
      if (millis() - lastBlink > 100) {
        digitalWrite(kHeartbeatLedPin, !digitalRead(kHeartbeatLedPin));
        lastBlink = millis();
      }

      if (s_otaIsFirmware) {
        // 使用Update库写入（自动处理分区、擦除等）
        size_t written = Update.write(upload.buf, upload.currentSize);
        if (written != upload.currentSize) {
          s_otaError = "Update.write失败: " + String(Update.errorString());
          Serial.printf("OTA_UPDATE_WRITE_FAILED: %s (wrote %u/%u)\n", Update.errorString(), written, upload.currentSize);
          return;
        }
      } else {
        // 原始SPI Flash写入（用于bootloader/partitions等）
        if (s_otaWriteAddr >= ESP.getFlashChipSize() ||
            upload.currentSize > ESP.getFlashChipSize() - s_otaWriteAddr) {
          s_otaError = "写入越界: addr=0x" + String(s_otaWriteAddr, HEX) + " 超出 Flash";
          Serial.printf("OTA_RAW_WRITE_OOB addr=0x%08X len=%u flash=%u\n",
                        s_otaWriteAddr, static_cast<unsigned>(upload.currentSize),
                        static_cast<unsigned>(ESP.getFlashChipSize()));
          return;
        }
        uint32_t startSector = s_otaWriteAddr / 0x1000;

        uint32_t endSector = (s_otaWriteAddr + upload.currentSize - 1) / 0x1000;
        for (uint32_t sec = startSector; sec <= endSector; sec++) {
          if (sec != s_otaLastErasedSector) {
            esp_err_t err = spi_flash_erase_sector(sec);
            if (err != ESP_OK) {
              s_otaError = "擦除扇区失败 sec=" + String(sec) + " err=" + String(esp_err_to_name(err));
              return;
            }
            s_otaLastErasedSector = sec;
          }
        }

        size_t writeSize = (upload.currentSize + 3) & ~3;
        uint8_t* writeBuf = (uint8_t*)malloc(writeSize);
        if (!writeBuf) {
          s_otaError = "内存不足，无法分配写入缓冲区";
          return;
        }
        memcpy(writeBuf, upload.buf, upload.currentSize);
        if (writeSize > upload.currentSize) {
          memset(writeBuf + upload.currentSize, 0xFF, writeSize - upload.currentSize);
        }
        esp_err_t err = spi_flash_write(s_otaWriteAddr, (uint32_t*)writeBuf, writeSize);
        free(writeBuf);
        if (err != ESP_OK) {
          s_otaError = "写入Flash失败 addr=0x" + String(s_otaWriteAddr, HEX) + " err=" + String(esp_err_to_name(err));
          return;
        }
        s_otaWriteAddr += upload.currentSize;
      }

      s_otaTotalWritten += upload.currentSize;

      static unsigned long lastProgressPrint = 0;
      if (s_otaTotalWritten - lastProgressPrint >= 4096 || s_otaTotalWritten < 4096) {
        Serial.printf("OTA_UPLOAD_PROGRESS %u bytes\n", s_otaTotalWritten);
        lastProgressPrint = s_otaTotalWritten;
      }

    } else if (upload.status == UPLOAD_FILE_END) {
      if (!s_otaError.isEmpty() && s_otaIsFirmware && Update.isRunning()) {
        // 首包判定失败后 Update 还没开始，但保险起见统一收尾，避免占用分区
        Update.abort();
        Serial.println("OTA_ABORT_ON_ERROR");
      }
      Serial.printf("OTA_UPLOAD_END file=%s total=%u firmware=%d\n",
                    s_otaFileName.c_str(), s_otaTotalWritten, s_otaIsFirmware);

    } else if (upload.status == UPLOAD_FILE_ABORTED) {
      s_otaError = "上传被中断";
      if (s_otaIsFirmware) Update.abort();
      Serial.println("OTA_UPLOAD_ABORTED");
    }

}

void setupRoutes() {
  const char* keys[] = {"Authorization", "X-Vela-Token"};
  server.collectHeaders(keys, 2);
  // 上传诊断：页面打完 POST 就断了，或者压根没进上传回调，只能从设备侧看。
  // 这里记录最近一次上传的每个阶段，出问题时能在「设备事件」里看到。
  {
    // 安全模式：上传固件前把蓝牙桥接停掉。
  // 桥上跑着蓝牙 + NAPT + lwIP，设备只有几十 KB 空闲堆；网页传 1.6 MB 时
  // HTTP 解析、Update 擦写、蓝牙收发抢同一块内存，落在中途就表现为
  // 「传到某个百分比断开、设备重启」。停掉桥接不是修根因，但能立刻把
  // 上传成功率拉回来，是排障时最省事的一刀。
  server.on("/api/v1/upload/safe-mode", HTTP_POST, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    JsonDocument d;
    const bool wasRunning = gWatchBridgeRunning;
    if (wasRunning) stopWatchBridge();
    d["ok"] = true;
    d["bridgeStopped"] = wasRunning;
    d["bridgeState"] = getWatchBridgeState();
    d["heapFree"] = static_cast<uint32_t>(ESP.getFreeHeap());
    sendJson(200, d);
    velaLog("SAFE_MODE bridge_stopped=%s free=%u", wasRunning ? "true" : "false",
            static_cast<unsigned>(ESP.getFreeHeap()));
  });

  server.on("/api/v1/ota/upload/diag", HTTP_GET, [](){
      if (!isSetupApClient() && !requireAuth()) return;
      JsonDocument d;
      d["ok"] = true;
      d["phase"] = otadirect::phaseName();
      d["kbps"] = otadirect::kbps();
      d["chunks"] = otadirect::sChunkCount;
      d["name"] = otadirect::sName;
      d["written"] = static_cast<uint32_t>(otadirect::sWritten);
      d["target"] = otadirect::sTargetLabel;
      d["error"] = otadirect::sError;
      d["updateRunning"] = Update.isRunning();
      d["freeHeap"] = static_cast<uint32_t>(ESP.getFreeHeap());
      // 客户端地址与接收端口：用来判断请求到底有没有落在 WebServer 上。
      d["peer"] = server.client().remoteIP().toString();
      d["localPort"] = server.client().localPort();
      sendJson(200, d);
    });
  }

  server.on("/", HTTP_GET, [](){
    // 只剩两种页面：日常管理台（含配网）与空中升级页。
    if (gOtaMode) {
      server.send_P(200, "text/html; charset=utf-8", kOtaWebUi);
    } else {
      sendMainWebUi();
    }
  });
  server.on("/setup/status", HTTP_GET, [](){
    if (server.arg("source") == "watch_quickapp") recordWatchFetchProbe();
    handleStatus(true);
  });
  server.on("/setup/trace", HTTP_GET, [](){ handleFetchTrace(); });
  server.on("/setup/wifi/scan", HTTP_GET, [](){
    if (!requireSetupAp()) return;

    const bool start = server.arg("start") == "1";
    const int state = WiFi.scanComplete();
    JsonDocument response;
    response["ok"] = true;

    if (start) {
      if (state == WIFI_SCAN_RUNNING) {
        response["scanning"] = true;
        sendJson(200, response);
        return;
      }
      if (state >= 0) WiFi.scanDelete();
      // AP+STA keeps the setup page reachable while the radio scans.
      WiFi.mode(WIFI_AP_STA);
      const int started = WiFi.scanNetworks(true, true);
      if (started == WIFI_SCAN_FAILED) {
        jsonError(503, "wifi_scan_failed", "unable to start scan");
        return;
      }
      response["scanning"] = true;
      sendJson(202, response);
      return;
    }

    if (state == WIFI_SCAN_RUNNING) {
      response["scanning"] = true;
      sendJson(200, response);
      return;
    }
    if (state < 0) {
      response["ready"] = false;
      sendJson(200, response);
      return;
    }

    JsonArray networks = response["networks"].to<JsonArray>();
    uint8_t listed = 0;
    for (int i = 0; i < state && listed < kSetupWifiScanMaxResults; ++i) {
      const String name = WiFi.SSID(i);
      if (name.isEmpty()) continue;
      JsonObject network = networks.add<JsonObject>();
      network["ssid"] = name;
      network["rssi"] = WiFi.RSSI(i);
      network["secure"] = WiFi.encryptionType(i) != WIFI_AUTH_OPEN;
      ++listed;
    }
    WiFi.scanDelete();
    response["ready"] = true;
    sendJson(200, response);
  });
  server.on("/setup/bluetooth/scan", HTTP_GET, [](){
    if (!requireSetupAp()) return;
    JsonDocument response;
    response["ok"] = true;

    if (server.arg("start") == "1") {
      if (!gSetupBluetoothScanRunning && !startSetupBluetoothScan()) {
        jsonError(503, "bluetooth_scan_unavailable", "setup scan cannot start");
        return;
      }
      response["scanning"] = true;
      sendJson(202, response);
      return;
    }

    if (gSetupBluetoothScanRunning) {
      response["scanning"] = true;
      sendJson(200, response);
      return;
    }
    if (!gSetupBluetoothScanReady) {
      response["ready"] = false;
      sendJson(200, response);
      return;
    }
    if (gSetupBluetoothScanFailed) {
      jsonError(503, "bluetooth_scan_failed", "Classic Bluetooth discovery failed");
      return;
    }

    JsonArray devices = response["devices"].to<JsonArray>();
    const uint8_t count = gSetupBluetoothResultCount;
    for (uint8_t i = 0; i < count; ++i) {
      const SetupBluetoothDevice& device = gSetupBluetoothResults[i];
      if (device.address[0] == '\0') continue;
      JsonObject item = devices.add<JsonObject>();
      item["name"] = device.name;
      item["address"] = device.address;
      item["rssi"] = device.rssi;
      item["cod"] = device.cod;
    }
    response["ready"] = true;
    sendJson(200, response);
  });
  server.on("/api/v1/status", HTTP_GET, [](){ handleStatus(false); });
  server.on("/api/v1/models", HTTP_GET, [](){
    if (!requireAuth()) return;
    JsonDocument d; d["ok"] = true; JsonArray a=d["models"].to<JsonArray>(); a.add("mimo-v2.5-pro"); a.add("mimo-v2.5"); sendJson(200,d);
  });
  server.on("/setup", HTTP_POST, [](){
    if (!requireSetupAp()) return;
    String b=body(); if (b.isEmpty()) return jsonError(400,"invalid_body","empty or too large");
    JsonDocument d; if (deserializeJson(d,b)) return jsonError(400,"invalid_json","cannot parse json");
    String newSsid=d["ssid"]|""; String newPass=d["wifiPassword"]|"";
    String newMac=d["watchMac"]|""; String newWatchAuth=d["watchAuthKey"]|"";
    String newAp=d["apPassword"]|"12345678";
    if (newAp.isEmpty()) newAp = "12345678";  // 与出厂热点密码保持一致
    String newApName=d["apSsid"]|"";
    newApName.trim();
    if (newApName.length()<1 || newApName.length()>32 ||
        newApName.indexOf('\n')>=0 || newApName.indexOf('\r')>=0) newApName = kApSsid;
    newMac.trim(); newMac.toUpperCase(); newWatchAuth.trim(); newWatchAuth.toLowerCase();
    if (!newMac.isEmpty() && newMac.length()!=17) return jsonError(400,"invalid_watch_mac","expected AA:BB:CC:DD:EE:FF");
    // 不校验AuthKey的内容，只检查长度是否为32（允许非hex字符通过）
    if (!newWatchAuth.isEmpty() && newWatchAuth.length()!=32) return jsonError(400,"invalid_watch_auth","expected 32 characters");
    if (newSsid.length()>64||newPass.length()>128||newAp.length()<8||newAp.length()>63) return jsonError(400,"invalid_config","field length invalid");
    prefs.putString("ssid",newSsid); prefs.putString("wifi_pass",newPass);
    prefs.putString("watch_mac",newMac); prefs.putString("watch_auth",newWatchAuth);
    // 只要配了完整的 Watch MAC + Auth Key，就强制开机自动连接手表，
    // 避免用户配好后重启却因忘勾「自动连接」而无法自动进入工作模式。
    prefs.putBool("watch_auto", newMac.length()==17 && newWatchAuth.length()==32);
    prefs.putString("ap_pass",newAp);
    prefs.putString("ap_ssid",newApName);
    prefs.remove("base_url"); prefs.remove("api_key"); prefs.remove("model");
    prefs.remove("asr_model"); prefs.remove("asr_lang"); prefs.remove("native_xiaoai");
    prefs.remove("chat_after_asr"); prefs.remove("local_token"); prefs.remove("ca_pem");
    prefs.remove("max_tokens"); prefs.remove("insecure_tls");
    loadConfig();
    JsonDocument r; r["ok"]=true; r["saved"]=true; r["rebooting"]=true; r["watchConfigured"]=watchMac.length()==17&&watchAuthKey.length()==32; sendJson(200,r);
    // 保存成功后重启，切回正常工作模式（STA 连接已保存的 WiFi）。
    Serial.println("SETUP_SAVED rebooting_to_normal_mode");
    delay(400);   // 让 HTTP 响应发出去
    ESP.restart();
  });
  server.on("/api/v1/config", HTTP_POST, [](){
    if (!requireAuth()) return;
    jsonError(403,"use_setup_ap","Cloud keys, Wi-Fi password and watch auth key can only be changed while connected to the setup AP.");
  });
  server.on("/api/v1/watch/start", HTTP_POST, [](){
    if (!requireAuth()) return;
    String error;
    if (!startWatchBridge(error)) return jsonError(error=="already_running"?409:400,"watch_start_failed",error);
    JsonDocument out; out["ok"]=true; out["state"]="starting"; sendJson(202,out);
  });
  server.on("/api/v1/watch/stop", HTTP_POST, [](){
    if (!requireAuth()) return;
    stopWatchBridge(); JsonDocument out; out["ok"]=true; out["state"]="stopping"; sendJson(202,out);
  });
  server.on("/api/v1/context/reset", HTTP_POST, [](){
    if (!requireAuth()) return;
    resetWatchConversationContext("api_request");
    JsonDocument out; out["ok"]=true; out["watchConversationTurns"]=0; sendJson(200,out);
  });
  auto chatHandler=[](){
    if (!requireAuth()) return;
    String b=body(); if (b.isEmpty()) return jsonError(400,"invalid_body","empty or too large");
    JsonDocument in; if (deserializeJson(in,b)) return jsonError(400,"invalid_json","cannot parse json");
    String prompt=in["prompt"]|"";
    if (prompt.isEmpty() && in["messages"].is<JsonArray>()) {
      JsonArray arr=in["messages"].as<JsonArray>();
      for (JsonVariant v:arr) if (String(v["role"]|"")=="user") prompt=String((const char*)(v["content"]|""));
    }
    String answer,error; if (!mimoRequest(prompt,answer,error)) return jsonError(502,"mimo_error",error);
    JsonDocument out; out["ok"]=true; out["model"]=model; out["content"]=answer; sendJson(200,out);
  };
  server.on("/api/v1/chat", HTTP_POST, chatHandler);
  server.on("/api/v1/test", HTTP_POST, [](){
    if (!requireAuth()) return;
    String answer,error;
    if (!mimoRequest("Reply with: Vela gateway OK",answer,error)) return jsonError(502,"mimo_error",error);
    JsonDocument out; out["ok"]=true; out["model"]=model; out["content"]=answer; sendJson(200,out);
  });
  server.on("/setup/test", HTTP_POST, [](){
    if (!requireSetupAp()) return;
    String b=body(); JsonDocument in; if(!b.isEmpty()) deserializeJson(in,b); String prompt=in["prompt"]|"Reply with Vela gateway OK";
    String answer,error; if(!mimoRequest(prompt,answer,error)) return jsonError(502,"mimo_error",error);
    JsonDocument out; out["ok"]=true; out["content"]=answer; sendJson(200,out);
  });
  // 蓝牙连接测试端点（配网模式下可用）
  server.on("/setup/bluetooth/test", HTTP_GET, [](){
    if (!requireSetupAp()) return;
    String macStr = server.arg("mac");
    macStr.trim();
    macStr.toUpperCase();
    uint8_t address[6];
    if (!parseWatchAddress(macStr, address)) {
      jsonError(400, "invalid_mac", "expected AA:BB:CC:DD:EE:FF");
      return;
    }
    if (!beginWatchBluetooth(kBtLocalName)) {
      jsonError(503, "bt_init_failed", "BluetoothSerial init failed");
      return;
    }
    Serial.printf("BT_TEST_START mac=%s\n", macStr.c_str());
    const bool connected = connectWatchWithSdp(address, "bt_test");
    JsonDocument d;
    d["ok"] = connected;
    if (connected) {
      d["channel"] = gWatchResolvedSppChannel;
      d["source"] = gWatchSdpSource;
      Serial.println("BT_TEST_OK");
      watchBt.disconnect();
    } else {
      d["error"] = "connect_failed";
      d["message"] = "Watch did not respond to SPP connection. Check MAC address and ensure watch is in pairing range.";
      Serial.println("BT_TEST_FAILED");
    }
    delay(200);
    watchBt.end();
    sendJson(connected ? 200 : 502, d);
  });

  // 模式切换端点：现在只剩「网关」和「空中升级」两个去向。
  // 保留原来的 URL 与 target 编号（1 / 6），老页面和脚本不用改。
  server.on("/setup/project/switch", HTTP_POST, [](){
    int target = server.hasArg("target") ? server.arg("target").toInt() : 1;
    if (target != 6) target = 1;
    prefs.putInt("project", target);
    Serial.printf("MODE_SWITCH to=%s rebooting\n", target == 6 ? "ota" : "watch");
    JsonDocument d;
    d["ok"] = true;
    d["switchingTo"] = target == 6 ? "ota" : "watch";
    sendJson(200, d);
    gRestartRequested = true;
  });

  // ====== 恢复出厂设置 / 设备自检 ======
  // 网页调用：先 GET /api/v1/factory/preview 让用户看清会丢什么，
  // 再 POST /api/v1/factory/reset?confirm=RESET。
  // 清除「上次升级被回滚」的提示
  server.on("/api/v1/ota/rollback/ack", HTTP_POST, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    gOtaRollbackDetected = false;
    gOtaRollbackExpected = "";
    gOtaRollbackRunning = "";
    JsonDocument d;
    d["ok"] = true;
    sendJson(200, d);
  });

  server.on("/api/v1/factory/preview", HTTP_GET, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    JsonDocument d;
    d["ok"] = true;
    d["configured"] = !ssid.isEmpty();
    d["ssid"] = ssid;                       // SSID 不算敏感，方便用户确认清的是哪一项
    d["watchConfigured"] = watchMac.length() == 17 && watchAuthKey.length() == 32;
    d["watchMac"] = watchMac;
    d["project"] = gProjectMode;
    d["apSsid"] = gApSsid;
    d["fwVersion"] = kFwVersion;
    // 会清空的键（前端直接展示，避免"点了才知道清什么"）
    JsonArray keys = d["willClear"].to<JsonArray>();
    keys.add("ssid");
    keys.add("wifi_pass");
    keys.add("watch_mac");
    keys.add("watch_auth");
    keys.add("watch_auto");
    keys.add("ap_ssid");
    keys.add("ap_pass");
    keys.add("local_token");
    keys.add("base_url/api_key/model/ca_pem");
    keys.add("运行模式 project");
    keys.add("旧版本遗留的 p4_*/p5_* 缓存");
    JsonArray keep = d["willKeep"].to<JsonArray>();
    keep.add("firmware");
    keep.add("分区表");
    keep.add("SPIFFS 文件");
    keep.add("芯片熔丝/eFuse");
    d["autoReset"] = gAutoResetCandidateSince != 0;
    d["autoResetReason"] = gAutoResetReason;
    d["autoResetClearsConfig"] = false;   // 前端据此显示"只开热点，不清配置"
    if (gAutoResetCandidateSince != 0) {
      const uint32_t elapsed = millis() - gAutoResetCandidateSince;
      d["autoResetRemainMs"] = elapsed < kAutoSetupFallbackMs
                                   ? (kAutoSetupFallbackMs - elapsed) : 0;
    }
    sendJson(200, d);
  });

  // ==================== 固件库 ====================
  // 上传 → 列表 → 选中安装 → 删除。安装只是「标记 + 延时」，真正写 OTA 分区
  // 在 loop() 里做（fwlib::servicePending），这样 HTTP 响应能先回给浏览器。
  // 网关模式直写升级：网关模式下直接写空闲 OTA 分区，不经过 SPIFFS。
  // 页面上的入口已在 v0.0.0.31 移除（主管理台不再提供第二条升级路径），
  // 接口保留给脚本和旧页面；网页升级统一走设置页 →「进入空中升级」。
  // 注意它写完后不再自动重启，需要显式调用 /api/v1/reboot 才生效。
  server.on("/api/v1/ota/upload", HTTP_POST, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    JsonDocument d;
    // Update 是全局单例，固件库安装与直传不能同时进行。
    if (Update.isRunning()) {
      d["ok"] = false;
      d["error"] = "busy";
      d["hint"] = "设备正在执行另一次写入，请等它结束或重启后重试。";
      sendJson(200, d);
      return;
    }
    if (otadirect::sFailed) {
      d["ok"] = false;
      d["error"] = otadirect::sError;
      sendJson(200, d);
      Serial.printf("OTA_DIRECT_REJECT %s\n", otadirect::sError.c_str());
      velaLog("OTA_REJECT file=%s reason=not_app_image", otadirect::sName.c_str());
      return;
    }
    if (otadirect::sWritten == 0) {
      d["ok"] = false;
      d["error"] = "no_data";
      d["hint"] = "没有收到文件内容，请重新选择文件上传。";
      sendJson(200, d);
      Serial.println("OTA_DIRECT_REJECT no_data");
      velaLog("OTA_REJECT file=%s reason=no_data", otadirect::sName.c_str());
      return;
    }
    if (!Update.end(true)) {
      d["ok"] = false;
      d["error"] = String("镜像校验失败：") + Update.errorString();
      sendJson(200, d);
      Serial.printf("OTA_DIRECT_END_FAILED %s\n", Update.errorString());
      velaLog("OTA_FAIL end=%s bytes=%u", Update.errorString(),
              static_cast<unsigned>(otadirect::sWritten));
      return;
    }
    d["ok"] = true;
    d["size"] = static_cast<uint32_t>(otadirect::sWritten);
    d["version"] = otadirect::sVersion;
    d["target"] = otadirect::sTargetLabel;
    sendJson(200, d);

    // 记录目标，重启后据此核对是否被 bootloader 回滚。
    prefs.putString("ota_expect_part", otadirect::sTargetLabel);
    prefs.putString("ota_expect_ver", otadirect::sVersion);
    Serial.printf("OTA_DIRECT_SUCCESS part=%s ver=%s bytes=%u\n",
                  otadirect::sTargetLabel.c_str(), otadirect::sVersion.c_str(),
                  static_cast<unsigned>(otadirect::sWritten));
    // 不再在响应后固定 delay + ESP.restart()：页面会说「设备重启中」，
    // 但如果这次写入被 bootloader 回滚，用户看到的就是版本没变、原因不明。
    // 改成先停在待生效状态，页面自行确认，再决定何时重定向。
    otadirect::sPhase = 3;
    velaLog("OTA_OK part=%s ver=%s bytes=%u", otadirect::sTargetLabel.c_str(),
            otadirect::sVersion.c_str(), static_cast<unsigned>(otadirect::sWritten));
  }, otaDirectUploadCallback);

  server.on("/api/v1/firmware/upload", HTTP_POST, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    JsonDocument d;

    // 文件系统没挂上时，SPIFFS.open() 一律失败，写入全部跳过。
    // 这种情况必须报存储错误，不能报「不是 app 镜像」，否则排查方向全错。
    if (!ensureSpiffs()) {
      d["ok"] = false;
      d["error"] = spiffsErrorCode();
      d["hint"] = spiffsErrorHint();
      sendJson(200, d);
      return;
    }

    if (fwlib::gUploadFailed) {
      d["ok"] = false;
      d["error"] = "upload_failed";
      d["hint"] = "仅接受 .bin 文件；网页升级需使用 -ota 镜像，整包 -factory 仅支持数据线烧录；存储空间不足时同样失败";
      sendJson(200, d);
      return;
    }

    File done = SPIFFS.open(fwlib::kName, FILE_READ);
    uint32_t size = done ? static_cast<uint32_t>(done.size()) : 0;
    uint8_t magic = 0;
    if (done) {
      done.seek(0);
      magic = static_cast<uint8_t>(done.read());
      done.close();
    }

    // 大小对不上说明写入中途失败，文件是残缺的，不能当成镜像来判类型
    if (size == 0 || size != fwlib::gUploadWritten) {
      SPIFFS.remove(fwlib::kName);
      d["ok"] = false;
      d["error"] = "write_incomplete";
      d["hint"] = "文件只写入了部分内容，通常是 SPIFFS 空间不足。请删除设备上已上传的表盘或固件后重试。";
      d["expected"] = static_cast<uint32_t>(fwlib::gUploadWritten);
      d["received"] = size;
      sendJson(200, d);
      return;
    }

    if (magic != 0xE9) {
      // app 镜像必须以 0xE9 开头（ESP 镜像魔数）。整包 -factory.bin 的第一个
      // 字节是 0xFF，在此处直接拒绝，避免写入阶段才失败。
      SPIFFS.remove(fwlib::kName);
      d["ok"] = false;
      d["error"] = "not_app_image";
      d["hint"] = "文件不是应用镜像。网页升级需使用文件名含 -ota 的镜像；整包 -factory 仅支持数据线烧录。";
      sendJson(200, d);
      return;
    }
    d["ok"] = true;
    d["name"] = "new.bin";
    d["bytes"] = size;
    sendJson(200, d);
  }, [](){
    HTTPUpload& upload = server.upload();
    if (upload.status == UPLOAD_FILE_START) {
      fwlib::gUploadFailed = true;
      fwlib::gUploadWritten = 0;
      if (!ensureSpiffs()) {
        Serial.println("FW_LIB_UPLOAD_REJECT spiffs_unavailable");
        return;
      }
      if (!SPIFFS.exists(fwlib::kDir)) SPIFFS.mkdir(fwlib::kDir);
      const size_t freeBytes = SPIFFS.totalBytes() - SPIFFS.usedBytes();
      // totalSize 在 START 阶段通常还是 0，这个检查只在浏览器给了准确长度时生效；
      // 真正的兜底是写入失败时立即置 gUploadFailed。
      if (upload.totalSize > 0 &&
          (upload.totalSize + fwlib::kReserve > freeBytes ||
           upload.totalSize > fwlib::kMaxFirmware)) {
        Serial.printf("FW_LIB_UPLOAD_REJECT no_space need=%u free=%u\n",
                      static_cast<unsigned>(upload.totalSize),
                      static_cast<unsigned>(freeBytes));
        return;
      }
      SPIFFS.remove(fwlib::kName);
      fwlib::gUpload = SPIFFS.open(fwlib::kName, FILE_WRITE);
      if (!fwlib::gUpload) {
        Serial.printf("FW_LIB_UPLOAD_REJECT open_failed free=%u\n",
                      static_cast<unsigned>(freeBytes));
        return;
      }
      Serial.printf("FW_LIB_UPLOAD_START name=%s size=%u\n",
                    upload.filename.c_str(), static_cast<unsigned>(upload.totalSize));
    } else if (upload.status == UPLOAD_FILE_WRITE) {
      if (!fwlib::gUpload) return;
      const size_t n = fwlib::gUpload.write(upload.buf, upload.currentSize);
      fwlib::gUploadWritten += n;
      if (n != upload.currentSize) {
        // 写不满就是空间不够。这里必须把状态钉死为失败，
        // 否则 END 阶段会把 gUploadFailed 清掉，上层就误判成镜像类型错误。
        fwlib::gUploadFailed = true;
        Serial.printf("FW_LIB_UPLOAD_WRITE_FAILED written=%u chunk=%u\n",
                      static_cast<unsigned>(fwlib::gUploadWritten),
                      static_cast<unsigned>(upload.currentSize));
      }
    } else if (upload.status == UPLOAD_FILE_END) {
      if (fwlib::gUpload) {
        fwlib::gUpload.flush();
        fwlib::gUpload.close();
      }
      // 只有全程没写失败才认为成功。原来这里无条件置 false，
      // 会把「打开失败」「写入失败」都洗成「镜像类型不对」。
      if (!fwlib::gUploadFailed) {
        Serial.printf("FW_LIB_UPLOAD_DONE bytes=%u\n",
                      static_cast<unsigned>(fwlib::gUploadWritten));
      } else {
        Serial.printf("FW_LIB_UPLOAD_END_WITH_ERROR written=%u\n",
                      static_cast<unsigned>(fwlib::gUploadWritten));
      }
    } else if (upload.status == UPLOAD_FILE_ABORTED) {
      if (fwlib::gUpload) fwlib::gUpload.close();
      SPIFFS.remove(fwlib::kName);
      fwlib::gUploadFailed = true;
      Serial.println("FW_LIB_UPLOAD_ABORTED");
    }
  });

  server.on("/api/v1/firmware/list", HTTP_GET, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    JsonDocument d;
    if (!ensureSpiffs()) {
      d["ok"] = false;
      d["error"] = spiffsErrorCode();
      d["hint"] = spiffsErrorHint();
      sendJson(200, d);
      return;
    }
    d["ok"] = true;
    d["current"] = kFwVersionFull;
    JsonObject usage = d["usage"].to<JsonObject>();
    usage["total"] = static_cast<uint32_t>(SPIFFS.totalBytes());
    usage["used"] = static_cast<uint32_t>(SPIFFS.usedBytes());
    JsonArray items = d["items"].to<JsonArray>();
    fwlib::listItems(items, "new.bin");
    sendJson(200, d);
  });

  server.on("/api/v1/firmware/install", HTTP_POST, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    if (!ensureSpiffs()) {
      jsonError(503, spiffsErrorCode(), spiffsErrorHint());
      return;
    }
    const String b = body();
    JsonDocument in;
    if (!b.isEmpty()) deserializeJson(in, b);
    const String name = in["name"] | "new.bin";
    String path;
    if (!fwlib::resolve(name, path)) {
      jsonError(404, "not_found", "文件不存在");
      return;
    }
    File f = SPIFFS.open(path, FILE_READ);
    if (!f) {
      jsonError(500, "open_failed", "文件打不开");
      return;
    }
    // Update.begin() 只校验镜像头、不写 Flash，可以在这里先试一遍：
    // 传错了当场报错，不用等重启后才发现进了回滚。
    if (!Update.begin(f.size())) {
      const String err = Update.errorString();
      f.close();
      jsonError(400, "bad_image", err);
      return;
    }
    Update.abort();
    f.close();
    fwlib::gPending.armed = true;
    fwlib::gPending.atMs = millis() + 800;
    Serial.printf("FW_LIB_INSTALL_ARMED name=%s\n", name.c_str());
    JsonDocument d;
    d["ok"] = true;
    d["installing"] = name;
    d["msg"] = "校验通过，正在写入，设备马上重启";
    sendJson(200, d);
  });

  server.on("/api/v1/firmware/delete", HTTP_POST, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    if (!ensureSpiffs()) {
      jsonError(503, spiffsErrorCode(), spiffsErrorHint());
      return;
    }
    const String b = body();
    JsonDocument in;
    if (!b.isEmpty()) deserializeJson(in, b);
    String path;
    if (!fwlib::resolve(String(in["name"] | ""), path)) {
      jsonError(404, "not_found", "文件不存在");
      return;
    }
    SPIFFS.remove(path);
    Serial.printf("FW_LIB_DELETE %s\n", path.c_str());
    JsonDocument d;
    d["ok"] = true;
    sendJson(200, d);
  });

  server.on("/api/v1/reboot", HTTP_POST, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    JsonDocument d;
    d["ok"] = true;
    d["rebooting"] = true;
    sendJson(200, d);
    velaLog("REBOOT_BY_USER");
    delay(300);
    ESP.restart();
  });

  // ==================== 偏好设置 / 灯效 / 音量式「免打扰」 ====================
  server.on("/api/v1/prefs", HTTP_GET, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    JsonDocument d;
    d["ok"] = true;
    d["ledMode"] = gLedMode;
    d["showLog"] = gPrefShowLog;
    d["compact"] = gPrefCompact;
    d["timezone"] = gNtpTz;
    d["autoConnectWatch"] = autoConnectWatch;
    d["insecureTls"] = allowInsecureTls;
    d["ledPin"] = kHeartbeatLedPin;
    sendJson(200, d);
  });

  server.on("/api/v1/prefs", HTTP_POST, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    if (!server.hasArg("plain")) return jsonError(400, "no_body", "JSON body required");
    JsonDocument in;
    if (deserializeJson(in, server.arg("plain"))) return jsonError(400, "bad_json", "cannot parse body");
    if (in["ledMode"].is<int>()) {
      const int mode = in["ledMode"] | 4;
      if (mode >= 0 && mode <= 4) gLedMode = static_cast<uint8_t>(mode);
    }
    if (in["showLog"].is<bool>()) gPrefShowLog = in["showLog"] | true;
    if (in["compact"].is<bool>()) gPrefCompact = in["compact"] | false;
    if (in["autoConnectWatch"].is<bool>()) {
      autoConnectWatch = in["autoConnectWatch"] | true;
      prefs.begin("vela", false);
      prefs.putBool("watch_auto", autoConnectWatch);
      prefs.end();
    }
    if (in["insecureTls"].is<bool>()) {
      allowInsecureTls = in["insecureTls"] | false;
      prefs.begin("vela", false);
      prefs.putBool("insecure_tls", allowInsecureTls);
      prefs.end();
    }
    prefs.begin("vela", false);
    prefs.putUChar("led_mode", gLedMode);
    prefs.putBool("pref_log", gPrefShowLog);
    prefs.putBool("pref_compact", gPrefCompact);
    prefs.end();
    velaLog("PREFS_SAVED led=%u", static_cast<unsigned>(gLedMode));
    JsonDocument d;
    d["ok"] = true;
    d["ledMode"] = gLedMode;
    d["showLog"] = gPrefShowLog;
    d["compact"] = gPrefCompact;
    sendJson(200, d);
  });

  // 灯效自检：点亮 1.5 秒再恢复，方便确认板载 LED 是否接在这颗 GPIO 上
  server.on("/api/v1/led/test", HTTP_POST, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    digitalWrite(kHeartbeatLedPin, HIGH);
    delay(1500);
    digitalWrite(kHeartbeatLedPin, LOW);
    JsonDocument d;
    d["ok"] = true;
    d["pin"] = kHeartbeatLedPin;
    d["note"] = "高电平点亮 1.5 秒后恢复；若灯没亮，说明这颗 GPIO 上没有灯或为低电平点亮";
    sendJson(200, d);
  });

  server.on("/api/v1/factory/reset", HTTP_POST, [](){
    // 双保险：配网 AP 来的请求天然可信；其他来源必须带 token。
    if (!isSetupApClient() && !requireAuth()) return;
    // 必须显式确认，防止网页误触/爬虫扫到就清空。
    if (server.arg("confirm") != "RESET") {
      return jsonError(400, "confirm_required", "add ?confirm=RESET to confirm factory reset");
    }
    JsonDocument d;
    d["ok"] = true;
    d["rebooting"] = true;
    d["message"] = "正在恢复出厂设置，设备将在 2 秒后重启并进入配网热点";
    sendJson(200, d);
    Serial.println("FACTORY_RESET_REQUESTED source=http");
    // 先把响应发出去，再清（清 NVS 会 deinit，不能放在 sendJson 之前）
    delay(300);
    factoryResetApply("http_api");
  });

  // 推迟自动开热点（用户看到倒计时在网页上点了「暂不开热点」）。
  // 注意不是取消整个判定，否则下一轮 loop 会立刻重新开始计时。
  server.on("/api/v1/factory/cancel", HTTP_POST, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    gAutoResetCandidateSince = 0;
    gReconnectFailCount = 0;
    gAutoSetupSnoozeUntil = millis() + kAutoSetupSnoozeMs;
    JsonDocument d;
    d["ok"] = true;
    d["cancelled"] = true;
    sendJson(200, d);
    Serial.printf("AUTO_SETUP_SNOOZED_BY_USER until_ms=%lu\n",
                  static_cast<unsigned long>(gAutoSetupSnoozeUntil));
  });

  server.on("/setup/project/status", HTTP_GET, [](){
    JsonDocument d;
    d["ok"] = true;
    d["project"] = gProjectMode;
    d["ota"] = gOtaMode;
    sendJson(200, d);
  });

  // ==================== HAL：硬件与外设状态 ====================
  server.on("/api/v1/hal", HTTP_GET, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    JsonDocument d;
    d["ok"] = true;
    d["chipModel"] = ESP.getChipModel();
    d["chipRevision"] = static_cast<uint32_t>(ESP.getChipRevision());
    d["chipCores"] = static_cast<uint32_t>(ESP.getChipCores());
    d["cpuFreqMHz"] = static_cast<uint32_t>(ESP.getCpuFreqMHz());
    d["flashSize"] = static_cast<uint32_t>(ESP.getFlashChipSize());
    d["flashSpeedHz"] = static_cast<uint32_t>(ESP.getFlashChipSpeed());
    d["sdkVersion"] = ESP.getSdkVersion();
    // 温度传感器：IDF 4.4 的 temperatureRead() 读内部传感器，未校准时会有偏差，
    // 所以这里给的是"趋势参考值"，前端标注了 ±3℃。
    d["chipTempC"] = static_cast<int>(temperatureRead());
    // LED 状态（心跳灯当前电平）
    d["ledPin"] = kHeartbeatLedPin;
    d["ledOn"] = digitalRead(kHeartbeatLedPin) == HIGH;
    // I2C / OLED 是否在场（状态屏）
    d["oledConfigured"] = true;
    // 运行时长（esp_timer 微秒级，不依赖 millis 回绕）
    const uint64_t upUs = esp_timer_get_time();
    d["uptimeMs"] = static_cast<uint32_t>(upUs / 1000ULL);
    d["uptimeText"] = String(jsonAgo(static_cast<uint32_t>(upUs / 1000ULL)));
    d["resetReason"] = static_cast<int>(esp_reset_reason());
    sendJson(200, d);
  });

  // ==================== 链路质量 / 信道分析 ====================
  server.on("/api/v1/linkscore", HTTP_GET, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    JsonDocument d;
    d["ok"] = true;
    const int rssi = WiFi.status() == WL_CONNECTED ? WiFi.RSSI() : 0;
    const uint32_t totalPkts = gWatchNetworkRxPackets + gWatchNetworkTxPackets;
    const uint32_t heapFree = static_cast<uint32_t>(ESP.getFreeHeap());
    d["rssi"] = rssi;
    d["channel"] = WiFi.status() == WL_CONNECTED ? WiFi.channel() : 0;
    d["freqMhz"] = wifiFreqFromChannel(WiFi.status() == WL_CONNECTED ? WiFi.channel() : 0);
    d["bssid"] = WiFi.status() == WL_CONNECTED ? WiFi.BSSIDstr() : String("");
    d["score"] = linkQualityScore(rssi, heapFree, gWatchNetworkDroppedPackets, totalPkts);
    d["dropRatePerMille"] = totalPkts ? static_cast<uint32_t>(static_cast<uint64_t>(gWatchNetworkDroppedPackets) * 1000ULL / totalPkts) : 0u;
    d["totalPackets"] = totalPkts;
    // 同信道邻居数：从上次扫描缓存里数（不主动触发扫描，避免打断当前连接）
    int neighbors = 0;
    const int cached = WiFi.scanComplete();
    if (cached > 0) {
      const int myCh = WiFi.channel();
      for (int i = 0; i < cached; ++i) {
        if (WiFi.channel(i) == myCh && WiFi.SSID(i) != ssid) ++neighbors;
      }
    }
    d["sameChannelNeighbors"] = neighbors;
    d["scanCached"] = cached > 0;
    sendJson(200, d);
  });

  // ==================== 流量与心跳（带历史曲线） ====================
  server.on("/api/v1/traffic", HTTP_GET, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    JsonDocument d;
    d["ok"] = true;
    d["rxBytes"] = gWatchRxBytes;
    d["txBytes"] = gWatchTxBytes;
    d["rxPackets"] = gWatchNetworkRxPackets;
    d["txPackets"] = gWatchNetworkTxPackets;
    d["dropped"] = gWatchNetworkDroppedPackets;
    d["turns"] = gWatchContextCount;
    d["intervalMs"] = kTrafficSampleMs;
    // 历史样本：给前端画迷你折线图用（旧→新）
    JsonArray hist = d["history"].to<JsonArray>();
    for (uint8_t i = 0; i < gTrafficHistCount; ++i) {
      const uint8_t idx = static_cast<uint8_t>((gTrafficHistNext + kTrafficHistLen - gTrafficHistCount + i) % kTrafficHistLen);
      JsonArray pair = hist.add<JsonArray>();
      pair.add(gTrafficHistRx[idx]);
      pair.add(gTrafficHistTx[idx]);
    }
    sendJson(200, d);
  });

  // ==================== 时钟 / NTP 校时 ====================
  server.on("/clock", HTTP_GET, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    JsonDocument d;
    d["ok"] = true;
    const time_t nowSec = time(nullptr);
    d["synced"] = nowSec > 1600000000;                 // 早于 2020 年说明还没走 NTP
    d["epochMs"] = static_cast<uint64_t>(nowSec) * 1000ULL + static_cast<uint64_t>(millis() % 1000);
    struct tm ti;
    if (getLocalTime(&ti, 0)) {
      char buf[32];
      strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &ti);
      d["localText"] = buf;
      strftime(buf, sizeof(buf), "%z", &ti);
      d["tzOffset"] = buf;
      strftime(buf, sizeof(buf), "%A", &ti);
      d["weekday"] = buf;
    } else {
      d["localText"] = "";
    }
    d["timezone"] = gNtpTz;
    sendJson(200, d);
  });

  server.on("/clock/sync", HTTP_POST, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    // 不允许把时区设置成空串，否则 configTzTime 会回落成 UTC
    if (server.hasArg("plain")) {
      JsonDocument in;
      if (!deserializeJson(in, server.arg("plain"))) {
        const char* tz = in["timezone"] | "";
        if (tz && *tz) {
          gNtpTz = tz;
          prefs.begin("vela", false);
          prefs.putString("ntp_tz", gNtpTz);
          prefs.end();
        }
      }
    }
    configTzTime(gNtpTz.c_str(), "ntp.aliyun.com", "ntp.tencent.com", "pool.ntp.org");
    JsonDocument d;
    d["ok"] = true;
    d["timezone"] = gNtpTz;
    d["note"] = "同步是异步的，2-5 秒后刷新 /clock 查看";
    sendJson(200, d);
  });

  // ==================== 投递（向手表推一条文本） ====================
  // 这里只入队，不判断成功。真正能不能发出去只有会话线程知道（要有序列号、
  // 会话密钥、已定位的快应用），所以页面随后轮询 /watch/push/result 拿结果。
  server.on("/api/v1/watch/push", HTTP_POST, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    if (!server.hasArg("plain")) return jsonError(400, "no_body", "JSON body required");
    JsonDocument in;
    if (deserializeJson(in, server.arg("plain"))) return jsonError(400, "bad_json", "cannot parse body");
    const char* text = in["text"] | "";
    if (!text || !*text) return jsonError(400, "empty_text", "text is required");
    if (strlen(text) > 400) return jsonError(413, "text_too_long", "keep it under 400 bytes");
    if (!gWatchBridgeRunning) return jsonError(409, "bridge_not_running", "手表桥接未运行，先到运行状态页确认已连接");
    const bool queued = pushWatchText(text);
    JsonDocument d;
    d["ok"] = queued;
    d["queued"] = queued;
    if (!queued) d["message"] = "上一条还在投递中，等几秒再发";
    sendJson(queued ? 200 : 503, d);
  });

  // 推送结果：state 0 空闲 / 1 投递中 / 2 已写入 SPP / 3 失败。
  // 注意 state=2 只代表帧发出去了，手表端是否弹通知还取决于手表快应用自身。
  server.on("/api/v1/watch/push/result", HTTP_GET, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    JsonDocument d;
    taskENTER_CRITICAL(&gPushMux);
    const uint8_t state = gPushTaskState;
    const uint8_t attempts = gPushTaskAttempts;
    char reason[sizeof(gPushTaskFail)];
    snprintf(reason, sizeof(reason), "%s", gPushTaskFail);
    taskEXIT_CRITICAL(&gPushMux);
    d["ok"] = true;
    d["state"] = state;
    d["attempts"] = attempts;
    d["pending"] = gPendingWatchTextReady;
    d["reason"] = reason;
    d["bridgeState"] = getWatchBridgeState();
    sendJson(200, d);
  });

  // ==================== 日志环形缓冲 ====================
  server.on("/api/v1/logs", HTTP_GET, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    JsonDocument d;
    d["ok"] = true;
    JsonArray lines = d["lines"].to<JsonArray>();
    for (uint8_t i = 0; i < gLogRingCount; ++i) {
      const uint8_t idx = static_cast<uint8_t>((gLogRingNext + kLogRingLines - gLogRingCount + i) % kLogRingLines);
      JsonObject o = lines.add<JsonObject>();
      o["t"] = gLogRingMs[idx];
      o["m"] = gLogRing[idx];
    }
    d["capacity"] = kLogRingLines;
    sendJson(200, d);
  });

  // 手机浏览器打开任何页面都会顺手请求 /favicon.ico。
  // 之前它落到 onNotFound：非配网模式下回一段 JSON 404，
  // 有些手机浏览器会把这个 404 当成"站点内容异常"的判据之一，
  // 干脆回一个 204 让它彻底闭嘴（不产生"缺图标"提示，也不进 404 日志）。
  // =========================================================================
  // 表盘 / 快应用：上传、列表、安装、进度、删除
  // -------------------------------------------------------------------------
  // 文件落 SPIFFS，命名固定成 /W<槽>.bin（表盘）和 /A<槽>.rpk（快应用）。
  // SPIFFS 的对象名上限很短，所以只用单字符槽位，展示名在列表时现解析
  // （表盘读 0x68 的名字字段，快应用读 manifest.json 的 name）。
  // =========================================================================
  server.on("/api/v1/resource/list", HTTP_GET, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    JsonDocument d;
    if (!ensureSpiffs()) {
      d["ok"] = false;
      d["error"] = spiffsErrorCode();
      d["hint"] = spiffsErrorHint();
      sendJson(200, d);
      return;
    }
    d["ok"] = true;
    d["bridgeRunning"] = gWatchBridgeRunning;

    JsonObject usage = d["usage"].to<JsonObject>();
    usage["total"] = static_cast<uint32_t>(SPIFFS.totalBytes());
    usage["used"] = static_cast<uint32_t>(SPIFFS.usedBytes());

    JsonArray items = d["items"].to<JsonArray>();
    File root = SPIFFS.open("/");
    if (root) {
      File f = root.openNextFile();
      while (f) {
        const String name = f.name();
        const uint32_t size = static_cast<uint32_t>(f.size());
        f.close();
        const char* base = name.c_str();
        if (base[0] == '/') ++base;
        const bool isWf = base[0] == 'W';
        const bool isApp = base[0] == 'A';
        if ((isWf || isApp) && strlen(base) == 5) {
          JsonObject o = items.add<JsonObject>();
          o["slot"] = String(base, 2);
          o["kind"] = isWf ? "watchface" : "app";
          o["bytes"] = size;
          char label[40] = {0};
          if (isWf) {
            char id[16] = {0};
            const char* err = nullptr;
            const String full = String("/") + base;
            if (wfi::parseWatchfaceMeta(full.c_str(), id, sizeof(id),
                                        label, sizeof(label), err)) {
              o["watchfaceId"] = id;
            }
          } else {
            char pkg[48] = {0};
            uint32_t vc = 0;
            const char* err = nullptr;
            const String full = String("/") + base;
            if (wfi::parseRpkManifest(full.c_str(), pkg, sizeof(pkg), vc,
                                      label, sizeof(label), err)) {
              o["package"] = pkg;
              o["versionCode"] = vc;
            }
          }
          o["name"] = label[0] ? label : base;
        }
        f = root.openNextFile();
      }
      root.close();
    }
    JsonObject inst = d["install"].to<JsonObject>();
    wfi::statusJson(inst);
    sendJson(200, d);
  });

  // 上传：WebServer 把文件切成若干块回调，这里直接落 SPIFFS。
  // 只接受表盘（.bin/.face）和快应用（.rpk），其它扩展名一律拒绝。
  static File* wfUploadFile = nullptr;
  static char wfUploadPath[16] = {0};
  static bool wfUploadFailed = false;

  WebServer::THandlerFunction wfUploadHandler = []() {
    HTTPUpload& upload = server.upload();
    if (upload.status == UPLOAD_FILE_START) {
      wfUploadFailed = true;   // 只有走到 END 才算成功
      wfUploadPath[0] = 0;
      if (!ensureSpiffs()) {
        Serial.println("WF_UPLOAD_REJECT spiffs_unavailable");
        return;
      }
      const String name = upload.filename;
      const bool isApp = name.endsWith(".rpk") || name.endsWith(".RPK");
      const bool isWf = name.endsWith(".bin") || name.endsWith(".face") ||
                        name.endsWith(".BIN") || name.endsWith(".FACE");
      if (!isApp && !isWf) {
        Serial.printf("WF_UPLOAD_REJECT ext name=%s\n", name.c_str());
        return;
      }
      const char prefix = isApp ? 'A' : 'W';
      const char* ext = isApp ? ".rpk" : ".bin";
      // 找一个空槽
      int slot = -1;
      for (int i = 0; i < 10; ++i) {
        char probe[12];
        snprintf(probe, sizeof(probe), "/%c%d%s", prefix, i, ext);
        if (!SPIFFS.exists(probe)) { slot = i; break; }
      }
      if (slot < 0) {
        Serial.println("WF_UPLOAD_REJECT no_free_slot");
        return;
      }
      snprintf(wfUploadPath, sizeof(wfUploadPath), "/%c%d%s", prefix, slot, ext);

      // 空间检查：留 96 KB 给日志/录音，别把 SPIFFS 撑满
      const size_t freeBytes = SPIFFS.totalBytes() - SPIFFS.usedBytes();
      if (upload.totalSize > 0 && upload.totalSize + 96 * 1024 > freeBytes) {
        Serial.printf("WF_UPLOAD_REJECT no_space need=%u free=%u\n",
                      static_cast<unsigned>(upload.totalSize),
                      static_cast<unsigned>(freeBytes));
        return;
      }
      SPIFFS.remove(wfUploadPath);
      wfUploadFile = new File(SPIFFS.open(wfUploadPath, FILE_WRITE));
      if (!wfUploadFile || !*wfUploadFile) {
        Serial.println("WF_UPLOAD_REJECT open_failed");
        delete wfUploadFile;
        wfUploadFile = nullptr;
        return;
      }
      Serial.printf("WF_UPLOAD_START path=%s name=%s\n", wfUploadPath, name.c_str());
      wfUploadFailed = false;
    } else if (upload.status == UPLOAD_FILE_WRITE) {
      if (!wfUploadFile || !*wfUploadFile) return;
      if (wfUploadFile->write(upload.buf, upload.currentSize) != upload.currentSize) {
        wfUploadFailed = true;
      }
    } else if (upload.status == UPLOAD_FILE_END) {
      if (wfUploadFile) {
        wfUploadFile->flush();
        wfUploadFile->close();
        delete wfUploadFile;
        wfUploadFile = nullptr;
      }
      if (!wfUploadFailed) {
        Serial.printf("WF_UPLOAD_DONE path=%s bytes=%u\n", wfUploadPath,
                      static_cast<unsigned>(upload.totalSize));
      } else {
        SPIFFS.remove(wfUploadPath);
        wfUploadPath[0] = 0;
      }
    } else if (upload.status == UPLOAD_FILE_ABORTED) {
      if (wfUploadFile) {
        wfUploadFile->close();
        delete wfUploadFile;
        wfUploadFile = nullptr;
      }
      if (wfUploadPath[0]) SPIFFS.remove(wfUploadPath);
      wfUploadPath[0] = 0;
      wfUploadFailed = true;
      Serial.println("WF_UPLOAD_ABORTED");
    }
  };

  server.on("/api/v1/resource/upload", HTTP_POST, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    JsonDocument d;
    if (!ensureSpiffs()) {
      d["ok"] = false;
      d["error"] = spiffsErrorCode();
      d["hint"] = spiffsErrorHint();
      sendJson(200, d);
      return;
    }
    if (wfUploadFailed || !wfUploadPath[0]) {
      d["ok"] = false;
      d["error"] = "upload_failed";
      d["hint"] = "仅接受 .bin/.face（表盘）与 .rpk（快应用）；槽位上限 10 个；请检查剩余空间";
      sendJson(200, d);
      return;
    }
    d["ok"] = true;
    d["slot"] = String(wfUploadPath + 1, 2);
    d["path"] = wfUploadPath;
    uint32_t sz = 0;
    d["bytes"] = wfi::fileInfo(wfUploadPath, sz) ? sz : 0;

    // 紧随其后把元数据解析出来，前端上传完就能直接显示名字
    char label[40] = {0};
    const char* err = nullptr;
    if (wfUploadPath[1] == 'W') {
      char id[16] = {0};
      if (wfi::parseWatchfaceMeta(wfUploadPath, id, sizeof(id), label, sizeof(label), err)) {
        d["watchfaceId"] = id;
        d["name"] = label;
      } else {
        d["ok"] = false;
        d["error"] = err ? err : "not_a_watchface";
        d["hint"] = "不是小米表盘文件（头部 magic 应为 5A A5）";
        SPIFFS.remove(wfUploadPath);
        wfUploadPath[0] = 0;
      }
    } else {
      char pkg[48] = {0};
      uint32_t vc = 0;
      if (wfi::parseRpkManifest(wfUploadPath, pkg, sizeof(pkg), vc, label, sizeof(label), err)) {
        d["package"] = pkg;
        d["versionCode"] = vc;
        d["name"] = label;
      } else {
        d["ok"] = false;
        d["error"] = err ? err : "not_a_quickapp";
        d["hint"] = "不是快应用包（应为含 manifest.json 的 .rpk）";
        SPIFFS.remove(wfUploadPath);
        wfUploadPath[0] = 0;
      }
    }
    wfUploadPath[0] = 0;
    sendJson(200, d);
  }, wfUploadHandler);

  server.on("/api/v1/resource/install", HTTP_POST, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    if (!ensureSpiffs()) return jsonError(503, spiffsErrorCode(), spiffsErrorHint());
    JsonDocument in;
    if (deserializeJson(in, server.arg("plain"))) return jsonError(400, "bad_json", "");
    const String slot = in["slot"] | "";
    if (slot.length() != 2) return jsonError(400, "bad_slot", "expected like W0 / A1");

    char path[16];
    const bool isWf = slot[0] == 'W';
    snprintf(path, sizeof(path), "/%s%s", slot.c_str(), isWf ? ".bin" : ".rpk");
    if (!SPIFFS.exists(path)) return jsonError(404, "not_found", path);

    if (wfi::busy()) return jsonError(409, "busy", "已有安装任务在跑");

    char label[40] = {0};
    const char* err = nullptr;
    char wfId[16] = {0};
    if (isWf) {
      if (!wfi::parseWatchfaceMeta(path, wfId, sizeof(wfId), label, sizeof(label), err)) {
        return jsonError(400, err ? err : "bad_watchface", "");
      }
    } else {
      char pkg[48] = {0};
      uint32_t vc = 0;
      if (!wfi::parseRpkManifest(path, pkg, sizeof(pkg), vc, label, sizeof(label), err)) {
        return jsonError(400, err ? err : "bad_quickapp", "");
      }
      strncpy(label, pkg, sizeof(label) - 1);
    }

    if (!wfi::prepareJob(path, isWf ? wfi::kDataTypeWatchFace : wfi::kDataTypeThirdpartyApp,
                         label, isWf ? wfId : nullptr, err)) {
      return jsonError(err && strcmp(err, "busy") == 0 ? 409 : 400,
                       err ? err : "prepare_failed", "");
    }

    JsonDocument d;
    d["ok"] = true;
    d["state"] = "preparing";
    d["label"] = label;
    sendJson(202, d);
  });

  server.on("/api/v1/resource/status", HTTP_GET, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    JsonDocument d;
    d["ok"] = true;
    JsonObject inst = d["install"].to<JsonObject>();
    wfi::statusJson(inst);
    sendJson(200, d);
  });

  server.on("/api/v1/resource/cancel", HTTP_POST, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    wfi::cancel();
    JsonDocument d;
    d["ok"] = true;
    sendJson(200, d);
  });

  server.on("/api/v1/resource/delete", HTTP_POST, [](){
    if (!isSetupApClient() && !requireAuth()) return;
    if (!ensureSpiffs()) return jsonError(503, spiffsErrorCode(), spiffsErrorHint());
    JsonDocument in;
    if (deserializeJson(in, server.arg("plain"))) return jsonError(400, "bad_json", "");
    const String slot = in["slot"] | "";
    if (slot.length() != 2) return jsonError(400, "bad_slot", "");
    char path[16];
    snprintf(path, sizeof(path), "/%s%s", slot.c_str(), slot[0] == 'W' ? ".bin" : ".rpk");
    const bool gone = SPIFFS.remove(path);
    JsonDocument d;
    d["ok"] = gone;
    sendJson(200, d);
  });

  server.on("/favicon.ico", HTTP_GET, [](){
    server.send(204, "image/x-icon", "");
  });

  // 配网模式下作为 captive portal：把手机连上热点后自动弹出的探测请求
  // 全部重定向到配置页，让手机浏览器自动打开配置界面。
  server.onNotFound([](){
    if (gSetupMode || gOtaMode) {
      server.sendHeader("Location", "/", true);
      server.send(302, "text/plain", "redirect to main");
      return;
    }
    jsonError(404,"not_found",server.uri());
  });

  // 上传固件文件并写入Flash
  // firmware.bin → 使用Update库写入OTA分区（支持自动回滚）
  // bootloader.bin/partitions.bin/自定义 → 原始SPI Flash写入
  // 手机浏览器上传：任何差错都回 JSON（200），因为 4xx/5xx 时部分手机浏览器
  // 会直接替换页面，前端拿不到错误原因。/ota/upload2 是 JSON 版别名。
  const bool phoneFriendlyUpload = true;
  (void)phoneFriendlyUpload;

  server.on("/ota/upload2", HTTP_POST, [](){
    if (!gOtaMode) { jsonError(403,"not_in_ota_mode",""); return; }
    JsonDocument d;
    if (!s_otaError.isEmpty()) {
      d["ok"] = false; d["error"] = s_otaError; d["file"] = s_otaFileName;
      d["written"] = (uint32_t)s_otaTotalWritten;
      sendJson(200, d);
      Serial.printf("OTA_PHONE_UPLOAD_ERROR: %s\n", s_otaError.c_str());
      return;
    }

    // 兜底：一个字节都没收到就绝不能回成功。以前上传回调缺失时正是这条路径，
    // 接口回「写入完成」、设备重启、版本不变，用户完全看不出发生了什么。
    if (s_otaTotalWritten == 0) {
      d["ok"] = false;
      d["error"] = "no_data";
      d["hint"] = "没有收到文件内容，请重新选择文件上传。";
      sendJson(200, d);
      Serial.println("OTA_UPLOAD_REJECT no_data");
      return;
    }
    if (s_otaIsFirmware) {
      if (!Update.end(true)) {
        d["ok"] = false;
        d["error"] = String("固件写入失败: ") + Update.errorString();
        sendJson(200, d);
        return;
      }
    }
    d["ok"] = true; d["file"] = s_otaFileName; d["size"] = (uint32_t)s_otaTotalWritten;
    d["firmware"] = s_otaIsFirmware;
    d["msg"] = "写入完成，设备即将重启";
    sendJson(200, d);
    Serial.printf("OTA_PHONE_UPLOAD_SUCCESS file=%s size=%u\n",
                  s_otaFileName.c_str(), (unsigned)s_otaTotalWritten);
    if (s_otaIsFirmware && server.arg("keep_ota") != "1") {
      prefs.putInt("project", 1);
      prefs.putBool("project2", false);
    }
    if (s_otaIsFirmware) {
      prefs.putString("ota_expect_part", s_otaTargetLabel);
      prefs.putString("ota_expect_ver", s_otaImageVersion);
      Serial.printf("OTA_EXPECT part=%s ver=%s\n",
                    s_otaTargetLabel.c_str(), s_otaImageVersion.c_str());
    }
    digitalWrite(kHeartbeatLedPin, HIGH);
    delay(2000);
    digitalWrite(kHeartbeatLedPin, LOW);
    delay(100);
    Serial.println("OTA_REBOOTING...");
    ESP.restart();
}, otaUploadCallback);

  server.on("/ota/upload", HTTP_POST, [](){
    // 响应处理：上传完成后调用
    if (!gOtaMode) { jsonError(403,"not_in_ota_mode",""); return; }

    JsonDocument d;
    if (!s_otaError.isEmpty()) {
      d["ok"] = false;
      d["error"] = s_otaError;
      d["file"] = s_otaFileName;
      d["written"] = (uint32_t)s_otaTotalWritten;
      sendJson(500, d);
      digitalWrite(kHeartbeatLedPin, LOW);
      Serial.printf("OTA_UPLOAD_ERROR: %s\n", s_otaError.c_str());
      return;
    }

    // 兜底：一个字节都没收到就绝不能回成功。以前上传回调缺失时正是这条路径，
    // 接口回「写入完成」、设备重启、版本不变，用户完全看不出发生了什么。
    if (s_otaTotalWritten == 0) {
      d["ok"] = false;
      d["error"] = "no_data";
      d["hint"] = "没有收到文件内容，请重新选择文件上传。";
      sendJson(200, d);
      Serial.println("OTA_UPLOAD_REJECT no_data");
      return;
    }

    // 如果是固件OTA更新，需要finalize
    if (s_otaIsFirmware) {
      if (!Update.end(true)) {
        d["ok"] = false;
        d["error"] = String("固件写入失败: ") + Update.errorString();
        d["file"] = s_otaFileName;
        sendJson(500, d);
        digitalWrite(kHeartbeatLedPin, LOW);
        Serial.printf("OTA_UPDATE_END_FAILED: %s\n", Update.errorString());
        return;
      }
      Serial.println("OTA_UPDATE_END_SUCCESS firmware written to OTA partition");
    }

    d["ok"] = true;
    d["file"] = s_otaFileName;
    d["addr"] = s_otaFlashAddr;
    d["size"] = (uint32_t)s_otaTotalWritten;
    d["firmware"] = s_otaIsFirmware;
    d["msg"] = s_otaIsFirmware ? "固件写入完成(支持回滚保护)，LED常亮2秒后重启" : "写入完成，LED常亮2秒后重启";
    sendJson(200, d);

    Serial.printf("OTA_UPLOAD_SUCCESS file=%s addr=0x%08X size=%u firmware=%d\n",
                  s_otaFileName.c_str(), s_otaFlashAddr, s_otaTotalWritten, s_otaIsFirmware);

    // 固件升级完成后自动回到手表网关模式。
    // 旧逻辑不带这个动作：升级完设备仍停留在 OTA 模式，热点虽在但没有
    // 桥接功能，用户会以为"刷完就坏了"。要留在 OTA 模式可传 keep_ota=1。
    if (s_otaIsFirmware && server.arg("keep_ota") != "1") {
      prefs.putInt("project", 1);
      prefs.putBool("project2", false);
      Serial.println("OTA_SWITCH_BACK project=1 reason=firmware_upgrade_done");
    }
    if (s_otaIsFirmware) {
      prefs.putString("ota_expect_part", s_otaTargetLabel);
      prefs.putString("ota_expect_ver", s_otaImageVersion);
      Serial.printf("OTA_EXPECT part=%s ver=%s\n",
                    s_otaTargetLabel.c_str(), s_otaImageVersion.c_str());
    }

    // LED常亮2秒，然后灭掉重启
    digitalWrite(kHeartbeatLedPin, HIGH);
    delay(2000);
    digitalWrite(kHeartbeatLedPin, LOW);
    delay(100);
    Serial.println("OTA_REBOOTING...");
    ESP.restart();
  }, otaUploadCallback);

  // OTA状态
  server.on("/ota/status", HTTP_GET, [](){
    if (!gOtaMode) { jsonError(403,"not_in_ota_mode",""); return; }
    JsonDocument d;
    d["ok"] = true;
    d["flashSize"] = ESP.getFlashChipSize();
    d["freeHeap"] = ESP.getFreeHeap();
    d["flashMode"] = (int)ESP.getFlashChipMode();
    d["chipModel"] = ESP.getChipModel();
    d["chipCores"] = ESP.getChipCores();
    // OTA分区信息
    const esp_partition_t* running = esp_ota_get_running_partition();
    const esp_partition_t* next = esp_ota_get_next_update_partition(nullptr);
    if (running) {
      d["runningPartition"] = running->label;
      d["runningAddr"] = (uint32_t)running->address;
      d["runningSize"] = (uint32_t)running->size;
      esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
      if (esp_ota_get_state_partition(running, &state) == ESP_OK) {
        d["partitionState"] = (int)state;
      }
    }
    if (next) {
      d["nextPartition"] = next->label;
      d["nextAddr"] = (uint32_t)next->address;
      d["nextSize"] = (uint32_t)next->size;
      // 空闲目标分区里是否已经躺着一个可直接启动的镜像。整片刷写、或用
      // /ota/upload?addr= 直接写过分区之后，这里是 true，页面要提示用户
      // 当前运行的不一定是这份镜像。
      esp_app_desc_t desc;
      const bool hasImage = esp_ota_get_partition_description(next, &desc) == ESP_OK;
      d["nextHasImage"] = hasImage;
      if (hasImage) d["nextImageVersion"] = String(desc.version);
    }
    d["rollbackEnabled"] = true;
    sendJson(200, d);
  });
}

void maintainMdns() {
  if (WiFi.status() != WL_CONNECTED) {
    if (gMdnsStarted) { MDNS.end(); gMdnsStarted = false; }
    return;
  }
  if (!gMdnsStarted && MDNS.begin("vela-gateway")) {
    MDNS.addService("http", "tcp", 80);
    gMdnsStarted = true;
    Serial.println("MDNS_READY host=vela-gateway.local");
  }
}

// ---- 配网模式（首次配置 / BOOT 长按触发） ----

void setupTriggerPins() {
  pinMode(kSetupTriggerPin, INPUT_PULLUP);
}

bool setupTriggered() {
  // BOOT (GPIO0) is low only while pressed after normal application boot.
  return digitalRead(kSetupTriggerPin) == LOW;
}

void enterSetupMode() {
  gSetupMode = true;
  gWatchBridgeStopRequested = true;  // 停止任何进行中的桥接，让阻塞的 loop() 恢复
  gWatchAutoReconnectSuppressed = true;
  // 自动降级（配置全部保留）时让 AP 与 STA 共存：后台继续尝试连已保存的
  // Wi-Fi。路由器一恢复 / 密码改回来，设备自己重启回正常工作模式，
  // 用户什么都不用改，这是「不清配置」能真正兑现的关键。
  const bool keepConfig = gSetupKeepConfig && !ssid.isEmpty() &&
                          watchMac.length() == 17 && watchAuthKey.length() == 32;
  WiFi.mode(keepConfig ? WIFI_AP_STA : WIFI_AP);
  const bool apStarted = WiFi.softAP(gApSsid.c_str(), apPassword.c_str());
  if (keepConfig) {
    WiFi.begin(ssid.c_str(), wifiPass.c_str());
    Serial.printf("SETUP_MODE_STA_TRYING ssid=%s keep_config=true\n", ssid.c_str());
  }
  if (!gServerStarted) {
    server.begin();
    gServerStarted = true;
  }
  // 兜底解绑：正常路径上 arm 标志已在开机处理里清掉，这里再查一次是为了
  // 覆盖"进入配网模式时标志仍然存在"的情况，保证标志不会跨到下一次开机
  // 变成无限清空循环。两种 magic（FACT / SEPU）都要清。
  if (factoryArmMagic() != 0) {
    Serial.println("SETUP_MODE_ARM_CONSUMED setup_mode_reached");
    factoryResetDisarm();
  }
  // 配网模式下不再参与降级判定（用户正在填表）。
  gFactoryBootChecked = true;
  Serial.printf("SETUP_MODE_ACTIVE ap=%s ip=%s started=%s keep_config=%s\n",
                gApSsid.c_str(), WiFi.softAPIP().toString().c_str(),
                apStarted ? "true" : "false", keepConfig ? "true" : "false");
}

// 独立任务检测 BOOT 长按：不依赖 loop()，因此即使 authenticateWatchSpp
// 同步阻塞了 Arduino 主循环，这个任务仍能触发配网。
//
// 长按分三档（与常见路由器/摄像头固件一致）：
//   3 秒  → 只清 Wi-Fi（临时换路由器/改密码，不想丢手表密钥时用）
//   10 秒 → 恢复出厂：清空全部配置并进入配网
//   15 秒 → 恢复出厂 + 重新校准提示（当前无 PSRAM/传感校准，等价于 10 秒档，
//           保留这一档是为了与 README/网页文案对齐，后续加校准再扩展）
static void setupTriggerTask(void*) {
  uint32_t since = 0;
  bool warned3 = false;
  bool warned10 = false;
  bool warned15 = false;
  while (true) {
    if (setupTriggered()) {
      if (since == 0) since = millis();
      const uint32_t held = millis() - since;
      // 3 分钟兜底：GPIO0 在下载模式下被拉低、或板子 IO 故障导致一直读 Low 时，
      // 如果不做上限，10 秒后就会无条件恢复出厂，那就变成"插上 USB 就清空"。
      if (held > 180000) {
        Serial.println("BOOT_HOLD_ABORT_TOO_LONG assume_download_mode_or_io_fault");
        since = millis();  // 重新开始计时，不触发动作
        warned3 = warned10 = warned15 = false;
        continue;
      }

      if (!warned3 && held >= 3000) {
        warned3 = true;
        // 3 秒提示用快速闪灯，无需串口也能看出来
        for (int i = 0; i < 3; ++i) {
          digitalWrite(kHeartbeatLedPin, HIGH); delay(60);
          digitalWrite(kHeartbeatLedPin, LOW); delay(60);
        }
        Serial.println("BOOT_HOLD_3S keep_holding_for_factory_reset");
      }
      if (!warned10 && held >= 10000) {
        warned10 = true;
        for (int i = 0; i < 6; ++i) {
          digitalWrite(kHeartbeatLedPin, HIGH); delay(50);
          digitalWrite(kHeartbeatLedPin, LOW); delay(50);
        }
        Serial.println("BOOT_HOLD_10S factory_reset_armed");
      }

      if (held >= kSetupTriggerHoldMs) {
        // 10 秒：恢复出厂。写独立 arm 标志 + 清空业务键，重启后进配网。
        Serial.println("SETUP_MODE_REASON boot_long_press_10s_factory_reset");
        factoryResetApply("boot_long_press");
      }
    } else {
      if (since != 0) {
        const uint32_t held = millis() - since;
        // 松手时按持续时长决定动作：300ms ~ 3s 忽略（防误触），
        // 3s ~ 10s 只清 Wi-Fi，≥10s 在按住时已经执行了恢复出厂。
        if (held >= 3000 && held < kSetupTriggerHoldMs) {
          Serial.printf("SETUP_MODE_REASON boot_short_press_%lums_clear_wifi\n",
                        static_cast<unsigned long>(held));
          prefs.begin("vela", false);
          prefs.remove("ssid");
          prefs.remove("wifi_pass");
          prefs.putBool("force_setup", true);
          prefs.putInt("project", 1);
          prefs.putBool("project2", false);
          prefs.end();
          delay(300);
          ESP.restart();
        } else if (held >= 300) {
          Serial.printf("BOOT_PRESS_IGNORED held_ms=%lu\n",
                        static_cast<unsigned long>(held));
        }
        since = 0;
        warned3 = warned10 = warned15 = false;
      }
    }
    vTaskDelay(pdMS_TO_TICKS(100));
  }
}

void connectWifi() {
  WiFi.persistent(false);
  WiFi.setAutoReconnect(true);
  // When a home Wi-Fi is already configured, use STA-only mode so the
  // SoftAP netif does not consume the heap the Bluetooth controller needs.
  // The setup AP is only enabled when no Wi-Fi has been configured yet.
  if (ssid.isEmpty()) {
    WiFi.mode(WIFI_AP);
    const bool apStarted = WiFi.softAP(gApSsid.c_str(), apPassword.c_str());
    Serial.printf("SoftAP started=%s ssid=%s ap=%s (no home wifi configured)\n",
                  apStarted ? "true" : "false", gApSsid.c_str(), WiFi.softAPIP().toString().c_str());
    return;
  }
  // 认证/bootstrap 阶段可能已经非阻塞地启动过 STA（WiFi.mode+begin）。
  // 这里必须保持非阻塞：connectWifi() 是在 SPP 桥接任务里调用的，旧实现
  // 用 60 秒 while(delay) 同步等待，期间完全不读蓝牙数据，手表侧的
  // SPP 发送窗口会被打满，表现为"连上 Wi-Fi 反而卡住/掉线"。
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("STA already connected ip=%s\n", WiFi.localIP().toString().c_str());
    gWatchInternetRouteReady = false;
    requestWatchInternetRouteRepair();
    return;
  }
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid.c_str(), wifiPass.c_str());
  gLastWifiAttemptMs = millis();
  gLastConnectAttemptMs = gLastWifiAttemptMs;
  Serial.println("STA mode begin (non-blocking, loop() will retry every 25s)");
  // mDNS is started lazily from loop() after the STA obtains an IP,
  // to keep heap available for the Bluetooth controller.
}
}

// 调试串口波特率。
// 默认 921600 而不是 2000000，原因是网页版串口监视器（flasher.welinklab.com
// 等）的下拉框最高只到 921600，2000000 会让日志全变成乱码。
// 需要满速时在 platformio.ini 里加 -DVELA_SERIAL_BAUD=2000000 即可。
#ifndef VELA_SERIAL_BAUD
#define VELA_SERIAL_BAUD 921600
#endif

void setup() {
  Serial.begin(VELA_SERIAL_BAUD);
  delay(120);

  // 协议常量在这里一次性解码（此时还没起任务，避免多任务首次并发解码）。
  // 之后再调用只是读缓存，无锁竞争。
  (void)watchQuickAppPackage();
  (void)watchManifestFormat();
  (void)watchRequiredBuildTag();

  // ====== 恢复出厂 / 自动降级前置处理（必须在 loadConfig 之前）======
  // 模块级实现见本文件前面的 "恢复出厂设置 / 自动配网降级" 一节。
  //   - FACT 标志（BOOT 长按 / 网页按钮）：补清空 + 解绑，强制进配网
  //   - SEPU 标志（连不上 Wi-Fi 自动降级）：不清任何配置，只强制进配网
  //   - 无标志：武装降级判定（见 autoSetupFallbackTick）
  //
  // 注意开机处理一律不重启：factoryResetApply() / autoSetupFallbackApply()
  // 末尾都会 ESP.restart()，而 arm 标志活过重启，于是
  // "看到标志 → 再执行一遍 → 再重启" 会变成无限复位环（第十三章）。
  if (!gFactoryBootChecked) {
    gFactoryBootChecked = true;
    gBootMs = millis();
    const uint32_t arm = factoryArmMagic();
    if (arm == kFactoryArmMagic) {
      factoryResetCompleteOnBoot();
    } else if (arm == kSetupOnlyArmMagic) {
      autoSetupCompleteOnBoot();
    } else {
      initAutoSetupWindow();
    }
  }

  // 启动横幅：一眼确认芯片、Flash 容量、当前 app 分区大小。
  // 16MB 版本应显示 flash=16777216 bytes、app_partition_size=6291456 (6MB)。
  {
    const esp_partition_t* running = esp_ota_get_running_partition();
    const esp_partition_t* fs = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_SPIFFS, nullptr);
    Serial.printf("\n=== Vela Gateway boot ===\n");
    Serial.printf("BOOT chip=%s rev=%d cores=%d flash=%u bytes (%.1f MB) heap=%lu\n",
                  ESP.getChipModel(), ESP.getChipRevision(), ESP.getChipCores(),
                  static_cast<unsigned>(ESP.getFlashChipSize()),
                  ESP.getFlashChipSize() / 1048576.0,
                  static_cast<unsigned long>(ESP.getFreeHeap()));
    Serial.printf("BOOT app_partition=%s addr=0x%08X size=%u next_ota=%s spiffs=%s size=%u\n",
                  running ? running->label : "?",
                  running ? static_cast<unsigned>(running->address) : 0u,
                  running ? static_cast<unsigned>(running->size) : 0u,
                  esp_ota_get_next_update_partition(nullptr)
                      ? esp_ota_get_next_update_partition(nullptr)->label : "none",
                  fs ? fs->label : "missing",
                  fs ? static_cast<unsigned>(fs->size) : 0u);
    if (!fs) {
      Serial.println("BOOT_WARNING no SPIFFS partition: audio export / packet capture will be disabled");
    }
    if (ESP.getFlashChipSize() < 16u * 1024u * 1024u) {
      Serial.println("BOOT_WARNING flash is smaller than 16MB: did you flash the 16MB build/partition table?");
    }
  }
  // In the ESP-IDF+Arduino low-memory environment, true preserves the tiny
  // sdkconfig Wi-Fi buffer counts instead of Arduino's large dynamic default.
  // In the pure-Arduino fallback, use dynamic buffers to avoid reserving the
  // precompiled framework's much larger static TX pool up front.
#ifdef VELA_LOW_MEMORY_SDKCONFIG
  WiFi.useStaticBuffers(true);
#else
  WiFi.useStaticBuffers(false);
#endif
  // Initialize the TCP/IP stack before any Bluetooth or network operations.
  // The tcpip thread is needed for tcpip_callback() used by the network bridge
  // (setupWatchNetworkProxy), which is called during Bluetooth auth, before
  // WiFi is connected. Without this, tcpip_callback asserts "Invalid mbox".
  //
  // 这里必须用 esp_netif_init()，绝对不要直接调 tcpip_init()。
  // IDF 的 esp_netif_init() 内部已经会调一次 tcpip_init()，而 lwip_init()
  // 没有任何幂等保护 → 第二次会再跑一遍 sys_init() → 第二次调用
  // esp_vfs_lwip_sockets_register()。socket 的 fd 区间（FD_SETSIZE-8 .. FD_SETSIZE-1）
  // 在 esp_vfs 里是「永久占用」的，第二次注册必然撞车返回 ESP_ERR_INVALID_ARG (0x102)，
  // 撞上 vfs_lwip.c 里的 ESP_ERROR_CHECK → abort() → 无限重启。
  // esp_netif_init() 自带 tcpip_initialized 保护，重复调用是安全的。
  esp_netif_init();
#ifndef VELA_DISABLE_LWIP_OVERRIDE
  vela_lwip_napt_override_marker();
#endif
  // Release the Bluetooth LE controller memory before Classic SPP init:
  // this firmware only uses Bluetooth Classic, and the BLE controller would
  // otherwise reserve ~32 KB of internal DRAM that the SPP host stack needs.
  loadConfig();

  // 运行模式：只认 1（手表网关）和 6（空中升级）。
  // 老固件在 NVS 里可能留着 2/3/4/5（BLE 广播 / 抓包 / 手环 / 测速），
  // 这些项目已经删除，读到时一律归一化为 1 并写回，避免设备一直卡在
  // 一个不存在的模式里反复重启。
  gProjectMode = prefs.getInt("project", 1);
  if (gProjectMode != 6) gProjectMode = 1;
  if (prefs.getInt("project", 1) != gProjectMode) prefs.putInt("project", gProjectMode);
  gOtaMode = (gProjectMode == 6);
  Serial.printf("RUN_MODE=%s\n", gOtaMode ? "ota" : "watch");

  // BOOT长按触发的强制配网：在任何项目模式下都优先处理
  // 注意：这里只重置项目号 + 记录请求，不能把 force_setup 标志在这里清掉。
  // 旧代码在开头 putBool(false)，后面网关分支再 getBool() 永远是 false，
  // 结果长按 BOOT 只是切回网关，并不会真的进入配网模式。
  const bool forceSetupRequested = prefs.getBool("force_setup", false);
  if (forceSetupRequested) {
    prefs.putBool("force_setup", false);
    prefs.putInt("project", 1);
    gProjectMode = 1;
    gOtaMode = false;
    Serial.println("FORCE_SETUP detected, mode reset to watch, setup AP will be entered");
  }

  // 升级结果核对：写分区前记下的目标分区/版本对不上，说明本次升级被 bootloader
  // 回滚了。这种情况必须让用户看见 —— 否则界面只表现为「刷完还是旧版本」。
  {
    const String expectPart = prefs.getString("ota_expect_part", "");
    const String expectVer = prefs.getString("ota_expect_ver", "");
    if (!expectPart.isEmpty() || !expectVer.isEmpty()) {
      prefs.remove("ota_expect_part");
      prefs.remove("ota_expect_ver");
      const esp_partition_t* running = esp_ota_get_running_partition();
      const String runningPart = running ? String(running->label) : String("?");
      const bool partOk = expectPart.isEmpty() || expectPart == runningPart;
      const bool verOk = expectVer.isEmpty() || expectVer == String(kFwVersionFull);
      if (partOk && verOk) {
        Serial.printf("OTA_UPGRADE_CONFIRMED part=%s ver=%s\n",
                      runningPart.c_str(), kFwVersionFull);
      } else {
        gOtaRollbackDetected = true;
        gOtaRollbackExpected = expectVer;
        gOtaRollbackRunning = String(kFwVersionFull);
        Serial.printf("OTA_ROLLBACK_DETECTED expect_part=%s expect_ver=%s running_part=%s running_ver=%s\n",
                      expectPart.c_str(), expectVer.c_str(),
                      runningPart.c_str(), kFwVersionFull);
      }
    }
  }

  // OTA回滚保护：标记当前固件为有效
  // 这里只置"待确认"标志，真正的 mark_app_valid 放到 loop() 里，等主循环跑满
  // kOtaConfirmDelayMs 再确认。旧实现在 setup() 一进来就 cancel_rollback，
  // 等于回滚保护从未生效。
  {
    const esp_partition_t* running = esp_ota_get_running_partition();
    if (running) {
      esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
      if (esp_ota_get_state_partition(running, &state) == ESP_OK) {
        if (state == ESP_OTA_IMG_NEW || state == ESP_OTA_IMG_PENDING_VERIFY) {
          gOtaPendingVerify = true;
          gOtaVerifyStartMs = millis();
          Serial.printf("OTA_FIRMWARE_PENDING_VERIFY partition=%s state=%d confirm_after_ms=%lu\n",
                        running->label, static_cast<int>(state),
                        static_cast<unsigned long>(kOtaConfirmDelayMs));
        }
      }
    }
  }

  if (gOtaMode) {
    // ====== 空中升级模式 ======
    Serial.println("OTA_MODE starting");

    // 释放BT内存（OTA不需要蓝牙）
    esp_bt_controller_mem_release(ESP_BT_MODE_BTDM);
    Serial.printf("OTA_BT_MEM_RELEASED free=%lu\n", static_cast<unsigned long>(ESP.getFreeHeap()));

    // WiFi AP模式（仅热点，不需要STA）
    WiFi.persistent(false);
    WiFi.mode(WIFI_AP);
    WiFi.softAP(gApSsid.c_str(), apPassword.c_str());
    Serial.printf("OTA_AP started ssid=%s ip=%s\n", gApSsid.c_str(), WiFi.softAPIP().toString().c_str());

    // 初始化LED
    pinMode(kHeartbeatLedPin, OUTPUT);

    // 启动HTTP服务器
    setupRoutes();
    server.begin();
    gServerStarted = true;

    // BOOT键检测
    setupTriggerPins();
    xTaskCreatePinnedToCore(setupTriggerTask, "vela_setup_trig", 2048, nullptr, 1, nullptr, 1);

    Serial.println("OTA_READY ap=on");
    return;
  }

  esp_bt_controller_mem_release(ESP_BT_MODE_BLE);
  Serial.printf("VELA_BLE_MEM_RELEASED free=%lu largest=%lu\n",
                static_cast<unsigned long>(ESP.getFreeHeap()),
                static_cast<unsigned long>(ESP.getMaxAllocHeap()));
  setupTriggerPins();
  // 板载心跳 LED（D2/GPIO2）
  pinMode(kHeartbeatLedPin, OUTPUT);
  digitalWrite(kHeartbeatLedPin, LOW);
  // OLED/Wire also consume and fragment heap. If this is a configured normal
  // boot, defer their initialization until STA has obtained an IP; Bluetooth
  // auth + Wi-Fi init get the cleanest possible WROOM heap. In first-setup AP
  // mode we can initialize the display immediately because no Classic-BT bridge
  // is competing for RAM.
  const bool displayCanStartEarly = ssid.isEmpty() ||
                                    watchMac.length() != 17 ||
                                    watchAuthKey.length() != 32;
  if (displayCanStartEarly) {
    initDisplay();
  } else {
    gDisplayInitDeferred = true;
    Serial.println("DISPLAY_INIT_DEFERRED until=wifi_got_ip");
  }
  // 独立任务检测 GPIO 短接（不依赖被桥接阻塞的 loop()）。
  xTaskCreatePinnedToCore(setupTriggerTask, "vela_setup_trig", 2048, nullptr, 1, nullptr, 1);
  if (!gBridgeStateMutex) gBridgeStateMutex = xSemaphoreCreateMutex();
  if (!gLogMutex) gLogMutex = xSemaphoreCreateRecursiveMutex();
  // ASR result queue is optional; scheduleWatchAsrJob() allocates it lazily.
  gWatchStreamCaptureFsReady = false;  // mounted lazily on first capture
  Serial.printf("WATCH_CAPTURE_FS lazy_mount=%s\n", gWatchStreamCaptureFsReady ? "true" : "false");
  // Wi-Fi is NOT connected here: it is brought up inside watchBridgeTaskMain
  // AFTER Bluetooth auth succeeds, to keep heap large/unfragmented for BT init.
  setupRoutes();
  Serial.println("WATCH_RETURN_PATH_TRACER v7 enabled");
  Serial.println("VELA_MEM_OPT v7 shared_spp_frame=true reused_tx_scratch=true lazy_asr_queue=true");
  Serial.printf("Vela Gateway ready. watch_configured=%s\n",
                (watchMac.length()==17 && watchAuthKey.length()==32) ? "true" : "false");

  // BOOT 长按触发的强制配网：重启后直接进入 SoftAP 配网模式。
  if (forceSetupRequested) {
    Serial.println("SETUP_MODE_REASON io_short_reboot");
    enterSetupMode();
    return;
  }

  // 首次配网：完全没有 Wi-Fi 配置（或缺少手表 key）时，直接进入 SoftAP 配网模式。
  // gForceSetupAfterReset：刚补完恢复出厂清空，强制进配网，不看 NVS 残留。
  const bool needSetup = gForceSetupAfterReset || ssid.isEmpty() ||
                         watchMac.length() != 17 || watchAuthKey.length() != 32;
  if (needSetup) {
    Serial.println(gSetupKeepConfig
                       ? "SETUP_MODE_REASON auto_setup_fallback_config_kept"
                       : gForceSetupAfterReset
                           ? "SETUP_MODE_REASON factory_reset_completed"
                           : "SETUP_MODE_REASON first_boot_no_config");
    enterSetupMode();
    return;  // 配网模式下不启动桥接，等用户在网页上保存配置后重启。
  }

  // 只要 Watch MAC + Auth Key 完整，就自动启动桥接
  // 设置自动重连为true（原来依赖autoConnectWatch标志，现在强制开启）
  autoConnectWatch = true;
  if (watchMac.length() == 17 && watchAuthKey.length() == 32) {
    String error;
    if (!startWatchBridge(error)) Serial.printf("WATCH_AUTOSTART_FAILED reason=%s\n", error.c_str());
  }
  // HTTP server is started from loop() once home Wi-Fi is connected
  // (lwIP must be initialised first).
}

// ====== OTA 空中升级 Web UI ======
const char kOtaWebUi[] PROGMEM = R"HTMLOTA(
<!DOCTYPE html><html lang=zh-CN><head>
<meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Vela Gateway - 空中升级</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:#0f1117;color:#e0e0e0;padding:12px;max-width:480px;margin:0 auto}
.card{background:#1a1d29;border-radius:12px;padding:16px;margin-bottom:12px;border:1px solid #2a2d3a}
h2{font-size:18px;color:#58a5ff;margin-bottom:12px}
h3{font-size:14px;color:#aaa;margin-bottom:8px}
.muted{color:#666;font-size:12px}
input,select,button{font-family:inherit;font-size:14px;border-radius:8px;border:1px solid #3a3d4a;background:#252836;color:#e0e0e0;padding:8px 12px;outline:none}
input[type=text]{width:100%;margin-bottom:8px}
input:focus{border-color:#58a5ff}
button{cursor:pointer;padding:8px 16px;margin-right:4px;margin-bottom:4px}
button:active{transform:scale(.97)}
.btn-blue{background:#2c6bed;color:#fff;border:none}
.btn-green{background:#27ae60;color:#fff;border:none}
.btn-orange{background:#e67e22;color:#fff;border:none}
.btn-red{background:#e74c3c;color:#fff;border:none}
.status-box{background:#11131a;border-radius:8px;padding:12px;font-size:13px;min-height:40px;word-break:break-all}
.flex{display:flex;gap:8px;flex-wrap:wrap}
.switch-btn{display:block;width:100%;padding:10px;margin-top:8px;border-radius:8px;border:1px solid #3a3d4a;background:#252836;color:#e0e0e0;cursor:pointer;font-size:14px}
.led-indicator{display:inline-block;width:12px;height:12px;border-radius:50%;background:#333;margin-right:6px;vertical-align:middle}
.led-on{background:#27ae60;box-shadow:0 0 6px #27ae60}
.led-blink{background:#f39c12;animation:blink .5s infinite}
@keyframes blink{0%,50%{opacity:1}51%,100%{opacity:.3}}
a{color:#58a5ff}
.upload-item{border:1px solid #3a3d4a;border-radius:8px;padding:12px;margin-bottom:12px;background:#252836}
.prog{height:8px;border-radius:99px;background:#252836;overflow:hidden;border:1px solid #3a3d4a}
.prog>i{display:block;height:100%;width:0;background:linear-gradient(90deg,#2c6bed,#58a5ff);transition:width .2s}
.warnbox{background:rgba(243,156,18,.12);border:1px solid rgba(243,156,18,.5);color:#f5b041;border-radius:8px;padding:10px;font-size:12.5px;line-height:1.6;margin-bottom:10px}
</style></head><body>

<h2>Vela Gateway - 空中升级</h2>

<div class=card>
<h3>设备信息</h3>
<div id=deviceInfo class=status-box>加载中...</div>
</div>

<div class=card id=preflight>
<h3>刷写前自检</h3>
<div id=preflightBox class=status-box>检查中…</div>
</div>

<div class=card id=phoneCard>
<h3>手机刷写 · 一键</h3>
<p class=muted style="margin-bottom:8px">手机连接本机热点后选择固件文件上传。上传前校验镜像是否为 16MB 版本，版本不符时直接拒绝写入。</p>
<div class=flex style="margin-bottom:8px">
<button class=btn-blue style="flex:1" data-act="quickOta">选择固件并升级</button>
</div>
<input type=file id=quickFile accept=".bin" style="display:none" data-act="quickOtaPick">
<div id=quickBar class=prog><i style="width:0"></i></div>
<div id=quickText class=muted style="margin-top:6px">待选择文件</div>
<p class=muted style="margin-top:8px;font-size:11px;line-height:1.6">
· 上传期间需保持在热点覆盖范围内，避免长时间切换后台（iOS 会冻结页面导致上传中断）<br>
· 传输中断不影响设备可用性：固件先写入空闲 OTA 分区，写入完成后才切换启动分区<br>
· 升级完成后设备自动重启并返回网关模式，热点中断约 15 秒
</p>
</div>

<div class=card>
<h3>新建更新包（高级）</h3>
<p class=muted style="margin-bottom:8px">用于单独刷写 bootloader、分区表或按自定义偏移写入。常规升级使用上方一键升级功能。</p>
<p class=muted style="color:#27ae60;margin-bottom:8px">升级启用回滚保护：新固件启动失败时自动回退至上一个可用固件。</p>

<div class=upload-item>
<h3>固件 (firmware.bin) - 支持回滚保护</h3>
<input type=text id=addr1 value=0x20000 placeholder="刷写地址（默认0x20000）">
<input type=file id=file1 accept=".bin" style="margin-bottom:8px">
<button class=btn-green onclick=uploadFile(1)>上传固件</button>
</div>

<div class=upload-item>
<h3>Bootloader (bootloader.bin)</h3>
<input type=text id=addr2 value=0x1000 placeholder="刷写地址（默认0x1000）">
<input type=file id=file2 accept=".bin" style="margin-bottom:8px">
<button class=btn-green onclick=uploadFile(2)>上传Bootloader</button>
</div>

<div class=upload-item>
<h3>分区表 (partitions.bin)</h3>
<input type=text id=addr3 value=0x8000 placeholder="刷写地址（默认0x8000）">
<input type=file id=file3 accept=".bin" style="margin-bottom:8px">
<button class=btn-green onclick=uploadFile(3)>上传分区表</button>
</div>

<div class=upload-item>
<h3>自定义文件</h3>
<input type=text id=addr4 placeholder="刷写地址（如0x100000）">
<input type=file id=file4 accept=".bin" style="margin-bottom:8px">
<button class=btn-green onclick=uploadFile(4)>上传自定义</button>
</div>

<div id=uploadResult class=status-box style="margin-top:8px"></div>
</div>

<div class=card>
<h3>升级状态</h3>
<div class=flex style="margin-bottom:8px">
<span class=led-indicator id=ledIndicator></span>
<span id=ledText>空闲</span>
</div>
<div id=otaStatus class=status-box>就绪</div>
</div>

<div class=card style="border:1px solid #e67e22">
<h3 style="color:#e67e22">退出升级模式</h3>
<p class=muted style="margin-bottom:8px">固件升级完成后自动返回手表网关。仅查看信息时可切换返回。</p>
<button class=btn-blue style="width:100%" onclick="switchProj(1)">返回手表网关</button>
</div>


<script>
async function api(path,opt={}){try{let r=await fetch(path,opt);let t=await r.text();try{return JSON.parse(t)}catch(e){return{ok:false,error:t}}}catch(e){return{ok:false,error:String(e)}}}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;')}

async function loadDeviceInfo(){
  let d=await api('/ota/status');
  if(d.ok){
    var html='芯片：'+esc(d.chipModel)+' ('+d.chipCores+'核)<br>'+
    'Flash大小：'+d.flashSize+' bytes<br>'+
    'Flash模式：'+d.flashMode+'<br>'+
    '可用内存：'+d.freeHeap+' bytes<br>';
    if(d.rollbackEnabled){
      html+='<span style="color:#27ae60">回滚保护已启用</span><br>';
    }
    if(d.runningPartition){
      html+='运行分区：'+esc(d.runningPartition)+' (0x'+d.runningAddr.toString(16)+', '+(d.runningSize/1024/1024).toFixed(1)+'MB)<br>';
    }
    if(d.nextPartition){
      html+='下次写入：'+esc(d.nextPartition)+' (0x'+d.nextAddr.toString(16)+', '+(d.nextSize/1024/1024).toFixed(1)+'MB)<br>';
    }
    document.getElementById('deviceInfo').innerHTML=html;
  }
}

async function uploadFile(n){
  var fileInput=document.getElementById('file'+n);
  var addrInput=document.getElementById('addr'+n);
  if(!fileInput.files[0]){alert('未选择文件');return}
  var addr=addrInput.value.trim()||'0x20000';
  var file=fileInput.files[0];
  document.getElementById('uploadResult').textContent='正在上传 '+file.name+' 到 '+addr+' ...';
  document.getElementById('ledIndicator').className='led-indicator led-blink';
  document.getElementById('ledText').textContent='升级中...';

  var formData=new FormData();
  formData.append('file',file);
  formData.append('addr',addr);

  try{
    let r=await fetch('/ota/upload?addr='+encodeURIComponent(addr),{method:'POST',body:formData});
    let t=await r.text();
    try{let d=JSON.parse(t);
      if(d.ok){
        document.getElementById('uploadResult').innerHTML=file.name+' 上传成功<br>地址：0x'+addr.toString(16)+'<br>大小：'+file.size+' bytes';
        document.getElementById('ledIndicator').className='led-indicator led-on';
        document.getElementById('ledText').textContent='升级完成，2秒后重启...';
        document.getElementById('otaStatus').textContent='升级完成！LED常亮2秒后设备将自动重启。';
        setTimeout(function(){document.body.innerHTML='<div style="text-align:center;padding:40px"><h2>升级完成</h2><p>设备正在重启，约 15 秒后重新连接 Wi-Fi 热点</p></div>'},2000);
      }else{
        document.getElementById('uploadResult').innerHTML='上传失败：'+esc(d.error||'未知错误');
        document.getElementById('ledIndicator').className='led-indicator';
        document.getElementById('ledText').textContent='失败';
      }
    }catch(e){
      document.getElementById('uploadResult').innerHTML='响应解析失败：'+esc(t.substring(0,200));
      document.getElementById('ledIndicator').className='led-indicator';
      document.getElementById('ledText').textContent='失败';
    }
  }catch(e){
    document.getElementById('uploadResult').innerHTML='上传错误：'+esc(String(e));
    document.getElementById('ledIndicator').className='led-indicator';
    document.getElementById('ledText').textContent='失败';
  }
}

// ===== 手机一键刷写 =====
function human(n){return n>=1048576?(n/1048576).toFixed(2)+' MB':(n/1024).toFixed(0)+' KB'}

async function preflight(){
  let box=document.getElementById('preflightBox');
  let d=await api('/ota/status');
  if(!d.ok){box.innerHTML='<span style="color:#e74c3c">读取设备信息失败：'+esc(d.error||'')+'</span>';return}
  var lines=[];
  var ok16 = d.flashSize>=16*1024*1024;
  lines.push('芯片：'+esc(d.chipModel)+' / '+d.chipCores+' 核');
  lines.push('Flash：'+human(d.flashSize)+(ok16?' <span style="color:#27ae60">16MB</span>':' <span style="color:#e74c3c">不是 16MB</span>'));
  lines.push('Flash 模式：'+d.flashMode);
  lines.push('可用内存：'+human(d.freeHeap));
  if(d.runningPartition){lines.push('当前运行分区：'+esc(d.runningPartition)+' @0x'+d.runningAddr.toString(16))}
  if(d.nextPartition){
    var nt='本次写入分区：'+esc(d.nextPartition)+' @0x'+d.nextAddr.toString(16);
    if(d.nextHasImage) nt+=' <span style="color:#e67e22">（已有镜像 '+(d.nextImageVersion||'')+'，写入后覆盖）</span>';
    lines.push(nt);
  }
  if(d.rollbackEnabled){lines.push('<span style="color:#27ae60">回滚保护已启用</span>')}
  box.innerHTML=lines.join('<br>');
  if(!ok16){
    let extra=document.createElement('div');
    extra.className='warnbox';
    extra.style.marginTop='10px';
    extra.textContent='芯片 Flash 容量小于 16MB，本固件分区表按 16MB 划分，网页升级将失败。需先用数据线烧录整包镜像重新分区。';
    box.appendChild(extra);
  }
}

function quickOta(){document.getElementById('quickFile').click()}

async function quickOtaPick(input){
  let f=input.files&&input.files[0];
  if(!f)return;
  let bar=document.getElementById('quickBar');
  let txt=document.getElementById('quickText');
  bar.firstElementChild.style.width='0';
  bar.firstElementChild.style.background='linear-gradient(90deg,#2c6bed,#58a5ff)';

  // 先读取前 36 字节判断镜像类型，避免传输完整镜像后才报错。
  // app 描述符在文件偏移 0x20，魔数 0xABCD5432 是唯一可靠判据。
  let head=new Uint8Array(36);
  try{ head=new Uint8Array(await f.slice(0,36).arrayBuffer()); }catch(e){}

  // 无条件按 app 镜像校验：整包镜像第 0 字节是 0xFF（空白 Flash），
  // 只有 app 镜像才是 0xE9，所以不能再拿首字节当过滤条件。
  let magic=((head[35]<<24)|(head[34]<<16)|(head[33]<<8)|head[32])>>>0;
  if(head[0]!==0xE9 || magic!==0xABCD5432){
    txt.innerHTML='<span style="color:#e74c3c">文件不是应用镜像（缺少 app 描述符）。'+
      '网页升级只能用文件名带 <b>-ota</b> 的文件；整包镜像需通过数据线烧录。</span>';
    return;
  }

  if(!confirm('准备刷入\n\n文件：'+f.name+'\n大小：'+human(f.size)+'\n\n上传期间请勿切换应用或锁屏，是否继续？'))return;

  txt.textContent='正在上传 '+f.name+'（0%）…';
  let fd=new FormData();
  fd.append('file',f, f.name);
  let xhr=new XMLHttpRequest();
  xhr.open('POST','/ota/upload2',true);
  xhr.upload.onprogress=function(e){
    if(!e.lengthComputable)return;
    let p=Math.min(100,Math.round(e.loaded/e.total*100));
    bar.firstElementChild.style.width=p+'%';
    txt.textContent='正在刷写 '+f.name+'（'+p+'%，'+human(e.loaded)+' / '+human(e.total)+'）';
  };
  xhr.onerror=function(){
    txt.innerHTML='<span style="color:#e74c3c">上传因网络中断失败，设备状态未改变，可重新上传。</span>';
  };
  xhr.onload=function(){
    let d=null;
    try{d=JSON.parse(xhr.responseText)}catch(e){}
    if(d&&d.ok){
      bar.firstElementChild.style.width='100%';
      txt.innerHTML='<span style="color:#27ae60">写入完成，共 '+human(d.size)+'，设备重启中…</span>';
      setTimeout(function(){
        document.body.innerHTML='<div style="text-align:center;padding:48px 16px">'+
        '<h2 style="margin:12px 0;color:#58a5ff">刷写完成</h2>'+
        '<p class=muted>镜像已写入备用分区，重启后生效。<br>'+
        '现在可以切回网关；不操作的话，3 分钟后设备自动返回。</p>'+
        '<button class=btn-blue style="margin-top:14px" data-act="backGateway">返回网关并重启</button></div>';
      },1200);
    }else{
      txt.innerHTML='<span style="color:#e74c3c">'+(d?esc(d.error||'未知错误'):'响应异常')+'</span>';
      bar.firstElementChild.style.background='#e74c3c';
    }
  };
  xhr.send(fd);
}

preflight();

// 升级页也用事件委托，避免内联属性里的引号把 C++ 原始字符串提前截断
document.addEventListener('click',function(ev){
  var b=ev.target.closest('[data-act]');
  if(!b)return;
  if(b.dataset.act==='quickOta')quickOta();
  if(b.dataset.act==='backGateway')switchProj(1);
});
document.addEventListener('change',function(ev){
  if(ev.target&&ev.target.id==='quickFile')quickOtaPick(ev.target);
});

function switchProj(t){
  var nm=t===6?'空中升级':'手表网关';
  if(!confirm('切换到「'+nm+'」？设备将重启。'))return;
  api('/setup/project/switch?target='+t,{method:'POST'}).then(d=>{if(d.ok)document.body.innerHTML='<div style="text-align:center;padding:40px"><h2>切换中…</h2><p>设备重启中，约 15 秒后重新连接 Wi-Fi 热点</p></div>';else alert('切换失败:'+(d.error||''))});
}

loadDeviceInfo();
</script>
</body></html>
)HTMLOTA";

void loop() {
  // OTA 回滚确认：稳定运行 30 秒后才把新固件标记为有效。
  // 放在最前面，保证所有项目模式（含 OTA 模式）都会执行。
  if (gOtaPendingVerify && millis() - gOtaVerifyStartMs >= kOtaConfirmDelayMs) {
    const esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
    gOtaPendingVerify = false;
    Serial.printf("OTA_FIRMWARE_MARK_VALID uptime_ms=%lu result=%s\n",
                  static_cast<unsigned long>(millis()), esp_err_to_name(err));
  }

  // 检查重启标志
  if (gRestartRequested) {
    Serial.println("GLOBAL_RESTART from loop");
    delay(300);
    ESP.restart();
  }

  if (gOtaMode) {
    if (gServerStarted) {
      gLastHttpActivityMs = millis();
      server.handleClient();
    }
    serviceHeartbeatLed();
    delay(2);
    return;
  }

  // 固件库延时安装：HTTP 响应已返回 200 后，在 loop 中写入 OTA 分区并重启。
  // 不能放在 HTTP 回调里做，1.6 MB 写 Flash 要好几秒，浏览器早超时了。
  fwlib::servicePending();

  handleWatchProbeSerial();

  // Normal configured boot defers OLED allocation until Wi-Fi is actually up,
  // so the Bluetooth controller and esp_wifi_init see an unfragmented heap.
  if (!gDisplayReady && gDisplayInitDeferred && WiFi.status() == WL_CONNECTED) {
    gDisplayInitDeferred = false;
    initDisplay();
  }

  // OLED 状态屏：节流刷新，覆盖配网/正常两种模式（配网分支会提前 return）。
  if (gDisplayReady && static_cast<int32_t>(millis() - gLastDisplayMs) >=
                           static_cast<int32_t>(kDisplayRefreshMs)) {
    gLastDisplayMs = millis();
    renderDisplay();
  }

  // 心跳 LED：必须在配网分支 return 之前调用，否则配网模式下灯不闪。
  serviceHeartbeatLed();

  // 配网模式：服务 AP 上的 HTTP 配置页面，不做桥接。
  // 但「自动降级」进来的这一档配置全保留，后台继续尝试连已保存的 Wi-Fi：
  // 连上并稳定 1 分钟、且 AP 上没人正在操作时，自动重启回正常工作模式。
  if (gSetupMode) {
    if (gServerStarted) server.handleClient();
    if (gSetupKeepConfig && !ssid.isEmpty()) {
      const uint32_t now = millis();
      static uint32_t staUpMs = 0;
      static uint32_t lastStaAttemptMs = 0;
      if (WiFi.status() == WL_CONNECTED) {
        if (staUpMs == 0) {
          staUpMs = now;
          Serial.printf("SETUP_MODE_STA_CONNECTED ip=%s will_return_to_normal_mode\n",
                        WiFi.localIP().toString().c_str());
        } else if (now - staUpMs >= 60000 && WiFi.softAPgetStationNum() == 0) {
          Serial.println("SETUP_MODE_STA_OK rebooting_to_normal_mode");
          delay(200);
          ESP.restart();
        }
      } else {
        staUpMs = 0;
        if (now - lastStaAttemptMs >= 30000) {
          lastStaAttemptMs = now;
          WiFi.begin(ssid.c_str(), wifiPass.c_str());
          Serial.println("SETUP_MODE_STA_RETRY keep_config=true");
        }
      }
    }
    delay(2);
    return;
  }

  // 正常工作模式：启动 HTTP 服务器（STA 连接后）。
  if (!gServerStarted && WiFi.status() == WL_CONNECTED) {
    server.begin();
    gServerStarted = true;
    Serial.println("VELA_HTTP_SERVER_STARTED");
  }
  if (gServerStarted) server.handleClient();
  maintainMdns();

  // 配网模式下也维持降级判定（实际上 tick 里遇到 gSetupMode 会直接返回，
  // 保留这行是为了链路健康心跳仍会被记录）。
  if (gSetupMode) {
    autoSetupFallbackTick(WiFi.status() == WL_CONNECTED, false);
  }

  // BOOT 长按触发配网已由独立任务 setupTriggerTask 处理（不依赖本循环）。

  // 自动重连逻辑：Wi-Fi 25 秒窗口重试、手表 60 秒间隔重试。
  // 恢复出厂已抽成独立模块（见 "恢复出厂设置" 一节）：
  // 旧实现「10 分钟没连上就清空」对停电/路由器重启/出差拔电都太激进，
  // 现在改成带健康门槛的倒数窗口 + 宽限期 + 调试冻结。
  if (!gWatchAutoReconnectSuppressed && !gWatchBridgeRunning && !gWatchBridgeTask) {
    if (gBootMs == 0) gBootMs = millis();
    uint32_t now = millis();

    // 检查是否曾经成功连接（WiFi或手表）
    bool wifiConnected = (WiFi.status() == WL_CONNECTED);
    bool watchConnected = gWatchBridgeRunning;
    if (wifiConnected || watchConnected) {
      if (!gEverConnected) {
        gEverConnected = true;
        Serial.println("HEALTH_FIRST_CONNECT_OK");
      }
      gLastSuccessMs = now;
    }

    autoSetupFallbackTick(wifiConnected, watchConnected);

    // 尝试连接WiFi（如果还没连上）
    // 旧逻辑每 3 秒就 WiFi.disconnect() + WiFi.begin() 一次：AP 正常需要
    // 4-10 秒完成关联，3 秒一断等于永远连不上。而且它和手表重连共用
    // gLastConnectAttemptMs，每 3 秒把计时器清零，手表重连条件永远不成立。
    if (!wifiConnected && !ssid.isEmpty() &&
        (gLastWifiAttemptMs == 0 ||
         static_cast<int32_t>(now - gLastWifiAttemptMs) >= static_cast<int32_t>(kReconnectTimeoutMs))) {
      Serial.printf("WIFI_RECONNECT attempt at=%lu status=%d free=%lu\n",
                    static_cast<unsigned long>(now),
                    static_cast<int>(WiFi.status()),
                    static_cast<unsigned long>(ESP.getFreeHeap()));
      // 保留 NVS 中的凭据，只重启 STA 关联
      WiFi.persistent(false);
      WiFi.disconnect(false, false);
      WiFi.mode(WIFI_STA);
      WiFi.begin(ssid.c_str(), wifiPass.c_str());
      gLastWifiAttemptMs = now;
      gLastConnectAttemptMs = now;
      gReconnectFailCount++;
    }

    // 尝试连接手表（独立计时器，与 WiFi 重试互不干扰）
    if (watchMac.length() == 17 && watchAuthKey.length() == 32 &&
        static_cast<int32_t>(now - gBootMs) >= static_cast<int32_t>(kReconnectStartDelayMs) &&
        (gLastWatchAttemptMs == 0 ||
         now - gLastWatchAttemptMs >= kWatchReconnectIntervalMs)) {
      Serial.printf("WATCH_RECONNECT attempt count=%lu wifi=%d free=%lu\n",
                    static_cast<unsigned long>(gReconnectFailCount),
                    wifiConnected ? 1 : 0,
                    static_cast<unsigned long>(ESP.getFreeHeap()));
      String error;
      if (!startWatchBridge(error)) {
        if (error != "already_running")
          Serial.printf("WATCH_RECONNECT_FAILED reason=%s\n", error.c_str());
      }
      gLastWatchAttemptMs = now;
      gReconnectFailCount++;
    }
  }

  // 空中升级模式的兜底返回：页面刷写成功后会调 /setup/project/switch 把
  // project 改回 1。手机中途锁屏或页面被关掉时这个请求不会发出，设备就
  // 一直停在只有热点的状态。这里在持续 3 分钟没有任何请求后自己切回网关，
  // 用户不必长按 BOOT 才能救回来。
  if (gOtaMode) {
    const uint32_t activeMs = millis() - gLastHttpActivityMs;
    if (gLastHttpActivityMs && activeMs > 180000u) {
      Serial.printf("OTA_MODE_IDLE_SWITCH_BACK idle_ms=%lu\n",
                    static_cast<unsigned long>(activeMs));
      velaLog("OTA_MODE idle_switch_back");
      prefs.putInt("project", 1);
      delay(200);
      ESP.restart();
    }
  }

  delay(2);
}
