#!/usr/bin/env bash
# YD-ESP32 16MB 固件刷写脚本（首次换分区表必须整片擦除）
#
# 用法：
#   ./flash_16mb.sh [串口] [镜像文件]
#   ./flash_16mb.sh /dev/ttyUSB0
#   ./flash_16mb.sh /dev/ttyUSB1 firmware/vela-gateway-v0.0.0.14-esp32-16mb-factory.bin
#
# 不指定镜像时，自动取 firmware/ 下最新的 *-factory.bin。factory 已经把
# bootloader、分区表、otadata、app 合并好了，从 0x0 一次写完，等价官方 Factory 镜像。
#
# 依赖：pip install esptool
set -euo pipefail

PORT="${1:-/dev/ttyUSB0}"
# 没指定就取最新的 factory 产物。写死版本号的话，下次出包后脚本就找不到文件了。
if [ -z "${2:-}" ]; then
  IMG=$(ls -t firmware/*-factory.bin 2>/dev/null | head -1 || true)
  if [ -z "$IMG" ]; then
    echo "firmware/ 下没有 *-factory.bin，先跑 pio run -e yd_esp32_16mb" >&2
    exit 1
  fi
else
  IMG="$2"
fi

cd "$(dirname "$0")"

if [ ! -f "$IMG" ]; then
  echo "找不到镜像：$IMG" >&2
  echo "请先执行 pio run -e yd_esp32_16mb，或确认 firmware/ 下有预编译好的 bin" >&2
  exit 1
fi

echo "==> 目标串口: $PORT"
echo "==> 镜像    : $IMG ($(du -h "$IMG" | cut -f1))"
echo
# 烧录前校验：otadata 全 0xFF 会导致 bootloader 每 2 秒复位一次
if command -v python3 >/dev/null 2>&1 && [ -f tools/verify_firmware.py ]; then
  if ! python3 tools/verify_firmware.py firmware; then
    echo
    echo "!! 镜像校验未通过，已中止烧录（避免刷成一个只会在 2 秒内复位的板子）" >&2
    echo "   otadata 修复：cp framework-arduinoespressif32/tools/partitions/boot_app0.bin firmware/ota_data_initial.bin" >&2
    exit 1
  fi
  echo
fi

echo "==> 整片擦除 + 写入（约 30-60 秒，请勿断电）"

esptool.py --chip esp32 --port "$PORT" --baud 921600 \
  write_flash --erase-all -z \
  --flash_mode dio --flash_freq 80m --flash_size 16MB \
  0x0 "$IMG"

echo
echo "==> 完成。按一下复位键，串口（921600 波特）应看到："
echo "    BOOT ... flash=16777216 bytes (16.0 MB)"
echo "    BOOT app_partition=ota_0 addr=0x00020000 size=6291456 ..."
echo
echo "如果反复重启：确认用的是本脚本的 --erase-all（旧 otadata 会让 bootloader 找错分区）。"
