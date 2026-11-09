@echo off
chcp 65001 >nul
REM YD-ESP32 16MB 固件刷写脚本（首次换分区表必须整片擦除）
REM 用法: flash_16mb.bat [COM口] [镜像文件]
REM 例:   flash_16mb.bat COM3
REM 依赖: pip install esptool

setlocal
cd /d "%~dp0"

set PORT=%1
if "%PORT%"=="" set PORT=COM3

set IMG=%2
if "%IMG%"=="" set IMG=firmware\vela-gateway-v0.0.0.1-esp32-16mb-factory.bin

if not exist "%IMG%" goto missing

echo ==^> 目标串口: %PORT%
echo ==^> 镜像    : %IMG%
echo.
REM 烧录前校验：otadata 全 0xFF 会导致 bootloader 每 2 秒复位一次
if exist tools\verify_firmware.py (
  python tools\verify_firmware.py firmware
  if errorlevel 1 (
    echo.
    echo !! 镜像校验未通过，已中止烧录
    echo    修复 otadata: copy /y parts\boot_app0.bin firmware\ota_data_initial.bin
    pause
    exit /b 1
  )
  echo.
)

echo ==^> 整片擦除 + 写入（约 30-60 秒，请勿断电）

esptool.py --chip esp32 --port %PORT% --baud 921600 write_flash --erase-all -z --flash_mode dio --flash_freq 80m --flash_size 16MB 0x0 "%IMG%"
if errorlevel 1 goto fail

echo.
echo ==^> 完成。按一下复位键，串口（921600 波特）应看到：
echo     BOOT ... flash=16777216 bytes (16.0 MB)
echo     BOOT app_partition=ota_0 addr=0x00020000 size=6291456 ...
pause
exit /b 0

:missing
echo 找不到镜像 %IMG%
echo 请确认 firmware\vela-gateway-v0.0.0.1-esp32-16mb-factory.bin 存在，或先运行 pio run -e yd_esp32_16mb
pause
exit /b 1

:fail
echo 刷写失败：检查串口是否被占用、CH340 驱动是否装好、板子是否在下载模式
pause
exit /b 1
