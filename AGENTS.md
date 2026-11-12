# 构建与发布

## 环境

```
平台: espressif32@6.1.0 + framework-espidf @ 3.40404.0 (IDF 4.4.4) + Arduino core 2.0.7
命令: /root/pioenv/bin/pio run -e yd_esp32_16mb
产物: .pio/build/yd_esp32_16mb/firmware.bin
```

`version.txt` 是真源。`tools/pio_version.py` 在构建前按源码指纹递增修订号，重新编译后 app 描述符里的版本才同步；只改 version.txt 而不重编，产物里的版本串不会变。

## 产物

```
python3 tools/make_artifacts.py     # 生成 factory / ota 两个 bin 到 firmware/
python3 tools/verify_firmware.py    # 校验镜像头与版本串
python3 tools/check_partitions.py partitions_ota_16mb.csv 16
```

## 发布

凭据已配置在本机：`~/.git-credentials`（credential.helper=store）、`gh auth`（账号 shikongxiaohan）、`~/.gh_token`。直接执行即可，不需要重新获取或询问令牌。

```
git add -A && git commit -m "..."
git tag -a vX.Y.Z -m "..." && git push origin HEAD:main --tags
gh release create vX.Y.Z firmware/*vX.Y.Z*-ota.bin firmware/*vX.Y.Z*-factory.bin \
  --title "..." --notes-file /tmp/rel.md --latest
```

中间态版本不要打标签。v0.0.0.32 曾作为改版过程中的临时构建打过标签，已删除。

## 静态检查

```
python3 tools/pio_verify.py    # 构建前钩子，串起 tools/test_*.py
```

单个脚本可直接运行，例如 `python3 tools/test_ota_push_honesty.py`。
