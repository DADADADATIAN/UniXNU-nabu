# 构建输入（用户自备，不随仓分发）

本仓库不含任何苹果版权内容。下列输入由每位使用者从**自己合法持有的**
iPadOS 17.7（21H16）IPSW 与本机数据派生；sha256 在 `board.toml` 与脚本里
全部钉死，派生结果可逐字节验证。

## 1. `ipsw-21h16-small.zip`（构建必需）

完整 IPSW 里构建只用到 BuildManifest + 4 个小成员（kernelcache、
DeviceTree、两个静态信任缓存）。用自带 IPSW 生成：

```sh
python3 source-ci/prepare_ipsw_input.py \
    --ipsw /path/to/iPad_10.2_17.7_21H16_Restore.ipsw \
    --output ipsw-21h16-small.zip
```

- 4 个成员的 sha256 逐一对比 `board.toml [ipsw.sha256]`；不符即失败
- 输出 zip 为确定性打包（排序、固定时间戳、无附加字段）
- 若 zip sha256 = `fce1ea…`（项目私有输入同款）即字节级一致；成员一致
  而 zip 不同也算通过，此时把生成器打印的 sha256 作为你自己构建的输入标识

构建时导出：`export UNIXNU_IPSW=/path/to/ipsw-21h16-small.zip`

## 2. owner 策略（owner/UFS profile 必需）

`os-policy.tar.gz` 与 `systemos-policy.tar.gz` 由上游 kit
`kits/VerifiedRoot/tools/manifest.py` 用**本机 raw 磁盘 + 卷 UUID +
generation + 本地 owner 私钥**生成，内容 = manifest + 公钥锚 + 元数据；
私钥留在本地。第三方须用**自己的磁盘与密钥**生成（这正是 owner-anchored
设计），参考原项目 `docs/BUILD.zh-CN.md` 的生成流程。生成后：

```sh
mkdir owner-policy systemos-policy
tar -xzf os-policy.tar.gz -C owner-policy
tar -xzf systemos-policy.tar.gz -C systemos-policy
export UNIXNU_OWNER_POLICY=$PWD/owner-policy
export UNIXNU_OWNER_POLICY_SYSTEMOS=$PWD/systemos-policy
```

## 3. 显示参考 `kernel.macho`（仅 display/CPU-present/GPU profile 的 ABI 门）

`nabu_display_ci.py` 用一份**先前已验证构建**的 `kernel.macho` 做 ABI
对比门（`REFERENCE = run 40446350654`）。项目的那份在私有发布资产里，
第三方拿不到；替代：

- 先构建并通过 `nabu_ufs_readonly_defconfig`/`nabu_ufs_cpu_present_defconfig`
  的候选，把产出的 `kernel.macho` 作为自己的参考；
- 或跳过 ABI 门（改 `nabu_display_ci.py` 的 REFERENCE 预期），此时显示路径
  失去参考对比保护，记录证据时要注明。

```sh
export UNIXNU_DISPLAY_REFERENCE=/path/to/reference-dir   # 内含 kernel.macho
```

## 4. 平台种子 `UNIXNU_UNIQUE_CHIP_ID`（payload 必需）

`board.toml [payload.adt] unique_chip_id = "required"`：每台设备的平台
种子不进任何仓库。用你自己设备的值，构建 payload 时：

```sh
export UNIXNU_UNIQUE_CHIP_ID=<hex>     # 或 --unique-chip-id HEX
```

## 5. 厂商固件 `proprietary-files.txt`

`a640_zap.mbn` 等固件 blob 在构建时从 linux-firmware/设备固件分区获取，
sha256 钉在 `proprietary-files.txt`，绝不入库。

## 校验

每次构建前流水线自动校验输入：`prepare_source.py` 检查 profile/闭包/
补丁 sha，`unixnu` 抽取成员时复核 pin，`collect_outputs.py` 把实际输入
sha256 写进 manifest——任何人可据此审计一次构建用了什么。
