# UniXNU-nabu

Xiaomi Pad 5（nabu，SM8150 / Adreno 640）的 UniXNU 设备仓库：在源码构建的
XNU 上运行 iPadOS 17.7（21H16，iPad7,11 j171ap）。

移植状态、分区证据与当前限制见 [`porting.toml`](porting.toml)；硬件输入见
[`board.toml`](board.toml) 与 [`dts/nabu.dts`](dts/nabu.dts)。

## 已实现（证据见 porting.toml）

- 八核 bring-up：SGI IPI 投递、GICv3 与架构定时器
- UFS 根卷（OS + SystemOS）、易失性 RAM Data 种子、union 挂载的
  SystemOS 缓存载体
- NT36523 触摸输入
- GOP 帧缓冲显示 + A640 GPU 合成输出；Metal 前端经 metal2vulkan +
  Turnip 为用户态客户端服务
- 实机上演示过可交互的 SpringBoard UI
- NABULOG2 ESP 启动日志，经 ADB 回读并完成 CRC 校验

## 已知限制

- 偶发的有界 scanout 停帧（首批若干帧后出现）仍在修复中
  （completion-wait 补丁已打包，尚未实机验证）
- 持久化 Data 卷、Wi-Fi、音频、电源管理与硬件恢复均未实现
- `board.dsc`/`fd` 为空：本板走原厂 Xiaomi UEFI + rEFInd 启动，ESP 上
  安装 UniXNU.efi 与 DarwinBoot.efi——本仓库不构建固件镜像

## 目录结构

| 路径 | 用途 |
| --- | --- |
| `board.toml` / `porting.toml` / `components.toml` / `feeds.toml` | 格式 2 设备配置与移植记录 |
| `configs/` | 内核 defconfig（`nabu_ufs_gpu_metal_defconfig` 为发布配置） |
| `dts/` | 板级设备树 |
| `patches/xnu/` | 设备 XNU 补丁序列 |
| `patches/*.patch` | 上游组件的板级补丁（adrenometal、NativeUfs、mesa-turnip） |
| `platform/` `ufs/` `gpu/` `usb/` `userprobe/` `vendor/` | 板级代码：平台服务、UFS 资源、A640 GPU、USB 探测、用户态探测、厂商帧缓冲源 |
| `scripts/` | 板级对象构建脚本（由 `source-ci/prepare_source.py` 编排调用） |
| `source-ci/` | 源码树装配、输出归集、显示/Turnip CI 编排脚本 |
| `scripts/package.sh` | ESP 负载打包入口 |
| `proprietary-files.txt` | 构建时获取的固件输入（绝不入库） |

## 构建

需要用户自有的 iPadOS 17.7（21H16）IPSW、macOS + Xcode 工具链。完整流水线
（源码树装配 → 内核构建 → 打包）由 `source-ci/prepare_source.py` +
`./unixnu build` + `scripts/package.sh` 组成；私有派生输入的获取方式见
`docs/BUILD-INPUTS.zh-CN.md`（本仓所有输入由用户自备，不随仓分发）。

设备侧产物仅在逐次明确授权下安装到 ESP，并保留回滚收据；运行证据见
`porting.toml`。

## 许可

BSD-2-Clause-Patent（见 `LICENSE`）。苹果固件与厂商固件 blob 仅作为
输入，绝不入库跟踪。
