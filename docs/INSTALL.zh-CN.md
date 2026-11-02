# ESP 安装与回滚（设备侧操作）

设备侧写入只对**你自己的平板**、在逐次明确授权下进行。本文是流程说明；
所有工具以 `NABU_ADB_SERIAL` 环境变量寻址设备，仓库不含任何序列号。

## 一次性 ESP 准备

1. **完整 ESP 备份**（必须先做）：平板进 Android/Recovery，root 的 adb
   环境读取整个 ESP 分区（约 334 MiB，nabu 上为 `/dev/block/sda31`），
   保留字节级镜像和 sha256 收据。`device_bringup/backup_esp` 类工具曾用于
   此；关键是**备份完整且可回写验证**，工具本身可自选。
2. **安装引导链**：在 ESP 上放 rEFInd + `/EFI/UniXNU/UniXNU.efi`（UniXNU
   菜单加载器）+ `/EFI/UniXNU/Drivers/DarwinBoot.efi`。UniXNU.efi/
   DarwinBoot.efi 来自上游 UniXNU 树的固件构建。
3. **首个菜单** `/EFI/UniXNU/unixnu.toml`：`[boot] default = "return"`，
   一个 `return` 项（回 rEFInd）+ 至少一个保留项。之后的候选安装只增
   删 payload 条目，不动引导链。
4. **记录基线**：`refind.conf` sha256、ESP 空闲块数（`esp_kblocks`）、
   当前 `boot_id`——候选打包器把这些作为安装前检查值写进包。

## 候选安装（每次迭代）

1. 打包：`scripts/package.sh <resolved tree>` 产出
   `out/nabu/<profile>/payload.img` + `stage/`；或用
   `device_bringup/xnu_stage/` 下对应 profile 的打包器产出
   `files/ + original/ + install.sh + manifest.json + transfer-checksums.txt`
   的包目录（含旧负载原文，回滚自包含）。
2. 传输：`adb push` 包到 `/data/local/tmp/<tag>/`（工具不含序列号，
   由 `NABU_ADB_SERIAL` 寻址）。
3. 装前检查（install.sh 内建，逐项 fail-stop）：设备型号/boot_id/
   ESP 别名/可用工具/传输校验和/菜单往返/被替换负载的 sha256。
4. 安装：`su -c 'sh install.sh install <stage>'`——挂载 ESP 只读→原子
   写入新 payload+菜单（先 `.new` 再 `mv`）→卸 ESP。脚本**不重启**。
5. 安装收据：装后立即重读 ESP，对新文件 sha256、菜单文本、boot_id
   逐项核对并落盘。

## 回滚

每个包都带 `original/` 完整副本 + `install.sh restore`：同一收据校验
后换回旧 payload/菜单。ESP 备份镜像是最底层兜底（不进仓）。

## 读取启动日志（NABULOG2）

内核含 `nabu-log=1` writer 时，日志写进 ESP 预分配 `XNU2LOG.BIN`；
系统起来后 adb 只读拉回、CRC 校验、导出文本（见 `porting.toml`
diagnostics 的 device 证据）。工具只读，不重启不刷写。

## 边界

- 不绕过任何锁、不改分区表、不动 userdata/super/cust；UFS 窗口是
  sda 上预留未分配区，GPT 的 userdata 条目原样属于 Android。
- `install_prepared_xnu.py`、`backup_recovery.py` 等 adb 工具一律
  `NABU_ADB_SERIAL` 寻址；请核对你的设备再授权。
