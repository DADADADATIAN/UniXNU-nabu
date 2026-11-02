# iPadOS 输入检查工具

项目选定的输入与已取得证据见 [当前状态](../../CURRENT_STATUS.zh-CN.md)。本目录同时包含
受版本绑定的实验和输入材料；本页只说明 `inspect_ipsw.py`，不作为固件处理或启动路线。

## 检查器范围

检查器只读 IPSW/解包目录中的 `BuildManifest.plist` 与可选 `Restore.plist`，输出产品类型和版本元数据。
它不联网、不提取成员、不验证签名/信任、不检查内核 ABI，也不证明系统能启动。
退出码 0 表示 iPadOS 17 且 manifest 含 iPad 产品；1 表示解析成功但版本门不通过；2 表示输入拒绝或解析错误。

```powershell
py -3 -B device_bringup/ipados17_inputs/inspect_ipsw.py "<IPSW 或解包目录>"
py -3 -B -m unittest discover -s device_bringup/ipados17_inputs -p test_inspect_ipsw.py -v
```

输出默认为新时间戳文件；`--output` 目标必须不存在且不得是输入路径。合成测试不读取真实 IPSW。

真实 21H16 输入、完整解码、信任/代码页检查和 QEMU/真机 APFS 证据由
[CURRENT_STATUS](../../CURRENT_STATUS.zh-CN.md) 索引。旧 CoreCrypto/APFS smoke 与预链实验步骤不再作为当前任务；
清理前完整说明保存在忽略归档 `local_notes/superseded-reports-20261024-part2.zip`。
