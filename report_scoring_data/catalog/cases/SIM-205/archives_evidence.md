# SIM-205 Archives 取证记录

取证日期：2026-08-05  
正式 RUN：`WAZUH-LAB-SIM-205-20260805T130102Z-1963EF3C`  
Agent：`003 / win10_node2`  
索引：`wazuh-archives-4.x-2026.08.05`

## 完整 alert 精确回读

按 `_index=wazuh-alerts-4.x-2026.08.05` 与 `_id=NGcD0p8BWAEr461gdrcu`
精确回读并保存完整原始文档：

```text
SIM-205-alert.json
SHA256: 74C396BD8182F06EB736B04197436FEA65B265ABF6339F759248814BA7A79991
```

完整告警确认：Agent `003`、规则 `92041 / level 10`、Sysmon Event ID 1、
`reg.exe add` PID 4996、ProcessGuid `...1a04...`、父 PowerShell PID 1760 / GUID
`...1904...`。命令行包含 RUN 专属 HKCU 路径；Base64 解码为：

```text
RUN_ID=WAZUH-LAB-SIM-205-20260805T130102Z-1963EF3C
```

## 冻结查询边界

- 时间窗：`2026-08-05T13:00:02Z` ～ `2026-08-05T13:02:03Z`；
- 只接受 `agent.id=003`；
- 从两条包含完整 RUN ID 的 `reg.exe` Event ID 1 出发；
- 只用 ProcessGuid、ParentProcessGuid、SourceProcessGuid、TargetProcessGuid 扩展；
- 逐层扩展 launcher PowerShell、cmd 和 explorer 祖先，最终按 `_index` 与 `_id`
  精确回读 18 个唯一文档。

主查询：`SIM-205-archives-query.json`  
完整原始文档：`SIM-205-archives.json`  
补充探针：`SIM-205-archives-probes.json`

## 核心进程链

| UTC time | 文档 ID | Event ID | 进程关系 | 关键事实 |
|---|---|---:|---|---|
| 13:01:02.727 | `HGcD0p8BWAEr461gXrfX` | 1 | `explorer.exe → cmd.exe(5880)` | `cmd.exe /C C:\round2\SIM-205\runtime\trigger.bat` |
| 13:01:04.759 | `IWcD0p8BWAEr461gZrep` | 1 | `cmd.exe(5880) → powershell.exe(1760)` | 启动 `simulation.ps1`；GUID `...1904...` |
| 13:01:04.944 | `LWcD0p8BWAEr461gZrep` | 1 | `powershell.exe(1760) → reg.exe(4996)` | `reg add` 写入 RUN 专属 HKCU 路径与 Base64-like 值 |
| 13:01:04.975 | `L2cD0p8BWAEr461gZrep` | 1 | `powershell.exe(1760) → reg.exe(1084)` | `reg query` 查询同一 RUN 专属值 |

父子 GUID 连续一致：

```text
cmd.exe 5880 / ...1504...
  → launcher powershell.exe 1760 / ...1904...
      → reg.exe add 4996 / ...1a04...
      → reg.exe query 1084 / ...1c04...
```

## 事件分布与遥测缺口

18 个冻结文档的 Event ID 分布：

```text
Event ID 1  : 4
Event ID 7  : 8
Event ID 11 : 2
Event ID 13 : 2
Event ID 17 : 1
Event ID 26 : 1
```

两条 Event ID 13 均为 BAM 系统活动：

- cmd.exe 写入 PowerShell 的 BAM 路径；
- launcher PowerShell 写入自身 BAM 路径。

它们都不是 RUN 专属 `HKCU\Software\WazuhLab\<RUN_ID>\Data` 的注册表值写入。
以下扩大探针均为 0：

- RUN ID 出现在 `targetObject`；
- ±5 分钟内任何 Event ID 13 的 `targetObject` 包含 RUN 专属路径；
- GUID 关联结果中由 `reg.exe(4996)` 产生的 Event ID 13。

因此 Archives 只直接确认 `reg add` 和 `reg query` 的命令执行，未提供计划中的 RUN
专属 RegistryValueSet 遥测。命令行证明写入命令被启动，不等于 Event ID 13 已直接
确认值写入成功；后续 manifest 可以作评分侧 Ground Truth 交叉验证，但不能替被测
智能体补充不可访问证据。

## 完整性哈希

```text
SIM-205-archives-query.json
36BBC4D511B7BAF760334B73C414D5146BCF58981C599FD03F063EC3AA4B583B

SIM-205-archives.json
697E8ED25C52945D03A6E1AF727191590B5DEAB3C70706FF174B4606DC52DFD6

SIM-205-archives-probes.json
8AA2849499EF4FA67F03646B2796B8A2093E3D0514140EE1A99138BCECD4BF29
```

结论：完整 alert、核心进程链与查询行为已经冻结。用户已接受本次缺少 RUN 专属 Event
ID 13 的降级遥测并保留正式 RUN；该不可见证据将统一排除在九份报告的召回分母之外，
不因缺失本身扣分。runtime manifest 已核验，正式 anchor/input 已冻结；下一阶段由
用户从冻结 TXT 手动创建三智能体各三次 fresh task。
