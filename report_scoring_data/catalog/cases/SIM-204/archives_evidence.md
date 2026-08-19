# SIM-204 Archives 取证记录

取证日期：2026-08-05  
正式 RUN：`WAZUH-LAB-SIM-204-20260805T080419Z-0D707D7F`  
Agent：`003 / win10_node2`  
索引：`wazuh-archives-4.x-2026.08.05`

## 冻结查询边界

- 主查询时间窗：`2026-08-05T08:03:19Z` ～ `2026-08-05T08:05:19Z`；
- 只接受 `agent.id=003`；
- 只用本次链路已确认的 `ProcessGuid` / `ParentProcessGuid` 关联；
- 未使用 PID 单独扩窗，避免 PID `2080` 在 08:08 被其他进程复用造成污染；
- 主查询共命中 32 个唯一文档，均已按 `_index` 与 `_id` 精确回读并完整保存。

主查询：`SIM-204-archives-query.json`  
完整原始文档：`SIM-204-archives.json`  
补充探针：`SIM-204-archives-probes.json`

## 核心进程链

| UTC time | 文档 ID | Event ID | 进程关系 | 关键事实 |
|---|---|---:|---|---|
| 08:04:16.843 | `I2fz0J8BWAEr461gxKH4` | 1 | `explorer.exe → cmd.exe(5196)` | `cmd.exe /C C:\round2\SIM-204\runtime\trigger.bat` |
| 08:04:19.029 | `JWfz0J8BWAEr461gxKH4` | 1 | `cmd.exe(5196) → powershell.exe(7128)` | 启动 `simulation.ps1`；ProcessGuid `...bf01...` |
| 08:04:19.339 | `Mmfz0J8BWAEr461gxKH4` | 1 | `powershell.exe(7128) → powershell.exe(4248)` | 子进程带 `-EncodedCommand`；ProcessGuid `...c001...` |
| 08:04:19.561 | `QWfz0J8BWAEr461gxKH4` | 1 | `powershell.exe(7128) → findstr.exe(2080)` | 命令行含完整 RUN ID 和 RUN 专属结果文件路径；ProcessGuid `...c201...` |

父子 PID 与 GUID 连续一致：

```text
cmd.exe 5196 / ...bb01...
  → launcher powershell.exe 7128 / ...bf01...
      → encoded child powershell.exe 4248 / ...c001...
      → findstr.exe 2080 / ...c201...
```

告警 anchor 的 `ParentProcessGuid={5fc1445e-ee83-6a72-bf01-000000001600}` 与
launcher 一致，告警子进程 `ProcessGuid={5fc1445e-ee83-6a72-c001-000000001600}`
与 Archives 子 PowerShell 一致；`findstr.exe` 同样以 launcher 为父进程，并通过完整
RUN ID 将该链归属于本次正式 RUN。

## 其他已冻结事件

32 个文档的 Event ID 分布：

```text
Event ID 1  : 4
Event ID 7  : 16
Event ID 11 : 4
Event ID 13 : 4
Event ID 17 : 2
Event ID 26 : 2
```

Event ID 7、13、17、26 以及 Event ID 11 中的 PowerShell 策略测试/启动配置事件均
按 GUID 完整保留，但不自动解释为本次编码命令的攻击副作用。

## 已确认遥测缺口

对 RUN 专属 `targetFilename` 的显式查询返回 0 条。现有 Archives 没有直接记录：

```text
C:\ProgramData\WazuhLab\WAZUH-LAB-SIM-204-20260805T080419Z-0D707D7F\
WAZUH-LAB-SIM-204-20260805T080419Z-0D707D7F-result.txt
```

因此不能仅凭 Archives 把结果文件 FileCreate 写成“已被遥测直接确认”。Archives 已
充分确认 trigger、launcher、编码子 PowerShell、后续 findstr 查询及它们的父子关系；
结果文件存在与子进程完成状态仍需用正式 runtime manifest 做评分侧交叉验证。

## 完整性哈希

```text
SIM-204-archives-query.json
1623CC528EB7AFB26A0C34F1857051C4E03F4C2EB2CD960B1990A56525AC9011

SIM-204-archives.json
06751C15ABA9B6E197D18F019268F2EF4E1E1D07A62342B8E827A29F70A68C6B
```

结论：Archives 关联取证门槛通过，同时保留结果文件 Event ID 11 缺口；该缺口不是
结果文件未创建的证据，也不能用 runtime Ground Truth 替被测智能体补证据。
