# SIM-206 Archives 冻结证据

- Scenario：`SIM-206`
- RUN：`WAZUH-LAB-SIM-206-20260805T164747Z-8613739C`
- Archives index：`wazuh-archives-4.x-2026.08.05`
- 时间窗口：`2026-08-05T16:46:47Z` 至 `2026-08-05T16:52:47Z`
- 取证方式：精确 RUN-ID 查询、ProcessGuid/ParentProcessGuid 关联查询、RUN-specific 字段探针；命中的文档再按精确 `_index`/`_id` 重读。

## 直接 RUN 证据

精确 RUN-ID 查询命中 3 条：

| 行为 | Event ID | 文档 ID |
|---|---:|---|
| RUN 专属 `.cmd` 创建 | 11 | `aWfT0p8BWAEr461gBL_M` |
| `cmd.exe` 执行 RUN 专属 `.cmd` | 1 | `a2fT0p8BWAEr461gBL_M` |
| `findstr.exe` 查询 RUN 结果 | 1 | `bmfT0p8BWAEr461gG7_L` |

Archives 冻结集合共 25 条，Event ID 分布为 `1: 6`、`7: 8`、`11: 3`、`13: 6`、`17: 1`、`26: 1`。其中 25 条保留为审计证据；正式报告应优先围绕上述 3 条直接 RUN 证据和其进程链解释，不得把无关 PowerShell 初始化噪声写成攻击动作。

## 因果边界

- Event ID 11 只证明 RUN 专属 `.cmd` 被创建；Event ID 1 才证明后续 `cmd.exe` 执行和 `findstr.exe` 查询。
- `findstr.exe` 是结果查询动作，不是命令文件本身的执行主体。
- 规则 92213 的本地映射包含 T1105，但本次证据没有网络入口，不能据此声称发生了下载或网络传输。
- 两条 `__PSScriptPolicyTest_*.ps1` 告警已经从正式锚点候选中排除，不得替代本次 RUN 的正式锚点。

原始文档、查询和探针见同目录的 `SIM-206-archives.json`、`SIM-206-archives-query.json`、`SIM-206-archives-probes.json`。
