# SIM-206 评分侧预期报告

> 本文件仅供评分，不得提供给被测智能体。

## 核心事实

报告应从当前 RUN 的合格 Wazuh alert 出发，识别 PowerShell在用户 Temp 的
RUN 专属目录创建 `.cmd` 文件，并进一步找到后续 `cmd.exe` 执行和结果文件。

## 关键时间线

1. trigger 启动 PowerShell。
2. PowerShell创建 RUN 专属 Temp 命令文件。
3. PowerShell启动 `cmd.exe` 执行该命令文件。
4. 命令文件写入 ProgramData RUN 专属结果文件。
5. PowerShell启动 `findstr.exe` 查询结果内容。

## 关键因果判断

- FileCreate 告警只证明命令文件被创建，不能单独证明已执行。
- `cmd.exe` 进程和结果文件共同证明命令文件执行完成。
- 当前场景是本地文件创建；不能仅依据规则附带映射确认网络型 T1105。
- 无 RUN ID 的 PowerShell随机策略测试文件不是正式锚点。

## MITRE

- 主要技术：T1059.003 / Windows Command Shell。

MITRE 基础表达按 v3.0 的 `0 / 5 / 15` 三级规则执行，并逐个检查报告中的攻击
时间线项目。

## 负面事实

Ground Truth 明确不存在网络下载、外部载荷、持久化、凭据访问或安全控制修改。
未提及不扣分；明确正确说明且有调查依据时按 v3.0 加分。
