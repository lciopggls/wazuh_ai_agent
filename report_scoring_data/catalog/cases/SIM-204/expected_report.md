# SIM-204 评分侧预期报告

> 本文件仅供评分，不得提供给被测智能体。

## 核心事实

报告应从当前 RUN 的合格 Wazuh alert 出发，识别父 PowerShell 创建带
`-EncodedCommand` 的子 PowerShell，并用 PID/ProcessGuid、父子关系、时间窗和
RUN 专属结果文件完成关联。

## 关键时间线

1. trigger 启动父 PowerShell。
2. 父 PowerShell生成编码命令并创建子 PowerShell。
3. 子 PowerShell执行编码内容并写入 RUN 专属结果文件。
4. 父 PowerShell启动 `findstr.exe` 查询结果内容。

## 关键因果判断

- 子 PowerShell才执行编码命令。
- 编码参数本身不能证明下载、持久化或其他后续行为。
- 结果文件和子进程退出码是完成状态的交叉证据。
- `findstr.exe` 是后续查询，不是编码命令的子行为。

## MITRE

- 主要技术：T1059.001 / PowerShell。

MITRE 基础表达按 v3.0 的 `0 / 5 / 15` 三级规则执行。每个攻击时间线项目必须在
同一项目内表达“时间 + 具体 T 编号 + 对应行为”，才能计入完整覆盖。

## 负面事实

Ground Truth 明确不存在网络下载、外部载荷、持久化、凭据访问或安全控制修改。
未提及不扣分；明确正确说明且有调查依据时按 v3.0 加分。
