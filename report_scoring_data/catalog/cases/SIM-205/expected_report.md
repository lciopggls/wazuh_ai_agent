# SIM-205 评分侧预期报告

> 本文件仅供评分，不得提供给被测智能体。

## 核心事实

报告应从当前 RUN 的合格 Wazuh alert 出发，识别 `reg.exe add` 向 RUN 专属 HKCU
路径写入 Base64-like 字符串，并进一步找到后续 `reg.exe query`。原设计期预期的 RUN
专属 Event ID 13 在本次正式 RUN 中不可见，因此不作为被测报告必需证据。

## 关键时间线

1. trigger 启动 PowerShell。
2. PowerShell启动 `reg.exe add` 写入 RUN 专属值。
3. 当前可见遥测没有 RUN 专属 RegistryValueSet Event ID 13，不能把无关 BAM 事件
   当成直接写入证明。
4. PowerShell启动第二个 `reg.exe` 查询该值。
5. manifest 在评分侧记录客观测量结果，但不得补充到智能体可见证据中。

## 关键因果判断

- `reg.exe add` 是写入行为，`reg.exe query` 只是查询。
- Base64-like 字符串被存储，不等于被解码或执行。
- 普通 RUN 专属 HKCU 测试键不能被写成登录持久化或系统策略修改。

## MITRE

- 主要技术：T1112 / Modify Registry。
- 辅助技术：T1027 / Obfuscated Files or Information。

MITRE 基础表达按 v3.0 的 `0 / 5 / 15` 三级规则执行，并逐个检查报告中的攻击
时间线项目。

## 负面事实

Ground Truth 明确不存在解码执行、启动项、系统策略、安全控制、网络或凭据操作。
未提及不扣分；明确正确说明且有调查依据时按 v3.0 加分。

## 降级遥测评分边界

九份报告统一按 `SIM-205-degraded-telemetry-scoring-boundary.md` 评分。缺失的 RUN 专属
Event ID 13 不进入召回分母，也不因未提及而扣分；如果报告声称实际找到了该事件，
则按事实错误处理。其余维度和错误仍严格执行 v3.0，不预设或人为抬高分数。
