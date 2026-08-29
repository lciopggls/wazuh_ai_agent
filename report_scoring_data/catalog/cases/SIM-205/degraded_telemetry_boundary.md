# SIM-205 降级遥测统一评分边界

记录日期：2026-08-05  
正式 RUN：`WAZUH-LAB-SIM-205-20260805T130102Z-1963EF3C`

## 决定

用户已接受本次正式 RUN 缺少 RUN 专属 Sysmon Event ID 13 的降级遥测。保留该 RUN，
不重跑；三类智能体各三次调查继续使用同一份完整 alert 锚点和同一段正式输入。

本决定用于保证智能体只按实际可见证据接受评价，而不是保证某一智能体获得特定分数。
除下述证据边界外，`评分标准v3.0.md` 的六维权重、事实错误、重复根因和最终计算规则
全部保持不变。

## 智能体实际可见证据

- 合格锚点：当前 RUN 的完整 `92041 / level 10` Sysmon Event ID 1 alert；
- Archives：可关联的 `explorer → cmd → PowerShell → reg.exe add/reg.exe query`
  Event ID 1 进程链及同一查询边界内的其他可访问遥测；
- 不可用证据：`HKCU\Software\WazuhLab\<RUN_ID>\Data` 对应的 RUN 专属 Event ID 13；
- 两条 BAM Event ID 13 不是本次 RUN 的注册表值写入证据；
- runtime manifest、Ground Truth 和 expected report 仅供评分侧核验，不能补充给被测
  智能体，也不能用于虚构其已召回的证据。

## v3.0 计分应用

1. 关键证据检索与覆盖度：分母排除不可见的 RUN 专属 Event ID 13；仍评价 alert、`reg add`、
   `reg query`、父子进程链及其他实际可访问关键证据的召回与引用准确性。
2. 时间线：不因没有写出 Event ID 13 而扣分；仍评价 add/query 的先后顺序、主体和
   时间关联。
3. 因果判断：可奖励正确区分 `reg add` 写入命令与 `reg query` 查询，以及“存储
   Base64-like 字符串不等于解码或执行”。不得要求智能体用不存在的 Event ID 13
   直接证明写入成功。
4. MITRE：`reg add` 可支持 T1112；Base64-like 内容可作为 T1027 的辅助判断；
   `reg query` 本身不能被写成注册表修改。
5. 负面事实和建议：继续完全按 v3.0 评分，不因本次遥测缺口额外放宽或加分。
6. 虚构证据：报告若声称实际找到 RUN 专属 Event ID 13，按事实错误处理；同一根因
   的扣分仍最多落在两个最相关维度，避免重复处罚。

## 一致性要求

上述口径必须原样应用于 simple、plus、attack 三类智能体的九份独立报告。评分人不得
根据智能体类别改变分母，不得预设最低分，也不得为补偿遥测缺口而放宽无关错误。
