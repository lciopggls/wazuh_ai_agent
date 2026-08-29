# 新主机新攻击案例：材料准备、溯源与评分测试流程

> 更新日期：2026-08-28
>
> 适用对象：在新主机上设计并执行新攻击案例的测试人员、案例设计人员和辅助 AI 工具
>
> 适用范围：新攻击案例的本地答案准备、AI 溯源报告保存、报告登记与评分
>
> 不包含：在产品页面中新建案例、自动生成 Ground Truth、恢复动态案例发布功能
>
> 当前结论：这是新主机每个新案例都要执行的文件准备流程；不需要继续增加前后端代码

## 1. 目的与关键定义

本文说明一台没有本机历史报告和评分记录的新主机，如何从零完成一个新攻击案例，并把它整理成
可以被当前评分系统读取的本地固定案例。

本文所说的“测试前准备”不是断网操作，也不要求把文件送回原开发主机。它表示：

- 答案材料由新主机上的案例设计人员或其辅助 AI 工具，在普通测试页面之外保存；
- 正式被测智能体开始性能测试前，本地案例目录已经完整、通过校验并启用；
- 普通 AI 对话和报告评分页面只消费这个案例，不负责制作答案。

新主机可以使用 AI 工具整理、填写、保存文件和计算哈希，但最终答案必须来自攻击脚本、真实执行
结果和 Wazuh 证据，不能来自被测智能体生成的溯源报告。

## 2. 新主机一次性系统启动与就绪检查

本节只在新主机首次克隆代码或环境重建后执行。`.env`、模型密钥和 Wazuh 凭据不会随 Git 提交，
必须由新主机操作人员根据实际环境配置，不能从其他测试主机复制包含密钥的文件。

### 2.1 后端依赖和环境

在仓库根目录执行：

```powershell
uv sync
Copy-Item .env.example .env
```

随后编辑根目录 `.env`，配置该主机实际可用的模型、Wazuh Server、Wazuh Indexer 和其他必需
凭据。不要把 `.env`、令牌或密码提交到 Git。

### 2.2 前端依赖和评分功能开关

```powershell
Set-Location frontend
corepack enable
pnpm install
Copy-Item .env.example .env.development
```

在 `frontend/.env.development` 中设置：

```dotenv
VITE_ENABLE_TEST_MODULE="true"
VITE_ENABLE_REPORT_SCORING="true"
```

同时按新主机实际地址填写 Wazuh 相关前端变量。功能开关在前端启动时读取；修改后必须重启前端。

### 2.3 启动三个本地服务

分别打开三个终端：

```powershell
# 终端 1：仓库根目录，LangGraph 智能体服务，默认端口 2024
$env:PYTHONUTF8="1"
uv run langgraph dev
```

```powershell
# 终端 2：仓库根目录，AI 对话保存和报告评分 API，端口 8001
$env:PYTHONUTF8="1"
uv run python -m src.service.memory
```

```powershell
# 终端 3：frontend 目录，前端，默认端口 8112
pnpm dev
```

报告评分 API 在启动时一次性加载本地案例注册表。新增或修改正式案例后，至少需要重启端口 8001
的服务；修改前端功能开关后需要重启端口 8112 的服务。

`PYTHONUTF8=1` 用于避免中文 Windows 的 GBK 终端在 LangGraph 输出 Unicode 字符时发生
`UnicodeEncodeError`。该环境变量只需在对应终端进程中设置，不需要写入或提交密钥文件。

### 2.4 开始测试前的就绪门

在 PowerShell 中检查：

```powershell
Invoke-RestMethod http://127.0.0.1:8001/api/report-scoring/test-cases
Invoke-RestMethod http://127.0.0.1:8001/api/report-scoring/agents
```

必须同时满足：

- `test-cases` 返回预期的已启用案例，而不是 503；
- `agents` 返回可选被测智能体；
- 浏览器打开 `http://127.0.0.1:8112` 后能看到测试模块和报告评分入口；
- AI 对话能够连接端口 2024 的 LangGraph 服务；
- 新主机没有历史 `runtime/reports` 或 `scoring_attempts` 不影响启动，首次登记时由后端自动建目录。

如果报告评分 API 返回 503，说明案例目录、manifest、哈希或评分标准加载失败。应先查看端口 8001
终端中的 `Report scoring subsystem is unavailable` 日志并修复案例文件，不能跳过校验继续测试。

## 3. 三个角色必须分开

### 3.1 案例设计人员或案例准备 AI

可以查看攻击脚本、运行记录、Wazuh Alerts/Archives 原始证据以及全部评分侧答案，负责保存
案例材料、补齐实际值、计算哈希并执行完整性检查。

### 3.2 被测智能体

只能接收 `input_message.txt` 中的攻击溯源请求和事件 JSON，并通过正常工具查询 Wazuh。不得看到：

- `ground_truth.json`；
- `archives_evidence.md` 或提前导出的 Archives 答案；
- `expected_report.md`；
- 其他智能体的报告、State、查询记录或评分结果。

### 3.3 评分智能体

报告登记后，评分智能体读取正式案例目录中的私有答案和被测报告，完成六维评分。评分智能体不负责
修正或补造案例答案。

## 4. 新主机需要保存的目录

每个新攻击案例先取得一个未使用的三位案例号，例如 `SIM-208`。若多个新主机并行准备案例，必须
先统一分配案例号，避免以后合并时发生目录和 ID 冲突。每次真实执行还必须生成唯一 RUN ID。

建议在案例准备阶段使用以下目录：

```text
attack_simulations/<round>/SIM-208/
├── runtime/
│   ├── README_OPERATOR.md
│   ├── preflight.ps1
│   ├── simulation.ps1
│   ├── trigger.bat
│   ├── cleanup.ps1
│   ├── runtime-manifest.json
│   └── cleanup-result.md
└── scoring/
    ├── design_card.md
    ├── ground_truth.draft.json
    ├── telemetry_expectations.md
    ├── expected_report.template.md
    ├── anchor.json
    ├── input_message.txt
    ├── archives-query.json
    ├── archives-probes.json
    ├── archives-raw.json
    ├── archives_evidence.md
    ├── ground_truth.json
    ├── expected_report.md
    └── leakage_review.md
```

以上是案例设计、复核和复现实验资料。评分系统真正读取的是后续安装到
`report_scoring_data/catalog/cases/SIM-208/` 的正式文件子集。

目录分成两类：`attack_simulations/` 保存可复现的测试资料和原始证据，`catalog/cases/` 只保存
评分运行必需的正式答案。前者不会因为“提交产品代码”而自动进入 Git；需要跨主机共享时，由案例
负责人另行确认哪些证据可以提交或传输。

## 5. 阶段 A：设计攻击脚本时先保存计划答案

此阶段尚未执行攻击，所以所有内容只能标记为“计划”“预期”或“禁止”，不能写成已经发生。

### A1. `runtime/README_OPERATOR.md`

写清：

- 测试目的和授权环境；
- 适用的虚拟机、Wazuh Agent 和操作系统；
- 前置条件、需要的权限和时间同步要求；
- `preflight -> simulation -> evidence collection -> cleanup` 的顺序；
- 失败时的停止条件；
- 哪些动作可能改变系统，怎样恢复。

### A2. `runtime/preflight.ps1`

只做执行前检查，例如：

- 当前主机和用户是否正确；
- 测试目录是否可写；
- Wazuh Agent、Sysmon 和必要服务是否正常；
- 当前时间和时区是否可靠；
- 目标文件、注册表项、计划任务或进程是否存在同名旧残留；
- 攻击所需命令和工具是否存在。

Preflight 失败必须停止，不能继续执行并把不完整运行做成正式案例。

### A3. `runtime/simulation.ps1`、`trigger.bat` 和 `cleanup.ps1`

攻击脚本至少应做到：

- 接收或生成唯一 RUN ID；
- 把关键开始时间和结束时间记录为 UTC；
- 对重要子步骤记录成功、失败、退出码和输出文件；
- 所有新建对象尽量带 RUN ID，便于从 Wazuh 中关联；
- 不执行设计范围之外的动作；
- Cleanup 只删除本次 RUN 明确创建的对象。

### A4. `scoring/design_card.md`

这是攻击执行前最重要的计划答案。至少记录：

- 案例 ID、场景名称和测试目的；
- 计划验证的 MITRE ATT&CK 技术；
- 将执行的每一个行为；
- 计划的父子进程链、命令行和对象路径；
- 预期创建、修改和读取的文件、注册表、进程、网络或其他产物；
- 明确不会执行的行为，例如不下载载荷、不建立持久化、不访问凭据；
- 预期触发的 Wazuh 规则、最低 level 和候选锚点；
- 预期出现的 Sysmon Event ID 和关键字段；
- Archives 关联字段，例如 RUN ID、PID、ProcessGuid、命令行和路径；
- 可能存在的遥测缺口；
- 清理范围和验收条件。

### A5. `scoring/ground_truth.draft.json`

该文件保存“计划答案草稿”，不得直接复制为最终答案。建议至少包含：

```json
{
  "scenario_id": "SIM-208",
  "status": "planned_not_executed",
  "planned_behaviors": [],
  "planned_process_chain": [],
  "expected_artifacts": [],
  "explicit_non_actions": [],
  "candidate_wazuh_rule": {},
  "expected_sysmon_event_ids": [],
  "correlation_requirements": [],
  "possible_telemetry_gaps": [],
  "cleanup_scope": []
}
```

设计阶段的辅助 AI 可以根据最终脚本提取这些内容，但必须由操作人员确认其与脚本一致。

### A6. `scoring/telemetry_expectations.md`

记录攻击前对遥测的预期：

- 应该看到什么；
- 需要用什么索引、时间窗和关键词查询；
- 哪些字段能够建立父子关系和因果关系；
- 哪些行为可能只能由运行结果证明，不能由 Wazuh 证明；
- 如果没有结果，应如何区分“没有发生”和“没有采集到”。

### A7. `scoring/expected_report.template.md`

只写报告应覆盖的章节和待填项，例如核心事实、时间线、进程链、MITRE、负面事实和遥测限制。
此时不能填写尚未观察到的实际时间、PID、ProcessGuid、文档 ID 或结论。

### 阶段 A 通过条件

- 脚本、安全边界、清理和计划答案互相一致；
- 没有把计划行为写成已执行事实；
- 已明确哪些事实必须在攻击后由 Wazuh 或运行结果确认；
- 私有答案目录不会被提供给被测智能体。

任一条件不满足都不得执行正式攻击。

## 6. 阶段 B：执行攻击并保存客观运行记录

攻击执行过程本身按现有授权环境正常进行。本节不展开攻击命令，只要求执行者严格保存本次 RUN
的客观结果。

建议顺序：

1. 运行 `preflight.ps1` 并保存结果；
2. 生成唯一 RUN ID，记录主机、Wazuh Agent、操作人和 UTC 开始时间；
3. 执行 `simulation.ps1` 或 `trigger.bat`；
4. 保存每个关键步骤的退出码、stdout、stderr 和产物哈希；
5. 记录 UTC 结束时间；
6. 在清理前完成 Wazuh 证据采集，并把 runtime manifest 和必要产物信息复制到开发机；
7. 完成阶段 C、D 的答案冻结和案例就绪检查后，再执行 `cleanup.ps1`，保存
   `cleanup-result.md`。如确需提前清理，必须由操作人员明确确认已经不再需要目标机活动产物。

`runtime-manifest.json` 至少记录：

```text
case_id
run_id
computer_name
wazuh_agent_id / wazuh_agent_name
operator
start_utc / end_utc
script_sha256
重要子步骤及退出码
实际创建的对象及其哈希
运行整体状态：completed / failed / partial
```

只有 `completed` 且关键行为有客观证据的 RUN 才能继续制作正式案例。`failed` 或 `partial` 运行应
保留为故障材料，但不得伪装成正式成功案例。

## 7. 阶段 C：攻击后补齐实际答案和 Wazuh 证据

### C1. 保存 `anchor.json`

从 `wazuh-alerts-*` 选择一条确实属于本次 RUN 的完整事件 JSON。不能只因为 level 高就选中；至少
核对 Wazuh Agent、事件时间、规则、RUN ID、PID、命令行、路径或其他关联字段。保存内容必须包括
`_index`、`_id` 和完整 `_source`，不要手工删减字段或只保存 `_source`。

### C2. 保存 `input_message.txt`

该文件必须是以后原样发送给被测智能体的内容：

```text
对这条日志进行攻击溯源：

<anchor.json 的完整 JSON>
```

不得附加 Ground Truth、预期进程链、Archives 证据、标准答案提示或评分要求。

### C3. 保存 Archives 查询和原始结果

建议分别保存：

- `archives-query.json`：索引、UTC 时间窗、过滤条件、排序、分页和返回上限；
- `archives-probes.json`：按 RUN ID、PID、ProcessGuid、命令行、文件路径等做过的补充查询；
- `archives-raw.json`：完整原始命中结果和总数。

查询至少覆盖锚点进程的父进程和子进程、脚本计划的副作用，以及能证明顺序和因果关系的时间、
ProcessGuid、ParentProcessGuid、PID 和路径。分页、结果截断或查询失败必须如实记录。没有返回结果
可能表示未采集、时间窗错误、字段不匹配或查询不完整，不能自动解释成行为没有发生。

### C4. 编写 `archives_evidence.md`

把原始查询整理成人可读的评分侧遥测边界，至少包含：

- RUN ID、Agent 和 UTC 查询时间窗；
- 锚点的 index、document ID、规则和事件时间；
- 已确认可见的关键证据及文档引用；
- 已查询但没有结果的项目；
- 未查询、无法查询、结果被截断或采集缺失的项目；
- 哪些结论只能由 runtime manifest 证明，不能声称被 Wazuh 证明；
- 时间字段、父子关系和因果关系的解释边界。

如遥测明显退化，可增加 `degraded_telemetry_boundary.md`，并在正式 manifest 的
`telemetry_boundary_paths` 中同时列出。

### C5. 把计划答案修订为正式 `ground_truth.json`

正式 Ground Truth 只保留真实发生或经过复核的内容。至少确认：

- `scenario_id` 与目录名一致；
- `visibility` 为 `scoring_only`；
- `must_not_be_provided_to_tested_agent` 为 `true`；
- 实际执行成功的行为；
- 实际进程链、时间、PID、ProcessGuid 和证据引用；
- 实际产生的文件、注册表、进程、网络或其他产物；
- 明确没有执行的行为和允许评分使用的负向行为目录；
- 正确 MITRE 技术和适用边界；
- 锚点和必要关联条件；
- 已知遥测缺口；
- 失败、未执行或无法确认的计划步骤；
- Cleanup 范围和结果。

信息来源优先级必须保持：

```text
实际攻击脚本和 runtime manifest
        +
冻结的 Wazuh Alerts / Archives 证据
        +
人工复核
        =
正式 Ground Truth
```

不得以被测智能体报告中的主张补充 Ground Truth，也不得为了让报告得高分而修改答案。

### C6. 完成 `expected_report.md`

它不是要求被测报告逐字一致，而是给评分侧提供最小正确事实参考。至少写清正确锚点、关键时间线、
父子进程链、因果关系、MITRE、明确未发生的行为、遥测限制和不得扩大推断的结论。

### C7. 完成 `leakage_review.md`

检查 `input_message.txt` 是否泄露 Ground Truth、Archives 答案、预期进程链、标准报告、明确未发生
行为清单、其他智能体输出或评分线索。同时确认正式答案的依据不是被测智能体报告。

### 阶段 C 通过条件

- 锚点能与本次 RUN 建立可靠关系；
- Ground Truth 中每个重要事实都有脚本、运行结果或 Wazuh 依据；
- 计划但未成功的行为已删除或明确标记；
- 遥测缺口没有被写成“确认未发生”；
- 输入文件没有答案泄漏；
- 所有 `<...>`、`TODO`、`TBD` 和模板占位符已经清除。

## 8. 阶段 D：安装为评分系统可读取的正式案例

把最终文件复制到：

```text
report_scoring_data/catalog/cases/SIM-208/
├── manifest.json
├── input_message.txt
├── anchor.json
├── ground_truth.json
├── archives_evidence.md
├── expected_report.md
└── degraded_telemetry_boundary.md   # 仅在实际需要时存在
```

攻击脚本、原始 Archives 导出、查询脚本、草稿、清理结果和复核记录继续保存在
`attack_simulations/<round>/SIM-208/`，不必复制进正式案例目录。

### D1. `manifest.json` 最小结构

```json
{
  "schema_version": 1,
  "test_case_id": "SIM-208",
  "display_name": "SIM-208 <场景名称>",
  "enabled": true,
  "scoring_standard_version": "v3.0",
  "scoring_standard_path": "standards/scoring_v3_0.md",
  "input_path": "input_message.txt",
  "anchor_path": "anchor.json",
  "ground_truth_path": "ground_truth.json",
  "telemetry_boundary_paths": ["archives_evidence.md"],
  "expected_report_path": "expected_report.md",
  "input_sha256": "<input_message.txt 的 SHA256>",
  "standard_sha256": "<scoring_v3_0.md 的 SHA256>"
}
```

如存在额外遥测边界，应把文件一起加入 `telemetry_boundary_paths`。

### D2. 计算哈希

新主机的辅助 AI 工具可以执行：

```powershell
Get-FileHash -Algorithm SHA256 `
  report_scoring_data\catalog\cases\SIM-208\input_message.txt

Get-FileHash -Algorithm SHA256 `
  report_scoring_data\catalog\standards\scoring_v3_0.md
```

将结果填入 manifest。不要手工猜测或复用其他案例哈希。

### D3. 完整性检查

至少检查：

- 目录名、manifest `test_case_id` 和 Ground Truth `scenario_id` 完全一致；
- 全部文本为 UTF-8，JSON 能正常解析且顶层是对象；
- manifest 只使用案例目录或 catalog 内的相对安全路径；
- `telemetry_boundary_paths` 至少包含一个文件；
- 输入和评分标准哈希正确；
- Ground Truth 的两个私有可见性字段正确；
- 不存在占位符和空答案；
- `enabled` 只在全部检查通过后设为 `true`。

### D4. 加载案例

完成正式目录后重启后端。评分页面案例列表应出现 `SIM-208`，或
`GET /api/report-scoring/test-cases` 返回 `SIM-208`。加载失败时应修复具体文件错误，不得绕过校验，
也不得把新报告临时绑定到旧 SIM 案例。

### D5. Cleanup、目标机关机与后续测试

标准 cleanup 只允许删除 runtime manifest 明确记录、且位于预定安全根目录中的本次 RUN 产物。
它不应删除：

- 已写入 Wazuh Indexer 的历史 Alerts/Archives；
- 已复制到开发机的 anchor、input、runtime manifest、Archives 冻结证据和正式答案；
- 已保存或登记的报告；
- 评分 attempts、结果和历史。

因此，在阶段 C、D 完整通过并保存 cleanup 输出后，可以关闭目标 Windows 虚拟机，再进行基于
历史 Wazuh 数据的攻击溯源和本地报告评分。此时仍必须保证 Wazuh Manager/Indexer 可访问；本地
LangGraph、评分 API 和前端则在相应测试时启动。

Cleanup 仍可能影响观察内容：它会删除目标机活动产物，并可能产生比攻击 RUN 更晚的进程或文件
删除遥测。不要在同一案例的溯源任务正在运行时执行 cleanup；应记录 cleanup 时间，并让后续查询
使用冻结输入和覆盖攻击 RUN 的受控时间窗，避免把清理动作误并入攻击链。若被测流程还需要直接
检查目标机文件系统或现场状态，则必须先完成该检查，不能以 Indexer 历史数据能够保留为由提前
清理或关机。

## 9. 阶段 E：被测智能体溯源、报告保存和登记

正式性能测试时，向被测智能体原样发送 `input_message.txt`。溯源智能体按正常流程查询 Wazuh 并
生成最终报告；除此之外不向它提供答案材料。

### 推荐顺序

1. 先完成并加载正式 `SIM-208` 案例；
2. 新建独立 AI 对话线程；
3. 原样发送 `input_message.txt`；
4. 等待完整最终报告；
5. 选择 `SIM-208` 和实际被测智能体；
6. 点击一次“保存并登记评分”；
7. 登记成功后点击一次“首次评分”。

### 如果报告已经在案例安装前生成

不需要重跑攻击：

1. 先点击“保存报告”；
2. 报告自动保存到 `src/knowledge_graph/input/attack_trace_report_*.md`；
3. 完成阶段 C、D 并重启后端；
4. 在“上传本机报告”中选择刚保存的 Markdown；
5. 选择 `SIM-208` 和实际被测智能体后登记评分。

报告保存目录和评分运行目录由后端自动创建。新主机没有历史记录不会影响保存：

```text
src/knowledge_graph/input/                         AI 报告原始 Markdown
report_scoring_data/runtime/reports/rpt_*/         登记后的报告副本和 metadata
report_scoring_data/runtime/scoring_attempts/...   本机评分 attempt、结果和历史
```

## 10. 同一案例测试多个智能体时的规则

- 所有智能体必须使用完全相同的 `input_message.txt` 和正式案例版本；
- 每个智能体使用独立 Thread ID，重复轮次也使用独立线程；
- 登记时选择实际生成该报告的智能体；
- 不得把前一个智能体的报告或查询结果提供给后一个智能体；
- 正式评分开始后不要修改 Ground Truth、遥测边界、输入或评分标准；
- 如发现答案存在实质错误，应停止当前批次，修复后使用新的案例 ID 或明确的新版本重新测试，不能
  静默修改答案后继续混用旧分数。

## 11. 新主机每个新案例的必交付清单

### 攻击设计和复现材料

- [ ] 唯一 `SIM-XXX` 和唯一 RUN ID；
- [ ] `README_OPERATOR.md`；
- [ ] `preflight.ps1`；
- [ ] 攻击、触发和清理脚本；
- [ ] `design_card.md`；
- [ ] `ground_truth.draft.json`；
- [ ] `telemetry_expectations.md`；
- [ ] `expected_report.template.md`。

### 攻击后的客观材料

- [ ] `runtime-manifest.json`；
- [ ] 命令输出、退出码和重要产物哈希；
- [ ] `cleanup-result.md`；
- [ ] 完整 `anchor.json`；
- [ ] `archives-query.json`；
- [ ] `archives-probes.json`；
- [ ] `archives-raw.json`。

### 最终评分答案

- [ ] `input_message.txt`；
- [ ] `ground_truth.json`；
- [ ] `archives_evidence.md`；
- [ ] `expected_report.md`；
- [ ] 必要时的 `degraded_telemetry_boundary.md`；
- [ ] `leakage_review.md`；
- [ ] `manifest.json` 和正确哈希；
- [ ] 后端重启后案例列表可见。

### 被测输出和评分记录

- [ ] 被测智能体最终原始报告；
- [ ] 正确的案例和智能体登记关系；
- [ ] `report_id`；
- [ ] 评分成功或明确失败的 attempt；
- [ ] 多轮测试时，每轮 Thread ID、报告和评分记录可区分。

## 12. 新主机辅助 AI 工具的允许与禁止事项

### 允许

- 阅读攻击脚本并生成计划答案草稿；
- 根据操作员提供的真实运行记录和 Wazuh 原始证据补齐实际值；
- 创建目录、保存 Markdown/JSON、计算哈希和检查占位符；
- 比对脚本计划、runtime manifest 和 Wazuh 证据的不一致；
- 运行只读格式、路径、哈希和案例加载检查；
- 输出待人工确认的问题清单。

### 禁止

- 把计划行为直接写成已执行事实；
- 用被测智能体报告生成或修正 Ground Truth；
- 在没有证据时补造 PID、ProcessGuid、时间、文档 ID 或行为；
- 把未观察到写成确认未发生；
- 把私有答案提供给被测智能体；
- 自动执行真实攻击、清理或评分，除非操作人员在相应阶段明确授权；
- 为了让案例通过校验而放宽代码校验或修改评分逻辑；
- 将新报告错误绑定到 SIM-204～SIM-206 等旧案例。

## 13. 交给新主机辅助 AI 的分阶段任务模板

不要把两个阶段合并成一个任务。攻击前的 AI 任务只允许生成计划草稿；完成真实攻击并提供客观
材料后，才能下发攻击后任务。

### 13.1 攻击前任务模板

```text
你是本次 Wazuh 攻击测试的案例准备 AI，不是被测攻击溯源智能体。

案例 ID：SIM-XXX
工作目录：attack_simulations/<round>/SIM-XXX/

请阅读已经确认的攻击脚本、安全边界和清理脚本，只完成攻击前材料准备：
1. 创建或更新 runtime/README_OPERATOR.md；
2. 检查 preflight、simulation、trigger、cleanup 的顺序和边界；
3. 创建 scoring/design_card.md；
4. 创建 scoring/ground_truth.draft.json，所有行为必须标记为 planned；
5. 创建 scoring/telemetry_expectations.md；
6. 创建 scoring/expected_report.template.md；
7. 输出仍需操作人员确认的问题。

禁止：
- 执行攻击或清理；
- 声称计划行为已经发生；
- 编造实际时间、PID、ProcessGuid、Wazuh 文档 ID 或查询结果；
- 创建正式 ground_truth.json；
- 运行被测智能体或评分。

完成后停下，等待操作人员执行真实攻击并提供 runtime manifest、Alerts 和 Archives 证据。
```

### 13.2 攻击后任务模板

```text
你是本次 Wazuh 攻击测试的案例准备 AI，不是被测攻击溯源智能体。

案例 ID：SIM-XXX
工作目录：attack_simulations/<round>/SIM-XXX/
正式案例目录：report_scoring_data/catalog/cases/SIM-XXX/

输入材料仅包括：
- 已确认的攻击和清理脚本；
- runtime-manifest.json、退出码、stdout/stderr 和产物哈希；
- 当前 RUN 的完整 wazuh-alerts-* 候选事件；
- 当前 RUN 的 Archives 查询、补充查询和完整原始结果；
- 操作人员对成功、失败、部分执行和清理结果的确认。

请完成：
1. 校验并保存完整 anchor.json；
2. 生成只含攻击溯源指令和完整锚点 JSON 的 input_message.txt；
3. 保存 archives-query.json、archives-probes.json 和 archives-raw.json；
4. 编写 archives_evidence.md，严格区分已确认、未观察到、未采集和查询不完整；
5. 根据脚本、runtime manifest 和 Wazuh 证据，把计划草稿修订为正式 ground_truth.json；
6. 编写 expected_report.md；
7. 完成 leakage_review.md；
8. 把正式文件复制到 catalog/cases/SIM-XXX/；
9. 计算 input 和 scoring_v3_0.md 的 SHA256，生成 manifest.json；
10. 检查 JSON、UTF-8、相对路径、占位符、私有可见性字段和案例 ID 一致性；
11. 给出需要人工最终确认的事实和无法确认的遥测缺口。

必须遵守：
- 不读取、不引用任何被测智能体报告来制作答案；
- 没有证据的内容不得写成事实；
- 计划但未成功的行为必须删除或标记为未执行；
- 不把 Ground Truth、Archives 答案或 expected report 放入 input_message.txt；
- 不修改评分代码、校验规则或旧 SIM 案例；
- 不启动被测智能体、不登记报告、不触发评分。

完成文件和检查报告后停下，等待操作人员人工确认并重启后端加载案例。
```

辅助 AI 可以只参考现有 `SIM-204`～`SIM-206` 的文件结构和字段写法，不得复制其中的事件事实、
哈希、RUN ID、规则、时间、进程链或答案到新案例。

## 14. 最短操作摘要

```text
分配案例号和 RUN ID
  -> 设计脚本并保存计划答案
  -> Preflight
  -> 执行攻击并保存 runtime manifest
  -> 冻结 Alerts 锚点和 Archives 原始证据
  -> 把计划答案修订为实际 Ground Truth
  -> 完成遥测边界、预期报告和泄漏检查
  -> 安装 catalog/cases/SIM-XXX 并重启后端
  -> 经操作人员确认后 cleanup，保存结果；不再需要现场检查时可关闭目标机
  -> 原样发送 input_message.txt 给被测智能体
  -> 保存/登记最终报告
  -> 首次评分、历史和对比
```

本流程通过本地文件约定解决新主机的新案例准备，不增加新的后端或前端代码逻辑。

只有“正式案例文件已安装、完整性校验通过、被测智能体看不到评分侧答案”三个条件同时满足，才算
进入正式性能测试；仅完成攻击或仅拿到一份溯源报告都还不能评分。
