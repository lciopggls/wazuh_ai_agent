# 报告评分智能体：当前项目状态

> 更新日期：2026-08-29
> 当前分支：`codex/report-scoring-case-preparation`
> 本轮起点提交：`718db3a`
> 当前阶段：功能验收与代码交付均完成，远程 `master` 已包含本轮成果

本文档是报告评分子项目的当前状态事实源。当前产品合同见
[`11_FIXED_BENCHMARK_SCORING_REQUIREMENTS.md`](./11_FIXED_BENCHMARK_SCORING_REQUIREMENTS.md)；新主机准备
新攻击案例的操作合同见
[`12_NEW_HOST_NEW_ATTACK_TEST_FLOW.md`](./12_NEW_HOST_NEW_ATTACK_TEST_FLOW.md)。

## 1. 当前结论

- 固定案例报告评分的两个入口、评分结果展示、历史记录和对比能力均已实现。
- 用户已通过当前测试环境连续执行溯源、报告登记和评分，并于 2026-08-29 确认：目前功能完全
  符合要求，运行效果良好，暂未发现其他 bug。
- AI 对话、报告评分页面和侧边栏之间切换时，正在运行的溯源不会因组件卸载而中断。
- 正在评分的报告同时受浏览器本地状态和服务端 `running` 状态保护，页面切换后不会恢复可点击；
  评分页面只轮询运行中的报告，并在完成后刷新最终状态。
- 当前没有待实现的产品功能、待修复的已知缺陷或待完成的本轮交付步骤。

“功能验收通过”只描述当前产品合同和已执行的手工/自动化验证，不代表所有本机仿真材料、历史报告
和评分样本都属于代码交付内容，也不把模型输出质量差异解释为产品 bug。

## 2. 当前业务合同

报告评分只评价已经生成的攻击溯源报告。评分所需案例和标准答案必须在测试开始前保存在本机，并
通过案例注册表完整性校验。测试阶段只有两个入口：

1. **AI 对话入口**：测试员向溯源智能体发送事件 JSON。报告完成后，可只保存为本地 Markdown，
   也可选择本地已有案例和实际被测智能体后保存并登记评分。
2. **本机报告入口**：测试员上传已有报告，选择本地已有案例和实际被测智能体后直接登记评分。

普通测试过程不会创建案例、生成标准答案、冻结 Archives 或发布案例。本机报告入口不要求上传
`anchor.json`；Thread ID、Run ID 和备注仅为可选审计信息。

## 3. 已完成能力

### 3.1 后端与评分

- LangGraph `report_scoring_agent`、模型调用和六维结构化评分。
- Studio 可提交 Human Input，并查看最终状态、AIMessage 和结构化分数。
- 六维稳定字段、正式中文名称和权重由后端统一映射维护；当前提示词版本为
  `report-scoring-v3.0-4`。
- 案例注册表在计算文本哈希前统一 CRLF/LF，SIM-204～SIM-206 的跨平台标准 SHA256 为
  `58606b7a13078cbb4e95504e747596c0851771fad26c49b7d120df5cc977e7a2`。
- 服务端字段校验、总分重算、负向行为规则和失败状态记录。
- 本地案例注册表、评分上下文加载和标准版本校验。
- 报告、评分 attempt 和结果的文件持久化、幂等登记和显式重评分。
- 报告列表、评分详情、评分历史和多智能体对比。
- 本地 Markdown 的空内容、1 MiB 上限和同名防覆盖边界。

### 3.2 前端与交互稳定性

- AI 对话报告支持“只保存”和“保存并登记评分”，并持续显示实际保存路径和 `report_id`。
- 登记失败不会抹掉已经成功保存的本地报告，错误反馈可持续查看。
- 本机上传成功显示报告 ID 和存储位置，并清空真实文件选择。
- 生产聊天、测试聊天和评分页面在首次访问后保持挂载，导航只改变可见性。
- `Reporter_Node` 的最终攻击溯源报告可正确显示保存与评分操作；普通中间消息不会误显示。
- 报告操作状态按“智能体 + Thread ID + 消息序号”隔离，不会在不同会话之间串状态。
- 评分按钮同时检查本地提交状态和服务端运行状态，防止切换页面后重复调用模型。
- 评分页面定时刷新仍在运行的报告，完成后自动同步详情、历史和对比数据。
- `VITE_ENABLE_TEST_MODULE` 和 `VITE_ENABLE_REPORT_SCORING` 两层功能开关继续生效。

### 3.3 已关闭的旧能力

以下旧需求不再出现在普通产品路径：

- 从 AI Human Input 提取、预览和匹配锚点；
- 本机报告同时上传 `anchor.json`；
- 私有案例草稿、invalid、audit、staging 和动态发布；
- 在线 Archives 查询、证据冻结和答案编辑；
- Studio inbox 报告导入入口；
- `CasePreparationPanel` 及相关 API、模型和专属测试。

## 4. 固定案例与本机数据边界

- Git 跟踪并随项目交付的固定案例为 SIM-204～SIM-206。
- 本机另外安装的 SIM-207～SIM-209 是受控测试环境数据，不因代码提交自动进入远程仓库。
- SIM-209 已在本机完成 Archives 证据冻结、正式 Ground Truth、expected report、泄漏复核、catalog
  安装和就绪检查；随后按精确 RUN 边界完成 cleanup，并由操作员确认目标虚拟机已关闭。
- SIM-209 cleanup 删除的是目标机当前 RUN 的活动目录，保留 `last_run.json`；已冻结的 Indexer
  历史证据和开发机案例材料不受影响。
- 本机连续溯源已证明 Dashboard 浏览器会话过期不影响后端通过独立 API/Indexer 凭据查询证据；
  报告中的日志截断应作为证据覆盖限制记录，而不是认证故障。

以下内容继续保留在本地但不纳入本轮提交：

- `attack_simulations/` 下的仿真包、Archives、manifest、答案、报告和清理记录；
- `report_scoring_data/catalog/cases/SIM-207`～`SIM-209`；
- `report_scoring_data/runtime/` 中的登记、attempt、结果和历史；
- `src/knowledge_graph/input/` 中的本机报告；
- Word 文档、测试临时目录、stash 和其他用户工作树内容。

## 5. 验证状态

本轮界面修复已完成用户手工验证，并于提交前完成以下自动化复跑：

- 前端报告评分 Node 测试：`11 passed`；
- 前端跨导航保持挂载测试：`2 passed`；
- `npm run type-check`：通过；
- `npm run build`：通过，仅保留既有 Browserslist 过期和大 chunk 警告；
- 报告评分、Server API 和 demo agent 后端专项：`161 passed, 1 skipped, 1 warning`；
- 完整 `uv run pytest`：`212 passed, 1 skipped, 1 failed, 2 warnings`。

完整测试的唯一失败仍是既有的 `tests/test_indexer_agent.py::test_indexer_agent`：真实模型返回了语义
正确但类型不同的工具参数，并使用了不同但等价的最终措辞，strict 逐轨迹比较因此失败。该结果与
本轮报告评分前端修复无关，必须单独披露，不能写成全仓全部通过。

整合 `origin/master@9656aa5` 后再次验证：

- 两组前端测试仍为 `11 passed` 和 `2 passed`，类型检查、生产构建均通过；
- 报告评分、Server API 和 demo agent 集成为 `157 passed, 1 skipped, 2 deselected`；
- 完整 pytest 为 `208 passed, 1 skipped, 1 failed, 2 deselected, 2 warnings`；
- 两项 deselected 是远程新增/既有测试对“默认目录精确只有 SIM-204～SIM-206/207”的断言；本机
  额外保留 SIM-207～SIM-209，因此另行用案例注册表实测确认 SIM-204～SIM-209 全部可加载，不修改
  远程测试代码；
- 唯一 failure 仍为上述 `test_indexer_agent` 模型 strict 轨迹波动。

推送前再次同步发现 `origin/master` 已前进到 `e7a28cf`。该提交补充知识图谱前端入口及其启动说明，
已在不覆盖双方实现的前提下自动整合：远程的 `attack_pattern`/`knowledge_graph` 入口与本分支的聊天、
评分页面持久挂载逻辑同时保留。整合后的两组前端测试再次为 `11 passed` 和 `2 passed`，类型检查、
生产构建均通过；构建只保留既有 Browserslist 过期和大 chunk 警告。

## 6. Git 交付与集成边界

- 使用显式路径白名单暂存，不执行 `git add .`。
- 本轮提交包含前端稳定性修复、对应前端测试、必要脚本配置和正式项目文档。
- 仅因本机 SIM-208/209 案例存在而修改的后端测试断言不纳入提交。
- 不删除、覆盖或暂存上述本机数据和无关工作树内容。
- 整合 `origin/master` 时保留远程新增的事件响应、知识图谱和其他功能，同时保留本分支已经交付的
  固定基准评分代码、需求文档和测试。
- 功能分支与远程 `master` 已于 2026-08-29 普通快进到已验证的整合提交 `43c06da`；全程未强推，
  未覆盖远程代码，也未把本机排除数据纳入提交。

## 7. 下一步

本轮任务已完成，不再继续扩展产品功能。后续仅在出现新需求或新缺陷时另开任务；案例共享、历史
数据清理和新的攻击测试仍按独立边界处理。
