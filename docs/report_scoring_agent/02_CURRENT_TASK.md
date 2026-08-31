# 报告评分智能体：当前任务

> 更新日期：2026-08-31
> 当前分支：`codex/report-scoring-case-preparation`
> 本轮起点提交：`718db3a`
> 当前任务状态：历史评分显示兼容修复已提交并推送，远程 `master` 已包含本轮交付

本文件记录本轮已完成的交付任务及其边界。产品合同见
[`11_FIXED_BENCHMARK_SCORING_REQUIREMENTS.md`](./11_FIXED_BENCHMARK_SCORING_REQUIREMENTS.md)，当前完成状态和
数据边界见 [`00_CURRENT_PROJECT_STATE.md`](./00_CURRENT_PROJECT_STATE.md)。

## 1. 已确认结论

- 2026-08-31 发现的历史评分不显示问题不是结果未持久化，而是换行规范化后旧评分指纹被判为过期。
- SIM-209 当前答案已通过攻击脚本、运行清单、冻结 Archives 和 Wazuh 实时查询复核，可作为最终版。
- 11 个基于旧 SIM-209 答案上下文的评分 attempt 已按用户授权删除；9 份报告和证据均保留，随后
  已按最终答案完成 `9/9` 重新评分。
- SIM-205、SIM-206、SIM-208 的既有评分仅为换行指纹差异，已通过显式兼容指纹恢复，不删除。
- SIM-207 评分案例目录已按用户明确授权删除；2 份历史 runtime 报告、评分历史、仿真目录和本地
  原始报告仍保留，不再把 SIM-207 暴露为可选评分案例。
- SIM-204 已完成异常文件精确清理：保留 9 份有效离线报告/State/evaluation；runtime 保留 6 份
  互不重复的有效登记报告和 2 个当前成功评分，删除异常/重复报告、失败或误登记 attempt 后不再
  存在重复 SHA。清理当时待测试员补跑 attack 2 份、plus 1 份报告，并补齐其余评分。
- SIM-204 缺项随后已补齐；当前 attack、simple、plus 各 3 份登记报告，9 份均有当前成功评分。
- 当前 SIM-204、SIM-205、SIM-206、SIM-208、SIM-209 均为三种智能体各 3 份、`9/9` 当前成功
  评分；逐报告总分复算与多智能体对比平均值一致。
- SIM-204 固定答案已由攻击脚本、runtime manifest、冻结证据和 Wazuh 实时查询交叉验证；RUN 专属
  32 条 Archives 与冻结集逐条相同，catalog Ground Truth 可由当前注册表加载并用于正常评分。
- 固定案例双入口、报告保存/登记、首次评分、重评分、详情、历史和对比链路均可用。
- AI 对话生成的报告可以只保存为本地 Markdown，之后在评分页“上传本机报告”，选择 SIM-204 和
  实际智能体后登记评分；该链路不依赖 AI 对话阶段的直接登记，已通过前后端专项测试。
- AI 对话和评分页面切换不会中断正在运行的溯源；评分运行状态不会因导航切换而丢失。
- 当前没有需要继续实现的产品功能。本轮修复已经用户确认并按白名单提交推送；未顺手扩展需求、
  重跑攻击或清理其他历史数据。

## 2. 已完成交付清单

1. 已按显式白名单提交历史评分显示兼容修复，修复提交为 `7759b1b`；
2. 提交前已复跑验证门：报告评分后端全套 `115 passed, 1 deselected, 1 warning`，Black 无需改动，
   Ruff `--fix` 未修改文件，`git diff --cached --check` 通过，暂存清单精确等于白名单；
3. 三个仅适配本机 SIM-208/209 的测试文件改动按既定边界排除，保留为本地未提交修改；
4. 已更新正式项目状态与任务文档；
5. 已推送功能分支，并将远程 `master` 普通快进到本轮交付提交，全程未强推。

## 3. 本轮提交白名单

### 3.1 修复代码、案例清单与测试

- `src/service/report_scoring/api_models.py`；
- `src/service/report_scoring/case_registry.py`；
- `src/service/report_scoring/scoring_service.py`；
- `report_scoring_data/catalog/cases/SIM-204/manifest.json`；
- `report_scoring_data/catalog/cases/SIM-205/manifest.json`；
- `report_scoring_data/catalog/cases/SIM-206/manifest.json`；
- `tests/test_report_scoring_score_repository.py`。

### 3.2 正式项目文档

- `docs/report_scoring_agent/00_CURRENT_PROJECT_STATE.md`；
- `docs/report_scoring_agent/02_CURRENT_TASK.md`；
- `docs/report_scoring_agent/11_FIXED_BENCHMARK_SCORING_REQUIREMENTS.md`。

本轮无远程主分支整合冲突；白名单外文件一律不暂存，不夹带本机运行数据。

## 4. 明确排除项

- `.pytest-tmp/` 和其他临时缓存；
- `attack_simulations/` 全部内容，包括 SIM-209 答案和 cleanup 证据；
- `report_scoring_data/catalog/cases/SIM-208`～`SIM-209`；
- `report_scoring_data/runtime/`；
- `src/knowledge_graph/input/` 中的本机溯源报告；
- Word 文档和其他用户资料；
- `tests/test_report_scoring_api.py`、`tests/test_report_scoring_case_registry.py`、
  `tests/test_report_scoring_validation.py` 中仅适配本机 SIM-208/209 的断言；
- `tests/test_knowledge_graph_template.py`；
- 内容与索引一致、仅工作树元数据呈修改状态的 `.gitignore`；
- 本地运行交接 `13_SIM205_SIM209_NEXT_WINDOW_HANDOFF.md`。

不执行 `git add .`，不删除排除项，也不通过 reset、clean 或广泛 stash 隐藏它们。

## 5. 远程整合事实

首次同步的 `origin/master` 为 `9656aa5`；推送前复核时远端已前进到 `e7a28cf`。当前功能分支起点为
`718db3a`，共同基线为 `d56130c`。
远程主分支在共同基线之后新增了事件响应、前端和知识图谱相关提交，也在合并过程中删除了本功能
分支已有的固定评分需求文档及部分报告评分测试。

`e7a28cf` 新增知识图谱入口和前端启动说明。三方预演及实际整合均无冲突；合并结果同时保留这些
远程新增内容和本分支的聊天/评分导航持久化修复，未改写远程实现。

已验证的整合提交为 `43c06da`。该提交已推送到
`origin/codex/report-scoring-case-preparation` 和 `origin/master`；推送采用普通快进，未使用强推。

本轮修复交付时 `origin/master` 未再前进（仍为本分支已整合的 `cd566b3`），无合并冲突；
功能分支推送后直接普通快进。

整合原则：

- 保留远程主分支新增功能和文件组织；
- 保留本功能分支的固定基准评分合同、代码、文档和测试；
- 保留 `dimensions.py`、前端类型化映射和 `report-scoring-v3.0-4` 提示词版本；
- 保留案例文本换行规范化和与之匹配的 `58606b…` 标准哈希，避免 Windows/Linux 换行差异导致
  固定案例误判损坏；
- 对 `frontend/package.json`、评分 API、页面和聊天组件等重叠文件逐项语义合并；
- 不用整文件单边覆盖代替冲突分析；
- 不让远程知识图谱数据与本地未跟踪溯源报告发生混淆；
- 合并完成后检查冲突标记、暂存清单、提交差异和完整测试结果。

## 6. 验证门

提交前至少满足：

- 两组前端 Node 测试通过；
- `npm run type-check` 通过；
- `npm run build` 通过；
- 报告评分后端专项测试通过；
- 完整 `uv run pytest` 的结果被准确记录；若仍只有既有真实模型 strict 轨迹失败，必须明确披露，
  不能声称全绿；
- `git diff --check` 通过；
- `git diff --cached --name-status` 只包含批准白名单和经复核的冲突解决文件；
- 不包含 `.env`、凭据、真实运行数据、SIM-208～SIM-209 或本机报告。

远程主分支整合后，至少重新运行受冲突影响的前端测试、类型检查、构建和后端报告评分专项；若整合
影响面扩大，则再次运行完整 pytest。

## 7. 完成证据

- 本轮修复提交 `7759b1b` 已推送至功能分支，交付时本地 HEAD 与远程分支一致；
- 远程 `master` 已普通快进到本轮交付提交，包含历史评分兼容修复与文档记录；
- 三个仅适配本机 SIM-208/209 的测试文件改动继续保留为本地未提交修改，未进入提交；
- 除用户于 2026-08-31 明确授权精确删除的 SIM-204 异常/重复材料外，其他本地排除数据仍保留且
  未进入提交；
- 实际测试结果和范围外问题已保留在当前状态文档中，并在最终交付说明中如实披露。
