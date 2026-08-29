# 报告评分智能体：当前任务

> 更新日期：2026-08-29
> 当前分支：`codex/report-scoring-case-preparation`
> 本轮起点提交：`718db3a`
> 当前任务状态：功能验收通过，正在执行交付验证、提交和远程主分支合并

本文件只描述当前尚未完成的交付任务。产品合同见
[`11_FIXED_BENCHMARK_SCORING_REQUIREMENTS.md`](./11_FIXED_BENCHMARK_SCORING_REQUIREMENTS.md)，当前完成状态和
数据边界见 [`00_CURRENT_PROJECT_STATE.md`](./00_CURRENT_PROJECT_STATE.md)。

## 1. 已确认结论

- 用户已确认当前功能完全符合要求，运行效果良好，暂未发现其他 bug。
- 固定案例双入口、报告保存/登记、首次评分、重评分、详情、历史和对比链路均可用。
- AI 对话和评分页面切换不会中断正在运行的溯源；评分运行状态不会因导航切换而丢失。
- 当前没有需要继续实现的功能。不得在交付前顺手扩展需求、重跑攻击、清理历史数据或修改固定
  评分合同。

## 2. 当前目标

1. 更新正式项目状态与操作文档；
2. 按显式白名单复核准备提交的代码、测试和文档；
3. 运行前端测试、类型检查、构建、后端专项和完整 pytest；
4. 提交当前功能分支；
5. 把最新 `origin/master` 整合到功能分支，解决冲突并复跑受影响验证；
6. 推送功能分支；
7. 将已包含最新主分支的交付结果合并到远程 `master`，核对远程指针。

## 3. 本轮提交白名单

### 3.1 功能代码与测试

- `frontend/package.json`；
- `frontend/src/api/report_scoring.ts`；
- `frontend/src/views/index/index.vue`；
- `frontend/src/views/index/second_right.vue`；
- `frontend/src/views/index/report_scoring.vue`；
- `frontend/src/views/index/report-scoring/ReportList.vue`；
- `frontend/src/views/index/report-scoring/presentation.ts`；
- `frontend/tests/report-scoring-presentation.test.mjs`；
- `frontend/tests/chat-navigation-persistence.test.mjs`。

### 3.2 正式项目文档

- `docs/report_scoring_agent/00_CURRENT_PROJECT_STATE.md`；
- `docs/report_scoring_agent/02_CURRENT_TASK.md`；
- `docs/report_scoring_agent/12_NEW_HOST_NEW_ATTACK_TEST_FLOW.md`。

只有完成远程主分支整合后，为解决真实合并冲突而必须修改的已跟踪文件，才可以在复核后追加到
白名单。任何追加都必须服务于同时保留两侧既有功能，不能夹带本机运行数据。

## 4. 明确排除项

- `.pytest-tmp/` 和其他临时缓存；
- `attack_simulations/` 全部内容，包括 SIM-209 答案和 cleanup 证据；
- `report_scoring_data/catalog/cases/SIM-207`～`SIM-209`；
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
- 不包含 `.env`、凭据、真实运行数据、SIM-207～SIM-209 或本机报告。

远程主分支整合后，至少重新运行受冲突影响的前端测试、类型检查、构建和后端报告评分专项；若整合
影响面扩大，则再次运行完整 pytest。

## 7. 完成条件

- 功能分支提交已推送且本地 HEAD 与远程分支一致；
- 远程 `master` 包含最新主分支改动和本轮报告评分交付；
- 远程 `master` 指向已经验证的整合提交；
- 本地排除数据仍原样保留且未进入提交；
- 最终向用户报告提交哈希、主分支哈希、实际测试结果和仍保留的已知范围外问题。
