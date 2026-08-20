# 报告评分智能体：实现与审查交接

> 更新日期：2026-08-20  
> 交接基线：`b89f4ae`  
> 交付状态：代码已提交并推送，等待独立审查

## 1. 实现概览

本阶段完成了一条独立的报告评分链路：

`报告登记 -> 评分请求 -> LangGraph 评分图 -> DeepSeek 结构化输出 -> 服务端校验与重算 -> 文件持久化 -> 前端详情/历史/对比`

Studio 可直接运行 `report_scoring_agent`；完整项目则通过 `/api/report-scoring` 接口族驱动同一评分能力。

后续工作区优化增加了开发测试入口：正式 AI 智能助手只保留路由智能体对话，测试模块复用同一聊天组件但支持 `attack_attribution`、`baseline_agent_simple` 和 `baseline_agent_plus`，并将报告评分页面迁移到测试模块。测试模块由 `VITE_ENABLE_TEST_MODULE` 控制显示，评分功能仍由 `VITE_ENABLE_REPORT_SCORING` 控制。

## 2. 主要代码位置

### LangGraph 与评分逻辑

- `src/agents/report_scoring/entry.py`：Studio/服务入口。
- `src/agents/report_scoring/graph.py`：评分图和节点连接。
- `src/agents/report_scoring/nodes.py`：上下文准备、模型调用、结果生成。
- `src/agents/report_scoring/prompt.py`：评分提示词。
- `src/agents/report_scoring/schemas.py`、`state.py`：结构化契约和图状态。
- `src/agents/report_scoring/validation.py`、`negative_behaviors.py`：字段校验、总分重算和负向行为规则。

### 后端服务

- `src/service/report_scoring/router.py`：`/api/report-scoring` 路由。
- `scoring_service.py`：评分编排、幂等和重评分。
- `report_repository.py`、`score_repository.py`：报告、attempt 和结果持久化。
- `case_registry.py`、`context_loader.py`：测试用例与评分上下文加载。
- `api_models.py`、`errors.py`、`safe_paths.py`：API 模型、错误契约和路径边界。
- `src/service/memory.py`：将评分路由接入现有 FastAPI 服务。

主要接口包括：

- `POST /api/report-scoring/reports/upload`
- `POST /api/report-scoring/reports/studio-import`
- `GET /api/report-scoring/reports`
- `POST /api/report-scoring/reports/{report_id}/score`
- `POST /api/report-scoring/reports/{report_id}/rescore`
- `GET /api/report-scoring/reports/{report_id}/scores`
- `GET /api/report-scoring/reports/{report_id}/scores/latest`
- `GET /api/report-scoring/scores/{score_id}`
- `GET /api/report-scoring/comparisons`

### 前端

- `frontend/src/api/report_scoring.ts`：类型和接口封装。
- `frontend/src/views/index/report_scoring.vue`：评分主页面。
- `frontend/src/views/index/report-scoring/`：登记、列表、详情和对比组件。
- `frontend/src/views/index/index.vue`、`second_right.vue`：入口接入。
- `frontend/types/env.d.ts`：`VITE_ENABLE_REPORT_SCORING`、`VITE_ENABLE_TEST_MODULE` 类型声明。

### 数据与配置

- `langgraph.json`：注册 `report_scoring_agent`。
- `report_scoring_data/catalog/`：智能体、SIM-204～206 和 `v3.0` 评分标准。
- `report_scoring_data/runtime/`：运行时报告和评分 attempt/结果目录。
- `report_scoring_data/studio_inbox/`：Studio 导入边界。

## 3. 结果格式化与展示

模型首先返回符合评分 schema 的候选结构。后端执行以下处理：

1. 校验六个维度、说明、优缺点、根因和扣分字段。
2. 校验分数范围及字段之间的一致性。
3. 按固定规则重新计算 `total_score`，不直接信任模型自报总分。
4. 将成功结果与 attempt 关联持久化；失败则保留明确失败状态。
5. API 返回统一的 `ScoreResult`，前端据此展示总分、六维详情、结论、历史和对比聚合。

因此，前端不解析 AIMessage 文本。AIMessage 主要用于 Studio 可读反馈，项目页面使用经过验证的结构化 API 数据。

## 4. 验证结果

- Python 静态检查通过。
- 完整 pytest 记录：145 passed，2 warnings。
- 前端测试、类型检查和生产构建通过。
- Studio 手工运行成功，示例分数 83.0。
- 完整前后端手工运行成功，SIM-204 / `baseline_agent_simple` 得分 48.0；详情、历史和对比均正常。
- 页面刷新未产生重复 attempt；未评分报告的 latest 404 符合约定。
- 用户已确认测试模块手动测试通过；测试模块关闭后导航后续分组自动补位。

本次手动验收后仅更新项目文档，没有重新运行自动化测试。

## 5. 提交记录

- `b016003`：增加 multipart 表单解析依赖。
- `cbb76cd`：加入报告评分智能体、后端、前端和用例目录。
- `b89f4ae`：修复评分工作流集成、持久化及相关兼容问题。

三个提交均已推送到 `origin/codex/report-scoring-agent-planning`。

## 6. 审查注意事项

- 当前功能验收强调“流程跑通”，不以自动分数贴近人工分数作为通过条件。
- SIM-204 自动评分与人工参考曾有约 +18 分差异，该项已明确延后。
- 剩余批量测试已暂停，不应把未跑完整批次误判为当前功能缺陷。
- 工作区存在未提交的本地修改和测试/仿真文件；审查与修复必须避免将其混入提交。
- 文档目录只保留当前状态、最终目标、当前任务和本交接文件；后续状态直接更新这些文件，不再累积中间文档。
