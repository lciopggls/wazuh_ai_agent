# 报告评分智能体：实现交接

> 更新日期：2026-08-28
> 基线：`origin/master=d56130c`
> 当前分支：`codex/report-scoring-case-preparation`
> 当前方向：本地预置答案案例 + AI 对话/本机报告两个入口

## 1. 当前架构

核心链路保持不变：

```text
本地案例目录
  + 已登记报告
  → LangGraph 报告评分图
  → 模型结构化输出
  → 服务端校验与总分重算
  → 文件持久化
  → 详情、历史和多智能体对比
```

测试阶段不再创建案例。所有 Ground Truth、遥测边界、预期报告、冻结证据和评分标准在测试前
已经保存在本机案例目录。

## 2. 报告入口合同

### AI 对话

`POST /api/report/save` 先保存报告。请求包含简单的 `scoring_registration` 时，再使用
`test_case_id`、`agent_id` 及可选 Thread ID、Run ID、备注登记评分报告。

登记失败只影响可选评分登记，不能撤销已经成功保存的核心 Markdown。

前端会持续显示实际本地路径；成功登记同时显示 `report_id`。登记失败时反馈中同时保留本地
保存路径和结构化错误，避免将部分成功误报为全部失败。

### 本机上传

`POST /api/report-scoring/reports/upload` 接受：

- 报告文件；
- `test_case_id`；
- `agent_id`；
- 可选 Thread ID、Run ID 和备注。

不再接受或要求 `anchor.json`、攻击 RUN、确认人或答案材料。

登记成功后显示 `report_id` 和仓储相对路径，浏览器文件输入被真实清空。同名本地 Markdown
保存不会覆盖不同内容，空内容和超过 1 MiB 的内容会被明确拒绝。

## 3. 主要代码位置

- `src/agents/report_scoring/`：评分图、提示词、schema、校验和负向行为规则。
- `src/service/report_scoring/case_registry.py`：读取本地已准备案例。
- `src/service/report_scoring/context_loader.py`：构造评分上下文。
- `src/service/report_scoring/report_repository.py`：报告登记与持久化。
- `src/service/report_scoring/score_repository.py`：attempt 和评分结果持久化。
- `src/service/report_scoring/scoring_service.py`：评分、重评分和比较编排。
- `src/service/report_scoring/router.py`：报告评分 API。
- `src/service/memory.py`：AI 对话报告保存及可选评分登记。
- `frontend/src/views/index/second_right.vue`：AI 对话报告保存/登记入口。
- `frontend/src/views/index/report-scoring/ReportRegistrationPanel.vue`：本机报告登记。
- `frontend/src/views/index/report_scoring.vue`：评分列表、详情、历史和对比页面。

## 4. 已移除内容

- `case_preparation_repository.py`
- `case_preparation_service.py`
- `CasePreparationPanel.vue`
- 锚点预览与上传 API
- 案例草稿、Archives 查询、人工材料确认、发布和恢复 API
- Studio inbox 登记路由、仓储入口、前端 API 和目录
- 动态案例准备数据模型和来源补录字段
- 旧功能专属测试和历史文档
- 本地 `report_scoring_data/case_preparation/` 草稿及审计数据

不得恢复上述能力，除非用户重新提出明确的新需求。

## 5. 数据边界

本轮没有删除：

- `attack_simulations/`
- `report_scoring_data/runtime/`
- `report_scoring_data/catalog/cases/SIM-207/`
- `src/knowledge_graph/input/`
- `stash@{0}`
- 无关测试修改和其他用户文件

本地案例列表由案例目录、manifest 的 `enabled` 状态和注册表完整性校验决定，不在前后端
硬编码具体案例编号。

## 6. 新主机新增案例的交接

新增案例不需要再开发页面或接口。新主机上的案例设计人员或辅助 AI 应先保存脚本设计答案，真实
执行后再根据 runtime manifest、Alerts 和 Archives 证据制作正式答案，最后把正式文件安装到
`report_scoring_data/catalog/cases/SIM-XXX/`。详细目录、必交付文件、哈希校验和分阶段 AI 提示词见
`12_NEW_HOST_NEW_ATTACK_TEST_FLOW.md`。

正式答案完成前，可以先把被测智能体报告保存为本地 Markdown；案例安装并重启后，再通过本机
上传入口登记。不得把新报告临时绑定到旧 SIM 案例，也不得用被测报告反推 Ground Truth。

全新克隆主机还必须按该文档先配置根目录 `.env`、启用前端两个测试开关并启动 2024、8001、8112
三个本地服务。以 `/api/report-scoring/test-cases` 和 `/agents` 返回成功作为评分链路就绪门，不以
“页面能打开”代替后端案例加载成功。

## 7. 验证与交付

本次提交前验证结果：

- Black：本轮 16 个 Python 文件已格式化并复查；当前 Python 3.12 与配置中的 `py313` target
  组合无法执行 Black AST 等价安全检查，因此按工具提示使用 `--fast`；
- Ruff：本轮修改范围通过；全仓仍有 3 个既有范围外问题（2 个 `UP042`、1 个 `B904`）；
- 后端专项：`157 passed, 1 skipped, 1 warning`；
- 新主机案例注册表/API：`35 passed, 1 skipped, 1 warning`；LangGraph 配置校验通过并识别 9 个图；
- 前端：`7 passed`，类型检查和生产构建通过；
- 完整 pytest：`208 passed, 1 skipped, 1 failed, 2 warnings`。唯一失败是既有真实模型 strict
  轨迹测试对参数类型和最终措辞差异敏感，实际工具选择和返回数据正确，与本轮评分修改无关。

验证使用的 pytest 和 Black 临时目录均已删除，没有把新临时目录留在项目根目录。

本轮按显式文件白名单交付，禁止使用 `git add .`。交付分支为
`codex/report-scoring-case-preparation`，不直接更新 `master`；本地仿真、历史报告、SIM-207 和无关
工作树文件继续排除。
