SCORING_AGENT_VERSION = "report-scoring-agent-v3"
PROMPT_VERSION = "report-scoring-v3.0-3"
SCORING_CONTRACT_VERSION = "report-scoring-contract-v3"

SYSTEM_PROMPT = """你是开发期攻击溯源报告评分智能体。严格按照给定 v3.0 标准评分。
最终报告是唯一被评分产物。原始输入、Ground Truth 和遥测边界只用于核对事实、
可见证据范围和合理遗漏，绝不能把最终报告没有写出的内容补进报告得分。
不要查询 Wazuh，不要参考 expected report、其他报告、State、查询记录或既有 evaluation。
返回且只返回满足 JSON schema 的单一 JSON 对象。"""

CONTEXT_TEMPLATE = """请评分以下最终报告。

<final_report>
{final_report}
</final_report>

<original_high_risk_event_input>
{original_input}
</original_high_risk_event_input>

<ground_truth_scoring_only>
{ground_truth}
</ground_truth_scoring_only>

<explicit_non_action_catalog>
{negative_behavior_catalog}
</explicit_non_action_catalog>

负面结论的 correct_findings 和 incorrect_findings 必须引用上述原子 behavior_id，
并将目录中的规范 behavior 文本逐字复制到候选结果，不能改写、合并或新增行为。
同一 behavior_id 最多出现一次，且不能同时出现在正确项和错误项中。

<telemetry_and_visibility_boundaries>
{telemetry_boundaries}
</telemetry_and_visibility_boundaries>

<scoring_standard_v3>
{scoring_standard}
</scoring_standard_v3>

{format_instructions}
"""

REPAIR_TEMPLATE = """上一个候选评分未通过程序硬规则校验。只修复结构或计分错误，
不得改变报告和案例事实，不得替报告补充证据。

<invalid_candidate>
{raw_output}
</invalid_candidate>

<validation_errors>
{validation_errors}
</validation_errors>

{format_instructions}
"""
