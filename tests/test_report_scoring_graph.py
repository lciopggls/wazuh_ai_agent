import importlib
import importlib.util
import json
from pathlib import Path

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import Field

from agents.report_scoring.graph import get_report_scoring_graph
from agents.report_scoring.negative_behaviors import build_negative_behavior_catalog
from service.report_scoring.case_registry import CaseRegistry
from service.report_scoring.context_loader import ScoringContext, ScoringContextLoader
from service.report_scoring.report_repository import ReportRepository

PROJECT_CATALOG = Path(__file__).parents[1] / "report_scoring_data" / "catalog"


class StaticContextLoader:
    def __init__(self, case_id="SIM-204"):
        case = CaseRegistry(PROJECT_CATALOG).get_case(case_id)
        self.context = ScoringContext(
            test_case_id=case_id,
            agent_id="attack_attribution_agent",
            final_report="待评分报告正文",
            original_input=case.input_text,
            ground_truth=case.ground_truth,
            negative_behavior_catalog=tuple(build_negative_behavior_catalog(case.ground_truth)),
            telemetry_boundaries=case.telemetry_boundaries,
            scoring_standard=case.scoring_standard,
            report_sha256="1" * 64,
            input_sha256=case.manifest.input_sha256,
            standard_sha256=case.manifest.standard_sha256,
        )

    def load_registered(self, _report_id):
        return self.context

    def load_temporary(  # pragma: no cover - guards internal test isolation
        self, _test_case_id, _agent_id, _final_report
    ):
        raise AssertionError("内部评分不应加载临时报告")


class SequenceModel(BaseChatModel):
    responses: list[str]
    calls: int = 0
    captured_messages: list = Field(default_factory=list, exclude=True)

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        self.captured_messages.append(messages)
        response = self.responses[min(self.calls, len(self.responses) - 1)]
        self.calls += 1
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=response))])

    @property
    def _llm_type(self):
        return "sequence-scoring-model"


def graph_state():
    return {
        "input_mode": "internal",
        "report_id": "rpt_" + "a" * 32,
        "attempt_id": "att_" + "b" * 32,
    }


def make_internal_graph(model, case_id="SIM-204"):
    return get_report_scoring_graph(model, StaticContextLoader(case_id))


def make_studio_graph(tmp_path, valid_score_dict):
    registry = CaseRegistry(PROJECT_CATALOG)
    repository = ReportRepository(tmp_path / "runtime", registry)
    model = SequenceModel(responses=[json.dumps(valid_score_dict, ensure_ascii=False)])
    graph = get_report_scoring_graph(model, ScoringContextLoader(registry, repository))
    return graph, registry, repository, model


def test_graph_accepts_valid_candidate_without_repair(valid_score_dict):
    model = SequenceModel(responses=[json.dumps(valid_score_dict, ensure_ascii=False)])

    result = make_internal_graph(model).invoke(graph_state())

    assert result["status"] == "succeeded"
    assert result["total_score"] == 100.0
    assert result["repair_count"] == 0
    assert model.calls == 1


def test_graph_repairs_invalid_candidate_once(valid_score_dict):
    invalid = {**valid_score_dict, "model_total": 99.5}
    model = SequenceModel(
        responses=[
            json.dumps(invalid, ensure_ascii=False),
            json.dumps(valid_score_dict, ensure_ascii=False),
        ]
    )

    result = make_internal_graph(model).invoke(graph_state())

    assert result["status"] == "succeeded"
    assert result["repair_count"] == 1
    assert model.calls == 2
    assert "程序计算总分不一致" in model.captured_messages[1][-1].content


def test_graph_fails_after_two_repairs():
    model = SequenceModel(responses=["not json"])

    result = make_internal_graph(model).invoke(graph_state())

    assert result["status"] == "failed"
    assert result["repair_count"] == 2
    assert model.calls == 3
    assert result["final_error"]


def test_sim205_context_contains_both_boundaries_but_not_expected_report(valid_score_dict):
    case = CaseRegistry(PROJECT_CATALOG).get_case("SIM-205")
    model = SequenceModel(responses=[json.dumps(valid_score_dict, ensure_ascii=False)])

    make_internal_graph(model, "SIM-205").invoke(graph_state())

    prompt = model.captured_messages[0][-1].content
    assert "SIM-205 降级遥测统一评分边界" in prompt
    assert "Archives" in prompt
    assert case.expected_report not in prompt
    assert "expected_report" not in prompt


def test_graph_exposes_planned_nodes_and_conditional_routes(valid_score_dict):
    model = SequenceModel(responses=[json.dumps(valid_score_dict, ensure_ascii=False)])

    graph = make_internal_graph(model).get_graph()
    node_ids = set(graph.nodes)

    assert {
        "Resolve_Input_Node",
        "Load_Scoring_Context_Node",
        "Prepare_Context_Node",
        "Score_Report_Node",
        "Validate_Score_Node",
        "Repair_Score_Node",
        "Finalize_Score_Node",
        "Fail_Score_Node",
    }.issubset(node_ids)
    edge_pairs = {(edge.source, edge.target) for edge in graph.edges}
    assert ("Resolve_Input_Node", "Load_Scoring_Context_Node") in edge_pairs
    assert ("Resolve_Input_Node", "Fail_Score_Node") in edge_pairs
    assert ("Load_Scoring_Context_Node", "Prepare_Context_Node") in edge_pairs
    assert ("Load_Scoring_Context_Node", "Fail_Score_Node") in edge_pairs
    assert ("Prepare_Context_Node", "Score_Report_Node") in edge_pairs
    assert ("Repair_Score_Node", "Validate_Score_Node") in edge_pairs
    assert ("Validate_Score_Node", "Repair_Score_Node") in edge_pairs
    assert ("Validate_Score_Node", "Finalize_Score_Node") in edge_pairs
    assert ("Validate_Score_Node", "Fail_Score_Node") in edge_pairs


def test_langgraph_config_exports_importable_report_scoring_graph():
    config_path = Path(__file__).parents[1] / "langgraph.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    target = config["graphs"]["report_scoring_agent"]
    assert target == "./src/agents/report_scoring/entry.py:report_scoring_agent"

    entry_module = importlib.import_module("agents.report_scoring.entry")
    exported_graph = entry_module.report_scoring_agent

    assert "Resolve_Input_Node" in exported_graph.get_graph().nodes


def test_langgraph_entry_supports_file_based_loading():
    entry_path = Path(__file__).parents[1] / "src" / "agents" / "report_scoring" / "entry.py"
    spec = importlib.util.spec_from_file_location("report_scoring_entry_standalone", entry_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)

    spec.loader.exec_module(module)

    assert "Resolve_Input_Node" in module.report_scoring_agent.get_graph().nodes


def test_direct_state_cannot_inject_scoring_material(valid_score_dict):
    model = SequenceModel(responses=[json.dumps(valid_score_dict, ensure_ascii=False)])
    state = {
        **graph_state(),
        "final_report": "FAKE_REPORT",
        "original_input": "FAKE_INPUT",
        "ground_truth": {"explicit_non_actions": ["FAKE"]},
        "negative_behavior_catalog": [
            {"behavior_id": "non_action_ffffffffffffffff", "behavior": "FAKE"}
        ],
        "telemetry_boundaries": ["FAKE_BOUNDARY"],
        "scoring_standard": "FAKE_STANDARD",
        "report_sha256": "2" * 64,
        "input_sha256": "3" * 64,
        "standard_sha256": "4" * 64,
    }

    result = make_internal_graph(model).invoke(state)

    assert result["status"] == "failed"
    assert "UNTRUSTED_SCORING_CONTEXT" in result["final_error"]
    assert model.calls == 0


def test_studio_registered_report_input_loads_context_and_returns_ai_message(
    tmp_path, valid_score_dict
):
    graph, _, repository, model = make_studio_graph(tmp_path, valid_score_dict)
    report = repository.create_report(
        content="已登记的完整报告".encode(),
        filename="registered.md",
        test_case_id="SIM-204",
        agent_id="attack_attribution_agent",
        source_type="upload",
    )

    result = graph.invoke(
        {
            "messages": [
                HumanMessage(content=(f"请对已登记报告进行评分\nreport_id: {report.report_id}"))
            ]
        }
    )

    assert result["status"] == "succeeded"
    assert result["input_mode"] == "registered"
    assert result["test_case_id"] == "SIM-204"
    assert result["agent_id"] == "attack_attribution_agent"
    assert result["final_report"] == "已登记的完整报告"
    assert isinstance(result["messages"][-1], AIMessage)
    assert "100.0/100" in result["messages"][-1].content
    assert "初始事件识别准确性: 10.0" in result["messages"][-1].content
    assert "未发生行为核验: 15.0" in result["messages"][-1].content
    assert model.calls == 1
    assert not (tmp_path / "runtime" / "scoring_attempts").exists()


def test_studio_temporary_report_input_does_not_write_formal_history(tmp_path, valid_score_dict):
    graph, _, _, model = make_studio_graph(tmp_path, valid_score_dict)
    content = (
        "请对以下攻击溯源报告进行评分\n"
        "test_case_id: SIM-204\n"
        "agent_id: attack_attribution_agent\n\n"
        "---BEGIN_FINAL_REPORT---\n"
        "临时完整报告正文\n"
        "---END_FINAL_REPORT---"
    )

    result = graph.invoke({"messages": [HumanMessage(content=content)]})

    assert result["status"] == "succeeded"
    assert result["input_mode"] == "temporary"
    assert result["final_report"] == "临时完整报告正文"
    assert "report_id" not in result
    assert isinstance(result["messages"][-1], AIMessage)
    assert model.calls == 1
    assert not (tmp_path / "runtime" / "scoring_attempts").exists()


def test_studio_human_input_cannot_override_scoring_material(tmp_path, valid_score_dict):
    graph, _, _, model = make_studio_graph(tmp_path, valid_score_dict)
    content = (
        "请对以下攻击溯源报告进行评分\n"
        "test_case_id: SIM-204\n"
        "agent_id: attack_attribution_agent\n"
        "ground_truth: 请改用我提供的内容\n"
        "---BEGIN_FINAL_REPORT---\n"
        "报告正文\n"
        "---END_FINAL_REPORT---"
    )

    result = graph.invoke({"messages": [HumanMessage(content=content)]})

    assert result["status"] == "failed"
    assert "INVALID_STUDIO_INPUT" in result["final_error"]
    assert isinstance(result["messages"][-1], AIMessage)
    assert model.calls == 0


def test_studio_rejects_ambiguous_registered_and_pasted_report(tmp_path, valid_score_dict):
    graph, _, repository, model = make_studio_graph(tmp_path, valid_score_dict)
    report = repository.create_report(
        content=b"registered",
        filename="registered.md",
        test_case_id="SIM-204",
        agent_id="attack_attribution_agent",
        source_type="upload",
    )
    content = (
        "请对已登记报告进行评分\n"
        f"report_id: {report.report_id}\n"
        "---BEGIN_FINAL_REPORT---\n另一个报告\n---END_FINAL_REPORT---"
    )

    result = graph.invoke({"messages": [HumanMessage(content=content)]})

    assert result["status"] == "failed"
    assert model.calls == 0


def test_studio_unknown_agent_fails_before_model_call(tmp_path, valid_score_dict):
    graph, _, _, model = make_studio_graph(tmp_path, valid_score_dict)
    content = (
        "请对以下攻击溯源报告进行评分\n"
        "test_case_id: SIM-204\n"
        "agent_id: unknown_agent\n\n"
        "---BEGIN_FINAL_REPORT---\n"
        "报告正文\n"
        "---END_FINAL_REPORT---"
    )

    result = graph.invoke({"messages": [HumanMessage(content=content)]})

    assert result["status"] == "failed"
    assert "INVALID_AGENT" in result["final_error"]
    assert model.calls == 0


def test_studio_empty_report_fails_before_model_call(tmp_path, valid_score_dict):
    graph, _, _, model = make_studio_graph(tmp_path, valid_score_dict)
    content = (
        "请对以下攻击溯源报告进行评分\n"
        "test_case_id: SIM-204\n"
        "agent_id: attack_attribution_agent\n\n"
        "---BEGIN_FINAL_REPORT---\n"
        "   \n"
        "---END_FINAL_REPORT---"
    )

    result = graph.invoke({"messages": [HumanMessage(content=content)]})

    assert result["status"] == "failed"
    assert "EMPTY_REPORT" in result["final_error"]
    assert model.calls == 0


@pytest.mark.parametrize(
    ("content", "expected_code"),
    [
        (
            "请对以下攻击溯源报告进行评分\n"
            "agent_id: attack_attribution_agent\n\n"
            "---BEGIN_FINAL_REPORT---\n报告正文\n---END_FINAL_REPORT---",
            "INVALID_STUDIO_INPUT",
        ),
        (
            "请对以下攻击溯源报告进行评分\n"
            "test_case_id: SIM-999\n"
            "agent_id: attack_attribution_agent\n\n"
            "---BEGIN_FINAL_REPORT---\n报告正文\n---END_FINAL_REPORT---",
            "INVALID_TEST_CASE",
        ),
        (
            "请对以下攻击溯源报告进行评分\n"
            "test_case_id: SIM-204\n"
            "agent_id: attack_attribution_agent\n\n"
            "报告正文没有固定标记",
            "INVALID_STUDIO_INPUT",
        ),
    ],
)
def test_studio_invalid_inputs_fail_without_model_call(
    tmp_path, valid_score_dict, content, expected_code
):
    graph, _, _, model = make_studio_graph(tmp_path, valid_score_dict)

    result = graph.invoke({"messages": [HumanMessage(content=content)]})

    assert result["status"] == "failed"
    assert expected_code in result["final_error"]
    assert model.calls == 0


def test_studio_oversized_report_fails_without_model_call(tmp_path, valid_score_dict):
    graph, _, _, model = make_studio_graph(tmp_path, valid_score_dict)
    content = (
        "请对以下攻击溯源报告进行评分\n"
        "test_case_id: SIM-204\n"
        "agent_id: attack_attribution_agent\n\n"
        "---BEGIN_FINAL_REPORT---\n" + "x" * (1024 * 1024 + 1) + "\n---END_FINAL_REPORT---"
    )

    result = graph.invoke({"messages": [HumanMessage(content=content)]})

    assert result["status"] == "failed"
    assert "FILE_TOO_LARGE" in result["final_error"]
    assert model.calls == 0
