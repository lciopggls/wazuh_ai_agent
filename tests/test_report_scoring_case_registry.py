import json
import shutil
from pathlib import Path

import pytest

from service.report_scoring.case_registry import CaseRegistry
from service.report_scoring.errors import ReportScoringError

PROJECT_CATALOG = Path(__file__).parents[1] / "report_scoring_data" / "catalog"


def copy_catalog(tmp_path: Path) -> Path:
    target = tmp_path / "catalog"
    shutil.copytree(PROJECT_CATALOG, target)
    return target


def read_manifest(catalog: Path, case_id: str) -> tuple[Path, dict]:
    path = catalog / "cases" / case_id / "manifest.json"
    return path, json.loads(path.read_text(encoding="utf-8"))


def write_manifest(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def test_default_catalog_loads_published_cases_and_canonical_agents():
    registry = CaseRegistry(PROJECT_CATALOG)

    cases = registry.list_cases()
    assert [case.test_case_id for case in cases] == [
        "SIM-204",
        "SIM-205",
        "SIM-206",
        "SIM-207",
    ]
    assert [agent.agent_id for agent in registry.list_agents()] == [
        "attack_attribution_agent",
        "baseline_agent_simple",
        "baseline_agent_plus",
    ]
    assert (
        registry.canonicalize_agent_id("attack_attributor", allow_alias=True)
        == "attack_attribution_agent"
    )
    with pytest.raises(ReportScoringError, match="未知被测智能体"):
        registry.canonicalize_agent_id("attack_attributor")


def test_sim205_telemetry_boundaries_are_loaded_in_manifest_order():
    registry = CaseRegistry(PROJECT_CATALOG)

    boundaries = registry.get_case("SIM-205").telemetry_boundaries

    assert len(boundaries) == 2
    assert "Archives" in boundaries[0]
    assert "降级遥测统一评分边界" in boundaries[1]


@pytest.mark.parametrize(
    ("case_id", "expected_ids"),
    [
        (
            "SIM-204",
            [
                "non_action_network_download",
                "non_action_external_payload",
                "non_action_persistence",
                "non_action_credential_access",
                "non_action_security_control",
            ],
        ),
        (
            "SIM-205",
            [
                "non_action_decode_execute",
                "non_action_autorun",
                "non_action_system_policy",
                "non_action_security_control",
                "non_action_network_operation",
                "non_action_credential_operation",
            ],
        ),
        (
            "SIM-206",
            [
                "non_action_network_download",
                "non_action_external_payload",
                "non_action_persistence",
                "non_action_credential_access",
                "non_action_security_control",
            ],
        ),
    ],
)
def test_atomic_negative_behavior_catalog_matches_v3_expected_scope(case_id, expected_ids):
    case = CaseRegistry(PROJECT_CATALOG).get_case(case_id)

    assert [item["behavior_id"] for item in case.negative_behavior_catalog] == expected_ids
    assert len({item["behavior"] for item in case.negative_behavior_catalog}) == len(expected_ids)


@pytest.mark.parametrize("duplicate_field", ["behavior_id", "behavior"])
def test_registry_rejects_duplicate_negative_behavior_catalog_values(tmp_path, duplicate_field):
    catalog = copy_catalog(tmp_path)
    path = catalog / "cases" / "SIM-204" / "ground_truth.json"
    ground_truth = json.loads(path.read_text(encoding="utf-8"))
    ground_truth["negative_behavior_catalog"][1][duplicate_field] = ground_truth[
        "negative_behavior_catalog"
    ][0][duplicate_field]
    path.write_text(json.dumps(ground_truth), encoding="utf-8")

    with pytest.raises(ReportScoringError) as exc_info:
        CaseRegistry(catalog)

    assert exc_info.value.field == "negative_behavior_catalog"


@pytest.mark.parametrize(
    ("mutation", "expected_field"),
    [
        (lambda manifest: manifest.update(input_sha256="0" * 64), "input_sha256"),
        (lambda manifest: manifest.update(standard_sha256="0" * 64), "standard_sha256"),
        (lambda manifest: manifest.update(scoring_standard_version="v2.0"), None),
    ],
)
def test_manifest_rejects_hash_or_version_mismatch(tmp_path, mutation, expected_field):
    catalog = copy_catalog(tmp_path)
    path, manifest = read_manifest(catalog, "SIM-204")
    mutation(manifest)
    write_manifest(path, manifest)

    with pytest.raises(ReportScoringError) as exc_info:
        CaseRegistry(catalog)

    if expected_field:
        assert exc_info.value.field == expected_field


def test_registry_rejects_missing_file(tmp_path):
    catalog = copy_catalog(tmp_path)
    (catalog / "cases" / "SIM-204" / "anchor.json").unlink()

    with pytest.raises(ReportScoringError) as exc_info:
        CaseRegistry(catalog)

    assert exc_info.value.code == "PATH_OUTSIDE_ALLOWED_ROOT"


@pytest.mark.parametrize("value", ["../ground_truth.json", "C:/Windows/win.ini"])
def test_registry_rejects_path_escape(tmp_path, value):
    catalog = copy_catalog(tmp_path)
    path, manifest = read_manifest(catalog, "SIM-204")
    manifest["ground_truth_path"] = value
    write_manifest(path, manifest)

    with pytest.raises(ReportScoringError) as exc_info:
        CaseRegistry(catalog)

    assert exc_info.value.code == "PATH_OUTSIDE_ALLOWED_ROOT"


def test_registry_rejects_symlink_escape_when_supported(tmp_path):
    catalog = copy_catalog(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    link = catalog / "cases" / "SIM-204" / "unsafe.json"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("当前系统未授权创建符号链接")
    path, manifest = read_manifest(catalog, "SIM-204")
    manifest["anchor_path"] = "unsafe.json"
    write_manifest(path, manifest)

    with pytest.raises(ReportScoringError) as exc_info:
        CaseRegistry(catalog)

    assert exc_info.value.code == "PATH_OUTSIDE_ALLOWED_ROOT"


def test_registry_rejects_duplicate_case_ids(tmp_path):
    catalog = copy_catalog(tmp_path)
    duplicate = catalog / "cases" / "SIM-999"
    shutil.copytree(catalog / "cases" / "SIM-204", duplicate)

    with pytest.raises(ReportScoringError, match="重复"):
        CaseRegistry(catalog)


def test_registry_rejects_ground_truth_id_mismatch(tmp_path):
    catalog = copy_catalog(tmp_path)
    path = catalog / "cases" / "SIM-204" / "ground_truth.json"
    ground_truth = json.loads(path.read_text(encoding="utf-8"))
    ground_truth["scenario_id"] = "SIM-999"
    path.write_text(json.dumps(ground_truth), encoding="utf-8")

    with pytest.raises(ReportScoringError) as exc_info:
        CaseRegistry(catalog)

    assert exc_info.value.field == "scenario_id"
