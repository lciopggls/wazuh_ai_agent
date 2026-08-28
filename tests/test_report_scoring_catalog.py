from service.report_scoring.case_registry import CaseRegistry
from service.report_scoring.context_loader import create_default_scoring_context_loader


def test_catalog_hashing_normalizes_platform_line_endings(tmp_path) -> None:
    catalog_file = tmp_path / "catalog.txt"
    catalog_file.write_bytes(b"first\r\nsecond\rthird\n")

    text, content = CaseRegistry._read_utf8(catalog_file, "catalog")

    assert text == "first\nsecond\nthird\n"
    assert content == b"first\nsecond\nthird\n"


def test_default_report_scoring_catalog_loads() -> None:
    loader = create_default_scoring_context_loader()

    assert [case.test_case_id for case in loader.case_registry.list_cases()] == [
        "SIM-204",
        "SIM-205",
        "SIM-206",
    ]
