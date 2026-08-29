import re
from typing import Any

_BEHAVIOR_ID = re.compile(r"^non_action_[a-z0-9_]{1,64}$")


def build_negative_behavior_catalog(ground_truth: dict[str, Any]) -> list[dict[str, str]]:
    """Load the explicit, atomic negative-behavior catalog from Ground Truth."""

    values = ground_truth.get("negative_behavior_catalog")
    if not isinstance(values, list) or not values:
        raise ValueError("Ground Truth negative_behavior_catalog 必须是非空列表")

    catalog: list[dict[str, str]] = []
    seen_behaviors: set[str] = set()
    seen_ids: set[str] = set()
    for value in values:
        if not isinstance(value, dict) or set(value) != {"behavior_id", "behavior"}:
            raise ValueError("Ground Truth 负面行为必须只包含 behavior_id 和 behavior")
        behavior_id = value.get("behavior_id")
        behavior = value.get("behavior")
        if not isinstance(behavior_id, str) or _BEHAVIOR_ID.fullmatch(behavior_id) is None:
            raise ValueError("Ground Truth 负面行为 behavior_id 格式无效")
        if not isinstance(behavior, str) or not behavior.strip() or behavior != behavior.strip():
            raise ValueError("Ground Truth 负面行为 behavior 必须是规范化非空文本")
        if behavior in seen_behaviors:
            raise ValueError("Ground Truth negative_behavior_catalog 包含重复规范文本")
        if behavior_id in seen_ids:
            raise ValueError("Ground Truth negative_behavior_catalog 包含重复 behavior_id")
        catalog.append({"behavior_id": behavior_id, "behavior": behavior})
        seen_behaviors.add(behavior)
        seen_ids.add(behavior_id)
    return catalog
