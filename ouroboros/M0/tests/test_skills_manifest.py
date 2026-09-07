import json
from pathlib import Path

import pytest

from ourob.model import ActionKind
from ourob.skills import (
    Skill,
    SkillManifestError,
    SkillRegistry,
    filesystem_skills,
    load_manifest,
    validate_manifest,
)


MANIFEST = Path(__file__).parents[1] / "ourob" / "skills_manifest.json"


def test_builtin_manifest_matches_filesystem_registry(tmp_path: Path) -> None:
    registry = filesystem_skills(tmp_path)
    manifest = load_manifest(MANIFEST)
    validate_manifest(registry, manifest)
    assert registry.names() == (
        "filesystem.read",
        "filesystem.search",
        "filesystem.write",
    )


def test_empty_manifest_is_rejected_for_nonempty_registry(tmp_path: Path) -> None:
    registry = filesystem_skills(tmp_path)
    with pytest.raises(SkillManifestError, match="undeclared"):
        validate_manifest(registry, {"schema": "ourob.skills.v1", "capabilities": []})


def test_manifest_rejects_unknown_action_kind() -> None:
    with pytest.raises(SkillManifestError, match="unknown action kind"):
        validate_manifest(SkillRegistry(), {
            "schema": "ourob.skills.v1",
            "capabilities": [{"name": "x.y", "kinds": ["NOPE"], "description": "x"}],
        })


def test_manifest_rejects_duplicate_capability() -> None:
    manifest = {
        "schema": "ourob.skills.v1",
        "capabilities": [
            {"name": "x.y", "kinds": ["READ"], "description": "x"},
            {"name": "x.y", "kinds": ["READ"], "description": "x"},
        ],
    }
    with pytest.raises(SkillManifestError, match="duplicate capability"):
        validate_manifest(SkillRegistry(), manifest)


def test_manifest_detects_kind_or_description_drift() -> None:
    registry = SkillRegistry()
    registry.register(Skill("x.y", frozenset({ActionKind.READ}), lambda _: None, "actual"))
    manifest = {
        "schema": "ourob.skills.v1",
        "capabilities": [{"name": "x.y", "kinds": ["WRITE"], "description": "actual"}],
    }
    with pytest.raises(SkillManifestError, match="mismatch for x.y"):
        validate_manifest(registry, manifest)


def test_manifest_loader_requires_object(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps([]), encoding="utf-8")
    with pytest.raises(SkillManifestError, match="root must be an object"):
        load_manifest(path)
