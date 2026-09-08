import json
from pathlib import Path

import pytest

from ourob.model import Action, ActionKind
from ourob.skills import (
    Skill,
    SkillManifestError,
    SkillRegistry,
    filesystem_skills,
    load_manifest,
    resolve_inside,
    validate_manifest,
)

MANIFEST = Path(__file__).parents[1] / "ourob" / "skills_manifest.json"


def test_builtin_manifest_matches_filesystem_registry(tmp_path: Path) -> None:
    registry = filesystem_skills(tmp_path)
    validate_manifest(registry, load_manifest(MANIFEST))
    assert registry.names() == ("filesystem.read", "filesystem.search", "filesystem.write")


def test_empty_manifest_is_rejected_for_nonempty_registry(tmp_path: Path) -> None:
    with pytest.raises(SkillManifestError, match="undeclared"):
        validate_manifest(filesystem_skills(tmp_path), {"schema": "ourob.skills.v1", "capabilities": []})


def test_manifest_rejects_unknown_action_kind() -> None:
    with pytest.raises(SkillManifestError, match="unknown action kind"):
        validate_manifest(SkillRegistry(), {"schema": "ourob.skills.v1", "capabilities": [{"name": "x.y", "kinds": ["NOPE"], "description": "x"}]})


def test_manifest_rejects_duplicate_capability() -> None:
    manifest = {"schema": "ourob.skills.v1", "capabilities": [
        {"name": "x.y", "kinds": ["READ"], "description": "x"},
        {"name": "x.y", "kinds": ["READ"], "description": "x"},
    ]}
    with pytest.raises(SkillManifestError, match="duplicate capability"):
        validate_manifest(SkillRegistry(), manifest)


def test_manifest_detects_kind_or_description_drift() -> None:
    registry = SkillRegistry()
    registry.register(Skill("x.y", frozenset({ActionKind.READ}), lambda _: None, "actual"))
    manifest = {"schema": "ourob.skills.v1", "capabilities": [{"name": "x.y", "kinds": ["WRITE"], "description": "actual"}]}
    with pytest.raises(SkillManifestError, match="mismatch for x.y"):
        validate_manifest(registry, manifest)


def test_manifest_loader_requires_object(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps([]), encoding="utf-8")
    with pytest.raises(SkillManifestError, match="root must be an object"):
        load_manifest(path)


def test_write_create_does_not_overwrite(tmp_path: Path) -> None:
    registry = filesystem_skills(tmp_path)
    target = tmp_path / "x.txt"
    target.write_text("old", encoding="utf-8")
    observation = registry.execute(Action("a", ActionKind.WRITE, "filesystem.write", {"path": "x.txt", "content": "new", "mode": "create"}))
    assert not observation.ok
    assert target.read_text(encoding="utf-8") == "old"


def test_write_replace_is_explicit_and_bounded(tmp_path: Path) -> None:
    registry = filesystem_skills(tmp_path)
    observation = registry.execute(Action("a", ActionKind.WRITE, "filesystem.write", {"path": "x.txt", "content": "new", "mode": "replace", "max_bytes": 3}))
    assert observation.ok
    assert (tmp_path / "x.txt").read_text(encoding="utf-8") == "new"

    too_large = registry.execute(Action("b", ActionKind.WRITE, "filesystem.write", {"path": "y.txt", "content": "toolong", "max_bytes": 3}))
    assert not too_large.ok


def test_search_limits(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("needle", encoding="utf-8")
    registry = filesystem_skills(tmp_path)
    observation = registry.execute(Action("a", ActionKind.SEARCH, "filesystem.search", {"pattern": "needle", "max_files": 0}))
    assert not observation.ok


def test_resolve_inside_rejects_escape_and_absolute(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="escapes"):
        resolve_inside(tmp_path, "../outside")
    with pytest.raises(ValueError, match="repository-relative"):
        resolve_inside(tmp_path, str(tmp_path / "x"))


def test_resolve_inside_rejects_symlink_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / "ourob-m05-outside"
    outside.mkdir(exist_ok=True)
    try:
        (tmp_path / "link").symlink_to(outside, target_is_directory=True)
        with pytest.raises(ValueError, match="escapes"):
            resolve_inside(tmp_path, "link/file.txt")
    finally:
        (tmp_path / "link").unlink(missing_ok=True)
        outside.rmdir()
