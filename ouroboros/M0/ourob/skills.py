"""Skill registry and built-in filesystem capabilities (M0.5).

Skills are the only components that touch the filesystem. They are never
invoked directly by a planner: the kernel dispatches an already policy-
evaluated ``Action`` to the registry.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .model import Action, ActionKind, Observation


SKILLS_MANIFEST_SCHEMA = "ourob.skills.v1"


@dataclass(frozen=True)
class Skill:
    name: str
    kinds: frozenset[ActionKind]
    handler: Callable[[Action], Any]
    description: str = ""


class SkillManifestError(ValueError):
    """Raised when a declarative skill manifest is invalid or mismatched."""


class SkillRegistry:
    def __init__(self) -> None:
        self._skills: dict[str, Skill] = {}

    def register(self, skill: Skill) -> None:
        if not skill.name or not skill.name.replace(".", "_").isidentifier():
            raise ValueError(f"invalid skill name: {skill.name!r}")
        if skill.name in self._skills:
            raise ValueError(f"skill already registered: {skill.name}")
        if not skill.kinds:
            raise ValueError(f"skill declares no action kinds: {skill.name}")
        self._skills[skill.name] = skill

    def has(self, name: str) -> bool:
        return name in self._skills

    def get(self, name: str) -> Skill:
        return self._skills[name]

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._skills))

    def __len__(self) -> int:
        return len(self._skills)

    def execute(self, action: Action) -> Observation:
        skill = self._skills.get(action.skill)
        if skill is None:
            return Observation(action.id, False, "", None, f"unknown skill: {action.skill}")
        if action.kind not in skill.kinds:
            return Observation(action.id, False, "", None, f"skill {action.skill} does not support {action.kind}")
        try:
            return Observation(action.id, True, "", skill.handler(action), None)
        except Exception as exc:  # noqa: BLE001 - failures are observations, not crashes
            return Observation(action.id, False, "", None, f"{type(exc).__name__}: {exc}")

    def call(self, name: str, arguments: dict[str, Any] | None = None, kind: ActionKind | None = None) -> Any:
        """Privileged convenience helper for tests; production dispatch uses ``execute``."""
        skill = self._skills[name]
        chosen = kind or sorted(skill.kinds, key=lambda value: value.value)[0]
        return skill.handler(Action(f"call-{name}", chosen, name, dict(arguments or {})))


def _manifest_records(manifest: Mapping[str, Any]) -> dict[str, tuple[frozenset[ActionKind], str]]:
    if manifest.get("schema") != SKILLS_MANIFEST_SCHEMA:
        raise SkillManifestError(f"unsupported skill manifest schema: {manifest.get('schema')!r}")
    capabilities = manifest.get("capabilities")
    if not isinstance(capabilities, list):
        raise SkillManifestError("skill manifest capabilities must be a list")

    records: dict[str, tuple[frozenset[ActionKind], str]] = {}
    for index, capability in enumerate(capabilities):
        if not isinstance(capability, Mapping):
            raise SkillManifestError(f"capability {index} must be an object")
        name = capability.get("name")
        kinds = capability.get("kinds")
        description = capability.get("description", "")
        if not isinstance(name, str) or not name:
            raise SkillManifestError(f"capability {index} requires a non-empty name")
        if not name.replace(".", "_").isidentifier():
            raise SkillManifestError(f"invalid capability name: {name!r}")
        if name in records:
            raise SkillManifestError(f"duplicate capability: {name}")
        if not isinstance(kinds, list) or not kinds:
            raise SkillManifestError(f"capability {name} declares no action kinds")
        if not isinstance(description, str):
            raise SkillManifestError(f"capability {name} description must be a string")
        try:
            parsed_kinds = frozenset(ActionKind(value) for value in kinds)
        except (TypeError, ValueError) as exc:
            raise SkillManifestError(f"capability {name} contains an unknown action kind") from exc
        if len(parsed_kinds) != len(kinds):
            raise SkillManifestError(f"capability {name} contains duplicate action kinds")
        records[name] = (parsed_kinds, description)
    return records


def validate_manifest(registry: SkillRegistry, manifest: Mapping[str, Any]) -> None:
    """Prove that the executable registry exactly matches the declaration."""
    declared = _manifest_records(manifest)
    actual = {
        name: (skill.kinds, skill.description)
        for name, skill in registry._skills.items()
    }
    if set(actual) != set(declared):
        missing = sorted(set(declared) - set(actual))
        undeclared = sorted(set(actual) - set(declared))
        raise SkillManifestError(f"skill manifest mismatch: missing={missing}, undeclared={undeclared}")
    for name in sorted(actual):
        if actual[name] != declared[name]:
            raise SkillManifestError(f"skill manifest mismatch for {name}")


def load_manifest(path: Path) -> dict[str, Any]:
    """Load and structurally validate a JSON skill manifest."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SkillManifestError(f"unable to load skill manifest: {path}") from exc
    if not isinstance(data, dict):
        raise SkillManifestError("skill manifest root must be an object")
    _manifest_records(data)
    return data


def resolve_inside(root: Path, path: str) -> tuple[Path, Path]:
    """Resolve ``path`` under ``root`` and prove (post-resolution) it stays inside."""
    root = Path(root).resolve()
    candidate = Path(str(path))
    if candidate.is_absolute():
        raise ValueError("path must be repository-relative")
    target = (root / candidate).resolve()
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise ValueError("path escapes repository root") from exc
    return target, relative


def filesystem_skills(repo_root: Path, registry: SkillRegistry | None = None) -> SkillRegistry:
    root = Path(repo_root).resolve()
    registry = registry if registry is not None else SkillRegistry()

    def read(action: Action) -> str:
        target, _ = resolve_inside(root, action.arguments["path"])
        return target.read_text(encoding="utf-8")

    def write(action: Action) -> str:
        target, relative = resolve_inside(root, action.arguments["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(action.arguments.get("content", "")), encoding="utf-8")
        return relative.as_posix()

    def search(action: Action) -> list[str]:
        pattern = str(action.arguments.get("pattern", ""))
        glob = str(action.arguments.get("glob", "**/*"))
        if not pattern:
            raise ValueError("search requires a pattern")
        hits: list[str] = []
        for candidate in sorted(root.glob(glob)):
            relative = candidate.relative_to(root)
            if not candidate.is_file() or ".git" in relative.parts:
                continue
            try:
                text = candidate.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                if pattern in line:
                    hits.append(f"{relative.as_posix()}:{line_number}:{line}")
        return hits

    registry.register(Skill("filesystem.read", frozenset({ActionKind.READ}), read, "read a repository file"))
    registry.register(
        Skill("filesystem.write", frozenset({ActionKind.WRITE, ActionKind.EDIT}), write, "write a repository file")
    )
    registry.register(Skill("filesystem.search", frozenset({ActionKind.SEARCH}), search, "substring search"))
    return registry
