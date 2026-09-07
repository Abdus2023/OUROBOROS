"""Skill registry and built-in filesystem capabilities (M0.5).

Skills are the only components that touch the filesystem. They are never
invoked directly by a planner: the kernel dispatches an already policy-
evaluated ``Action`` to the registry.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .model import Action, ActionKind, Observation


@dataclass(frozen=True)
class Skill:
    name: str
    kinds: frozenset[ActionKind]
    handler: Callable[[Action], Any]
    description: str = ""


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
        """Convenience helper for invoking a capability outside a run (e.g. tests)."""
        skill = self._skills[name]
        chosen = kind or sorted(skill.kinds)[0]
        return skill.handler(Action(f"call-{name}", chosen, name, dict(arguments or {})))


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
            if not candidate.is_file() or ".git" in candidate.relative_to(root).parts:
                continue
            try:
                text = candidate.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                if pattern in line:
                    hits.append(f"{candidate.relative_to(root).as_posix()}:{line_number}:{line}")
        return hits

    registry.register(Skill("filesystem.read", frozenset({ActionKind.READ}), read, "read a repository file"))
    registry.register(
        Skill("filesystem.write", frozenset({ActionKind.WRITE, ActionKind.EDIT}), write, "write a repository file")
    )
    registry.register(Skill("filesystem.search", frozenset({ActionKind.SEARCH}), search, "substring search"))
    return registry
