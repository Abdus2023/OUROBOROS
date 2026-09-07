"""Deterministic planners (M0.10).

A planner produces a ``Plan``: a proposal, never an authorization. M0 ships a
``ScriptedPlanner`` (reads a JSON plan file) and a built-in
``AddCapabilityPlanner`` that emits the two-write plan used by the
self-extension proof. An LLM-backed planner belongs to M2 and must emit the
same ``Plan`` object; the kernel does not care where a plan came from.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from .bootstrap import SKILLS_MANIFEST_SCHEMA, load_skills_manifest
from .model import Action, ActionKind, Plan

PLAN_SCHEMA = "ourob.plan.v1"


class Planner(Protocol):
    def propose(self, task: str) -> Plan: ...


class ScriptedPlanner:
    def __init__(self, plan_path: Path):
        self.plan_path = Path(plan_path)

    def propose(self, task: str) -> Plan:
        raw = json.loads(self.plan_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("schema") != PLAN_SCHEMA:
            raise ValueError(f"plan file must declare schema {PLAN_SCHEMA}")
        plan = Plan.from_record({"task": raw.get("task"), "actions": raw.get("actions")})
        if plan.task != task:
            raise ValueError(f"scripted plan is for task {plan.task!r}, not {task!r}")
        return plan


CAPABILITY_TEMPLATE = '''"""Repository-declared capability: {name}."""

from ourob.model import ActionKind
from ourob.skills import Skill


def {name}(action):
    who = str(action.arguments.get("name", "World"))
    return f"{greeting}, {{who}}!"


def register(registry):
    registry.register(Skill("{name}", frozenset({{ActionKind.EXECUTE}}), {name}, "{greeting} someone"))
'''


class AddCapabilityPlanner:
    """Emits the canonical self-extension plan: write ``skills/<name>.py`` and
    re-declare ``skills/manifest.json`` with the new capability appended."""

    def __init__(self, repo_root: Path, name: str, greeting: str = "Hello"):
        if not name.isidentifier():
            raise ValueError(f"capability name must be an identifier: {name!r}")
        self.repo_root = Path(repo_root)
        self.name = name
        self.greeting = greeting

    def propose(self, task: str) -> Plan:
        manifest_path = self.repo_root / "skills" / "manifest.json"
        existing = load_skills_manifest(manifest_path)
        capabilities = [{"name": c.name, "module": c.module} for c in existing if c.name != self.name]
        capabilities.append({"name": self.name, "module": f"skills/{self.name}.py"})
        manifest = {"schema": SKILLS_MANIFEST_SCHEMA, "capabilities": capabilities}
        return Plan(
            task,
            (
                Action(
                    f"write-{self.name}", ActionKind.WRITE, "filesystem.write",
                    {"path": f"skills/{self.name}.py", "content": CAPABILITY_TEMPLATE.format(name=self.name, greeting=self.greeting)},
                    f"create capability module {self.name}",
                ),
                Action(
                    "write-manifest", ActionKind.WRITE, "filesystem.write",
                    {"path": "skills/manifest.json", "content": json.dumps(manifest, indent=2) + "\n"},
                    f"declare capability {self.name}",
                ),
            ),
        )
