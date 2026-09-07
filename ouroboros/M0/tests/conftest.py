"""Shared fixtures: a disposable repository image per test.

Each fixture repo contains a constitution, a gate set, an (initially empty)
skills manifest and a copy of the ``ourob`` package so that repository-declared
capabilities can import ``ourob.skills`` during cold bootstrap.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parents[1]  # ouroboros/M0
OUROB_PACKAGE = PACKAGE_ROOT / "ourob"

CONSTITUTION = {
    "schema": "ourob.constitution.v1",
    "mode": "fail_closed",
    "invariants": ["M0-INV-01", "M0-INV-03", "M0-INV-10"],
    "protected_surfaces": ["ouroboros/M0/ourob/kernel.py", "policies/", "verification/", "bootstrap/"],
}

# A gate that always passes and one that touches nothing in the repository.
PASSING_GATES = {
    "schema": "ourob.gates.v1",
    "gates": [{"name": "compileall", "command": ["python", "-m", "compileall", "-q", "ouroboros"], "required": True}],
}


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def make_repo(root: Path, *, gates: dict | None = None, constitution: dict | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    write_json(root / "policies" / "constitution.json", constitution or CONSTITUTION)
    write_json(root / "verification" / "gates.json", gates or PASSING_GATES)
    write_json(root / "skills" / "manifest.json", {"schema": "ourob.skills.v1", "capabilities": []})
    target = root / "ouroboros" / "M0" / "ourob"
    shutil.copytree(OUROB_PACKAGE, target, ignore=shutil.ignore_patterns("__pycache__"))
    (root / "README.md").write_text("fixture repository\n", encoding="utf-8")
    return root


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return make_repo(tmp_path / "repo")


@pytest.fixture
def failing_repo(tmp_path: Path) -> Path:
    gates = {
        "schema": "ourob.gates.v1",
        "gates": [{"name": "always_fail", "command": ["python", "-c", "import sys; sys.exit(3)"], "required": True}],
    }
    return make_repo(tmp_path / "repo", gates=gates)


@pytest.fixture
def journal_path(tmp_path: Path) -> Path:
    return tmp_path / "state" / "journal.jsonl"


@pytest.fixture(autouse=True)
def _isolate_capability_modules():
    """Capability modules are registered under ``ourob_capability.*``; drop them between tests."""
    yield
    for name in [m for m in sys.modules if m.startswith("ourob_capability")]:
        sys.modules.pop(name, None)
