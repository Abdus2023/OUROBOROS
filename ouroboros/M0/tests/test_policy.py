import json

import pytest

from ourob.model import Action, ActionKind
from ourob.policy import (ConstitutionError, MutationClass, PolicyEngine, load_constitution,
                          parse_constitution)


def write(path):
    return Action("a", ActionKind.WRITE, "filesystem.write", {"path": path, "content": ""})


@pytest.mark.parametrize("path,expected", [
    ("README.md", MutationClass.ORDINARY),
    ("docs/notes.md", MutationClass.ORDINARY),
    ("skills/greet.py", MutationClass.CAPABILITY),
    ("skills/manifest.json", MutationClass.CAPABILITY),
    ("ourob/kernel.py", MutationClass.KERNEL),
    ("ouroboros/M0/ourob/kernel.py", MutationClass.KERNEL),
    ("./ouroboros/M0/ourob/state.py", MutationClass.KERNEL),
    ("ouroboros/M0/ourob/policy.py", MutationClass.POLICY),
    ("policies/constitution.json", MutationClass.POLICY),
    ("verification/gates.json", MutationClass.VERIFIER),
    ("ouroboros/M0/ourob/verify.py", MutationClass.VERIFIER),
    ("ouroboros/M0/ourob/evidence.py", MutationClass.VERIFIER),
    ("bootstrap/manifest.json", MutationClass.BOOTSTRAP),
    ("ouroboros/M0/ourob/bootstrap.py", MutationClass.BOOTSTRAP),
    ("ouroboros/M0/ourob/journal.py", MutationClass.BOOTSTRAP),
])
def test_classification(path, expected):
    assert PolicyEngine(package_prefix="ouroboros/M0").classify(path) is expected


def test_ordinary_and_capability_mutations_allowed():
    engine = PolicyEngine(package_prefix="ouroboros/M0")
    assert engine.evaluate(write("notes.md")).allowed
    assert engine.evaluate(write("skills/greet.py")).allowed


@pytest.mark.parametrize("path", ["ouroboros/M0/ourob/kernel.py", "policies/constitution.json",
                                  "verification/gates.json", "ouroboros/M0/ourob/bootstrap.py"])
def test_elevated_surfaces_denied_on_ordinary_path(path):
    decision = PolicyEngine(package_prefix="ouroboros/M0").evaluate(write(path))
    assert not decision.allowed
    assert decision.mutation_class is not MutationClass.ORDINARY


def test_non_mutating_actions_pass():
    action = Action("a", ActionKind.READ, "filesystem.read", {"path": "ouroboros/M0/ourob/kernel.py"})
    assert PolicyEngine().evaluate(action).allowed


@pytest.mark.parametrize("path", ["", "/etc/passwd", "../outside.txt", "skills/../../x"])
def test_missing_absolute_or_escaping_paths_denied(path):
    assert not PolicyEngine().evaluate(write(path)).allowed


def test_constitution_extra_surfaces_are_protected(tmp_path):
    payload = {"schema": "ourob.constitution.v1", "mode": "fail_closed", "invariants": ["X"],
               "protected_surfaces": ["infra/"]}
    path = tmp_path / "c.json"
    path.write_text(json.dumps(payload))
    engine = PolicyEngine(load_constitution(path))
    assert not engine.evaluate(write("infra/deploy.sh")).allowed


@pytest.mark.parametrize("payload", [
    {"schema": "other", "mode": "fail_closed", "invariants": ["X"]},
    {"schema": "ourob.constitution.v1", "mode": "permissive", "invariants": ["X"]},
    {"schema": "ourob.constitution.v1", "mode": "fail_closed", "invariants": []},
    [],
])
def test_invalid_constitution_rejected(payload):
    with pytest.raises(ConstitutionError):
        parse_constitution(payload)
