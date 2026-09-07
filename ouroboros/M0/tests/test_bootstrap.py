import json

import pytest

from ourob.bootstrap import Bootstrap, BootstrapError, parse_skills_manifest
from ourob.generation import repository_generation
from ourob.model import ActionKind
from tests.conftest import write_json

GREET = '''
from ourob.model import ActionKind
from ourob.skills import Skill

def greet(action):
    return f"Hello, {action.arguments.get('name', 'World')}!"

def register(registry):
    registry.register(Skill("greet", frozenset({ActionKind.EXECUTE}), greet))
'''


def declare(repo, name, module):
    write_json(repo / "skills" / "manifest.json", {"schema": "ourob.skills.v1", "capabilities": [{"name": name, "module": module}]})


def test_cold_start_is_trusted_and_stable(repo):
    result = Bootstrap(repo).cold_start()
    assert result.trusted
    assert result.generation_before == result.generation_after == repository_generation(repo).id
    assert result.registry.names() == ("filesystem.read", "filesystem.search", "filesystem.write")


def test_missing_constitution_is_untrusted(repo):
    (repo / "policies" / "constitution.json").unlink()
    result = Bootstrap(repo).cold_start()
    assert not result.trusted and any("constitution" in e for e in result.errors)
    with pytest.raises(BootstrapError):
        Bootstrap(repo).kernel(result)


def test_permissive_constitution_is_untrusted(repo):
    write_json(repo / "policies" / "constitution.json",
               {"schema": "ourob.constitution.v1", "mode": "permissive", "invariants": ["X"]})
    assert not Bootstrap(repo).cold_start().trusted


def test_invalid_gates_untrusted(repo):
    write_json(repo / "verification" / "gates.json", {"schema": "ourob.gates.v1", "gates": []})
    assert not Bootstrap(repo).cold_start().trusted


def test_declared_capability_is_reconstructed(repo):
    (repo / "skills" / "greet.py").write_text(GREET)
    declare(repo, "greet", "skills/greet.py")
    result = Bootstrap(repo).cold_start()
    assert result.trusted
    assert result.registry.has("greet")
    assert result.registry.call("greet", {"name": "World"}, ActionKind.EXECUTE) == "Hello, World!"


def test_external_module_rejected(repo, tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text(GREET)
    declare(repo, "greet", "../outside.py")
    result = Bootstrap(repo).cold_start()
    assert not result.trusted and any("escapes repository root" in e for e in result.errors)


def test_missing_register_rejected(repo):
    (repo / "skills" / "greet.py").write_text("x = 1\n")
    declare(repo, "greet", "skills/greet.py")
    result = Bootstrap(repo).cold_start()
    assert any("does not export register" in e for e in result.errors)


def test_name_mismatch_rejected(repo):
    (repo / "skills" / "greet.py").write_text(GREET)
    declare(repo, "salute", "skills/greet.py")
    result = Bootstrap(repo).cold_start()
    assert any("expected exactly ['salute']" in e for e in result.errors)


def test_register_adding_two_skills_rejected(repo):
    (repo / "skills" / "greet.py").write_text(GREET.replace(
        'registry.register(Skill("greet"', 'registry.register(Skill("extra", frozenset({ActionKind.EXECUTE}), greet)); registry.register(Skill("greet"'))
    declare(repo, "greet", "skills/greet.py")
    assert not Bootstrap(repo).cold_start().trusted


@pytest.mark.parametrize("payload", [
    {"schema": "nope", "capabilities": []},
    {"schema": "ourob.skills.v1", "capabilities": [{"name": "greet"}]},
    {"schema": "ourob.skills.v1", "capabilities": [{"name": "bad name", "module": "skills/x.py"}]},
    {"schema": "ourob.skills.v1", "capabilities": [{"name": "a", "module": "skills/a.py"}, {"name": "a", "module": "skills/b.py"}]},
    {"schema": "ourob.skills.v1", "capabilities": [{"name": "a", "module": "skills/a.txt"}]},
])
def test_manifest_schema_enforced(payload):
    with pytest.raises(BootstrapError):
        parse_skills_manifest(payload)


def test_generation_change_during_bootstrap_is_untrusted(repo):
    mutating = GREET + "\nopen(__import__('pathlib').Path(__file__).parents[1] / 'README.md', 'a').write('!')\n"
    (repo / "skills" / "greet.py").write_text(mutating)
    declare(repo, "greet", "skills/greet.py")
    result = Bootstrap(repo).cold_start()
    assert not result.trusted
    assert any("changed during bootstrap" in e for e in result.errors)
