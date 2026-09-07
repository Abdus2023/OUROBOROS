"""M0.14/M0.15 — the closed self-extension conformance proof.

OUROBOROS writes a new capability and its manifest entry *through the kernel*,
verifies, promotes, cold-boots from the modified repository, discovers the
capability from repository state alone, and executes it.
"""

from ourob.bootstrap import Bootstrap
from ourob.journal import Journal
from ourob.model import ActionKind, Plan, RunState
from ourob.planner import AddCapabilityPlanner
from ourob.recovery import recover_from_journal


def test_runtime_extends_its_own_capability_surface(repo, journal_path):
    generation_before = Bootstrap(repo).cold_start().generation_after
    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    assert not kernel.skills.has("greet")

    plan = AddCapabilityPlanner(repo, "greet").propose("Add a greet capability")
    run = kernel.run_plan("self-extend", plan)

    assert run.state is RunState.PROMOTED
    assert run.generation != generation_before
    assert run.verification_epoch == 2  # two mutations

    # Cold bootstrap from the *modified repository*, not from the running process.
    fresh = Bootstrap(repo).cold_start()
    assert fresh.trusted
    assert fresh.generation_after == run.generation
    assert [c.name for c in fresh.capabilities] == ["greet"]
    assert fresh.registry.has("greet")
    assert fresh.registry.call("greet", {"name": "World"}, ActionKind.EXECUTE) == "Hello, World!"

    # The new capability is usable by the next-generation kernel.
    next_kernel = Bootstrap(repo).kernel(fresh, journal=Journal(journal_path))
    assert next_kernel.skills.has("greet")

    # The whole lifecycle is durably recoverable.
    recovered = recover_from_journal(journal_path, "self-extend")
    assert recovered.state is RunState.PROMOTED
    assert recovered.evidence is not None


def test_self_extension_cannot_touch_trust_boundary(repo, journal_path):
    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    plan = AddCapabilityPlanner(repo, "greet").propose("Add greet")
    # Tamper with the plan so the second action targets the verifier config.
    poisoned = Plan(plan.task, (plan.actions[0], plan.actions[1].__class__(
        plan.actions[1].id, plan.actions[1].kind, plan.actions[1].skill,
        {"path": "verification/gates.json", "content": '{"schema":"ourob.gates.v1","gates":[{"name":"noop","command":["true"]}]}'},
    )))
    run = kernel.run_plan("poison", poisoned)
    assert run.state is RunState.BLOCKED
    assert "noop" not in (repo / "verification" / "gates.json").read_text()
    assert not Bootstrap(repo).cold_start().registry.has("greet")  # never declared


def test_second_generation_can_extend_again(repo, journal_path):
    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    assert kernel.run_plan("g1", AddCapabilityPlanner(repo, "greet").propose("add greet")).state is RunState.PROMOTED
    kernel2 = Bootstrap(repo).kernel(journal=Journal(journal_path))
    assert kernel2.skills.has("greet")
    assert kernel2.run_plan("g2", AddCapabilityPlanner(repo, "salute", "Salutations").propose("add salute")).state is RunState.PROMOTED
    final = Bootstrap(repo).cold_start()
    assert final.trusted and sorted(c.name for c in final.capabilities) == ["greet", "salute"]
    assert final.registry.call("salute", {"name": "Ada"}, ActionKind.EXECUTE) == "Salutations, Ada!"
