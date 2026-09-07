import pytest

from ourob.bootstrap import Bootstrap
from ourob.journal import Journal
from ourob.kernel import Kernel, KernelError
from ourob.model import Action, ActionKind, EventName, Plan, RunState


def kernel_for(repo, journal_path):
    return Bootstrap(repo).kernel(journal=Journal(journal_path))


def write(aid, path, content="x\n"):
    return Action(aid, ActionKind.WRITE, "filesystem.write", {"path": path, "content": content})


def test_full_lifecycle_reaches_promoted(repo, journal_path):
    kernel = kernel_for(repo, journal_path)
    run = kernel.run_plan("run-1", Plan("write a note", (write("a1", "notes/hello.md", "hi\n"),)))
    assert run.state is RunState.PROMOTED
    assert (repo / "notes" / "hello.md").read_text() == "hi\n"
    assert run.verification_epoch == 1
    names = [e.name for e in Journal(journal_path).events()]
    assert names == [
        "RUN_CREATED", "RUN_PLANNED", "AUTHORIZATION_GRANTED", "ACTION_PROPOSED", "POLICY_ALLOWED",
        "ACTION_EXECUTED", "VERIFICATION_STARTED", "GATE_RESULT", "VERIFICATION_EVIDENCE_CAPTURED",
        "PROMOTION_AUTHORIZED", "PROMOTED",
    ]


def test_protected_surface_blocks_run(repo, journal_path):
    kernel = kernel_for(repo, journal_path)
    run = kernel.run_plan("run-2", Plan("hack kernel", (write("a1", "ouroboros/M0/ourob/kernel.py", "pwned"),)))
    assert run.state is RunState.BLOCKED
    assert "pwned" not in (repo / "ouroboros/M0/ourob/kernel.py").read_text()
    assert EventName.POLICY_DENIED.value in [e.name for e in Journal(journal_path).events()]
    with pytest.raises(KernelError):
        kernel.verify(run)


def test_unplanned_action_rejected(repo, journal_path):
    kernel = kernel_for(repo, journal_path)
    run = kernel.intake("run-3", "t")
    kernel.plan(run, Plan("t", (write("a1", "a.md"),)))
    kernel.authorize(run)
    with pytest.raises(KernelError, match="not part of the authorized plan"):
        kernel.execute(run, write("a2", "b.md"))
    with pytest.raises(KernelError, match="not part of the authorized plan"):
        kernel.execute(run, write("a1", "b.md"))  # same id, different content


def test_execute_requires_authorization(repo, journal_path):
    kernel = kernel_for(repo, journal_path)
    run = kernel.intake("run-4", "t")
    kernel.plan(run, Plan("t", (write("a1", "a.md"),)))
    with pytest.raises(KernelError, match="expected AUTHORIZED"):
        kernel.execute(run, write("a1", "a.md"))


def test_multi_action_run_reauthorizes_each_step(repo, journal_path):
    kernel = kernel_for(repo, journal_path)
    plan = Plan("two writes", (write("a1", "one.md"), write("a2", "two.md")))
    run = kernel.run_plan("run-5", plan)
    assert run.state is RunState.PROMOTED
    assert run.verification_epoch == 2
    names = [e.name for e in Journal(journal_path).events()]
    assert names.count("AUTHORIZATION_GRANTED") == 2


def test_failing_gate_fails_run_and_denies_promotion(failing_repo, journal_path):
    kernel = kernel_for(failing_repo, journal_path)
    run = kernel.run_plan("run-6", Plan("t", (write("a1", "a.md"),)))
    assert run.state is RunState.FAILED
    assert kernel.evidence_for(run) is None
    with pytest.raises(KernelError):
        kernel.promote(run)


def test_out_of_band_mutation_after_execution_fails_verification(repo, journal_path):
    kernel = kernel_for(repo, journal_path)
    run = kernel.intake("run-7", "t")
    kernel.plan(run, Plan("t", (write("a1", "a.md"),)))
    kernel.authorize(run)
    kernel.execute(run, write("a1", "a.md"))
    (repo / "sneaky.txt").write_text("outside the kernel\n")
    assert kernel.verify(run) is None
    assert run.state is RunState.FAILED


def test_new_action_invalidates_captured_evidence(repo, journal_path):
    kernel = kernel_for(repo, journal_path)
    run = kernel.intake("run-8", "t")
    kernel.plan(run, Plan("t", (write("a1", "a.md"), write("a2", "b.md"))))
    kernel.authorize(run)
    kernel.execute(run, write("a1", "a.md"))
    # verify is only legal from OBSERVED; emulate evidence then execute another action
    evidence = kernel.verify(run)
    assert evidence is not None and run.state is RunState.VERIFIED
    # VERIFIED cannot execute further actions - the state machine forbids it
    with pytest.raises(KernelError):
        kernel.execute(run, write("a2", "b.md"))


def test_planner_output_is_not_evidence(repo, journal_path):
    kernel = kernel_for(repo, journal_path)
    run = kernel.intake("run-9", "t")
    kernel.plan(run, Plan("t", (write("a1", "a.md"),)))
    # A plan claiming PASS is meaningless: state remains PLANNED, no evidence exists.
    assert run.state is RunState.PLANNED
    assert kernel.evidence_for(run) is None
    with pytest.raises(KernelError):
        kernel.promote(run)
