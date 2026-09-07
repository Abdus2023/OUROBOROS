import dataclasses

from ourob.evidence import capture_evidence
from ourob.generation import repository_generation
from ourob.model import Run, RunState, VerificationResult, VerificationStatus
from ourob.promotion import PromotionAuthority

GATES = "gate-contract-digest"


def verified_run(repo):
    return Run("run", "task", RunState.VERIFIED, repository_generation(repo).id, 2)


def evidence_for(run, status=VerificationStatus.PASS, gates=GATES, epoch=None, gen=None):
    epoch = run.verification_epoch if epoch is None else epoch
    gen = run.generation if gen is None else gen
    results = [VerificationResult("compileall", status, "e" * 64, gen, epoch)]
    return capture_evidence(dataclasses.replace(run, generation=gen, verification_epoch=epoch), results, ["compileall"], gates)


def test_valid_evidence_authorizes(repo):
    run = verified_run(repo)
    assert PromotionAuthority().authorize(run, evidence_for(run), repo, GATES).allowed


def test_wrong_state_denied(repo):
    run = verified_run(repo)
    ev = evidence_for(run)
    run.state = RunState.OBSERVED
    assert not PromotionAuthority().authorize(run, ev, repo, GATES).allowed


def test_missing_evidence_denied(repo):
    assert "no verification evidence" in PromotionAuthority().authorize(verified_run(repo), None, repo, GATES).reason


def test_other_run_evidence_denied(repo):
    run = verified_run(repo)
    ev = evidence_for(dataclasses.replace(run, id="other"))
    assert "another run" in PromotionAuthority().authorize(run, ev, repo, GATES).reason


def test_tampered_evidence_denied(repo):
    run = verified_run(repo)
    ev = dataclasses.replace(evidence_for(run), epoch=run.verification_epoch)  # digest unchanged
    ev = dataclasses.replace(ev, digest="0" * 64)
    assert "digest is invalid" in PromotionAuthority().authorize(run, ev, repo, GATES).reason


def test_changed_gate_contract_denied(repo):
    run = verified_run(repo)
    assert "gate contract" in PromotionAuthority().authorize(run, evidence_for(run), repo, "different").reason


def test_stale_epoch_denied(repo):
    run = verified_run(repo)
    ev = evidence_for(run, epoch=1)
    assert "epoch" in PromotionAuthority().authorize(run, ev, repo, GATES).reason


def test_failed_gate_denied(repo):
    run = verified_run(repo)
    assert "not all PASS" in PromotionAuthority().authorize(run, evidence_for(run, VerificationStatus.FAIL), repo, GATES).reason


def test_repository_changed_before_promotion_denied(repo):
    run = verified_run(repo)
    ev = evidence_for(run)
    (repo / "README.md").write_text("mutated after verification\n")
    assert "changed before promotion" in PromotionAuthority().authorize(run, ev, repo, GATES).reason
