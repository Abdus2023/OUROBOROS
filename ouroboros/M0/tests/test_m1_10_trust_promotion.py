from pathlib import Path

from ourob.evidence import capture_evidence
from ourob.model import Run, RunState, VerificationResult, VerificationStatus
from ourob.promotion import PromotionAuthority


def _evidence(run):
    result = VerificationResult("gate", VerificationStatus.PASS, "e", run.generation, run.verification_epoch, "ok")
    return capture_evidence(run, (result,), ("gate",), "contract")


def test_authoritative_promotion_requires_authenticated_external_trust(tmp_path):
    run = Run("r1", "task", state=RunState.VERIFIED, generation="g", verification_epoch=0)
    evidence = _evidence(run)
    authority = PromotionAuthority(require_trust=True)
    denied = authority.authorize(run, evidence, Path(tmp_path), "contract", trust_authenticated=False)
    assert not denied.allowed
    assert "external trust" in denied.reason


def test_authoritative_promotion_accepts_authenticated_external_trust(monkeypatch, tmp_path):
    run = Run("r1", "task", state=RunState.VERIFIED, generation="g", verification_epoch=0)
    evidence = _evidence(run)
    monkeypatch.setattr("ourob.promotion.repository_generation", lambda _: type("G", (), {"id": "g"})())
    authority = PromotionAuthority(require_trust=True)
    allowed = authority.authorize(run, evidence, Path(tmp_path), "contract", trust_authenticated=True)
    assert allowed.allowed
