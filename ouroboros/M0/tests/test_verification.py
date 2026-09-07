import pytest

from ourob.evidence import VerificationEvidence, capture_evidence
from ourob.generation import repository_generation
from ourob.model import Run, RunState, VerificationResult, VerificationStatus
from ourob.verify import (Gate, GateConfigurationError, Verifier, gate_set_digest, load_gates,
                          parse_gates, validate_gates)

PASS = Gate("ok", ("python", "-c", "pass"))
FAIL = Gate("bad", ("python", "-c", "import sys; sys.exit(1)"))


def test_verifier_binds_generation_and_epoch(repo):
    report = Verifier(repo, (PASS,)).verify(epoch=7)
    assert report.passed
    assert report.generation == repository_generation(repo).id
    assert all(r.epoch == 7 for r in report.results)
    assert report.gate_set_digest == gate_set_digest((PASS,))


def test_failed_gate_is_fail_not_exception(repo):
    report = Verifier(repo, (PASS, FAIL)).verify(epoch=0)
    assert not report.passed
    assert {r.gate: r.status for r in report.results} == {"ok": VerificationStatus.PASS, "bad": VerificationStatus.FAIL}


def test_missing_executable_blocks_required_gate(repo):
    report = Verifier(repo, (Gate("ghost", ("definitely-not-a-binary-xyz",)),)).verify(0)
    assert report.results[0].status is VerificationStatus.BLOCKED


def test_mutation_during_verification_is_stale(repo):
    gate = Gate("mutate", ("python", "-c", "open('README.md','a').write('x')"))
    report = Verifier(repo, (gate,)).verify(0)
    assert all(r.status is VerificationStatus.STALE for r in report.results)


@pytest.mark.parametrize("gates", [
    (),
    (Gate("a", ("python",)), Gate("a", ("python",))),
    (Gate("", ("python",)),),
    (Gate("a\nb", ("python",)),),
    (Gate("a", ()),),
    (Gate("a", ("python", "")),),
])
def test_invalid_gate_configurations_rejected(gates):
    with pytest.raises(GateConfigurationError):
        validate_gates(gates)


def test_gate_contract_is_order_independent_and_content_sensitive():
    a, b = Gate("a", ("python", "-m", "x")), Gate("b", ("python", "-m", "y"), required=False)
    assert gate_set_digest((a, b)) == gate_set_digest((b, a))
    assert gate_set_digest((a, b)) != gate_set_digest((a, Gate("b", ("python", "-m", "y"), required=True)))
    assert gate_set_digest((a,)) != gate_set_digest((Gate("a", ("python", "-m", "z")),))
    # argument boundaries are preserved
    assert gate_set_digest((Gate("a", ("echo", "x y")),)) != gate_set_digest((Gate("a", ("echo", "x", "y")),))


def test_gates_file_schema_enforced(tmp_path):
    with pytest.raises(GateConfigurationError):
        parse_gates({"schema": "nope", "gates": []})
    with pytest.raises(GateConfigurationError):
        parse_gates({"schema": "ourob.gates.v1", "gates": [{"name": "a", "command": "python"}]})
    p = tmp_path / "g.json"
    p.write_text('{"schema":"ourob.gates.v1","gates":[{"name":"a","command":["python","-c","pass"]}]}')
    assert load_gates(p)[0].name == "a"


# --- evidence ------------------------------------------------------------

def result(gate, gen="g" * 64, epoch=1, status=VerificationStatus.PASS):
    return VerificationResult(gate, status, "e" * 64, gen, epoch, "")


def make_run(gen="g" * 64, epoch=1):
    return Run("run", "task", RunState.VERIFYING, gen, epoch)


def test_evidence_digest_roundtrip_and_tamper_detection():
    ev = capture_evidence(make_run(), [result("a"), result("b")], ["a", "b"], "gs")
    assert ev.integrity_valid() and ev.passed
    restored = VerificationEvidence.from_record(ev.to_record())
    assert restored == ev
    record = ev.to_record()
    record["results"][0]["status"] = "FAIL"
    with pytest.raises(ValueError, match="digest"):
        VerificationEvidence.from_record(record)


def test_evidence_requires_every_required_gate():
    ev = capture_evidence(make_run(), [result("a")], ["a", "b"], "gs")
    assert ev.integrity_valid() and not ev.complete and not ev.passed


def test_evidence_rejects_extra_or_duplicate_gates():
    assert not capture_evidence(make_run(), [result("a"), result("a")], ["a"], "gs").passed
    assert not capture_evidence(make_run(), [result("a"), result("z")], ["a"], "gs").passed


def test_evidence_rejects_stale_generation_or_epoch():
    assert not capture_evidence(make_run(), [result("a", gen="h" * 64)], ["a"], "gs").passed
    assert not capture_evidence(make_run(), [result("a", epoch=0)], ["a"], "gs").passed


def test_evidence_rejects_non_pass():
    assert not capture_evidence(make_run(), [result("a", status=VerificationStatus.STALE)], ["a"], "gs").passed
    assert not capture_evidence(make_run(), [], [], "gs").passed
