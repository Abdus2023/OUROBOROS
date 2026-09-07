"""Immutable verification evidence (M0.18–M0.22, M1.3).

``VerificationEvidence`` binds a run, a repository generation, a verification
epoch, the complete set of required gates, the gate-contract digest and every
gate result under a single SHA-256 digest. Promotion consumes exactly one
evidence object; it never reconstructs authority from mutable ``Run`` state.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable

from .generation import repository_generation
from .model import Run, VerificationResult, VerificationStatus

EVIDENCE_VERSION = "ourob.evidence.v1"


@dataclass(frozen=True)
class VerificationEvidence:
    run_id: str
    generation: str
    epoch: int
    results: tuple[VerificationResult, ...]
    required_gates: tuple[str, ...]
    gate_set_digest: str
    digest: str

    # -- semantic validity -----------------------------------------------

    @property
    def complete(self) -> bool:
        required = tuple(sorted(set(self.required_gates)))
        actual = tuple(sorted(r.gate for r in self.results))
        return bool(required) and actual == required and len(actual) == len(set(actual))

    @property
    def passed(self) -> bool:
        return self.complete and all(
            r.status is VerificationStatus.PASS and r.generation == self.generation and r.epoch == self.epoch
            for r in self.results
        )

    def is_current(self, repo_root: Path) -> bool:
        return repository_generation(repo_root).id == self.generation

    # -- integrity -------------------------------------------------------

    def canonical_bytes(self) -> bytes:
        header = "\0".join(
            (
                EVIDENCE_VERSION,
                self.run_id,
                self.generation,
                str(self.epoch),
                self.gate_set_digest,
                "\x1f".join(sorted(self.required_gates)),
            )
        )
        body = "\n".join(
            "\0".join((r.gate, r.status.value, r.evidence_id, r.generation, str(r.epoch), r.message))
            for r in sorted(self.results, key=lambda x: x.gate)
        )
        return (header + "\n" + body + "\n").encode("utf-8")

    def recompute_digest(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()

    def integrity_valid(self) -> bool:
        return bool(self.digest) and self.digest == self.recompute_digest()

    # -- durability ------------------------------------------------------

    def to_record(self) -> dict[str, Any]:
        return {
            "version": EVIDENCE_VERSION,
            "run_id": self.run_id,
            "generation": self.generation,
            "epoch": self.epoch,
            "required_gates": list(self.required_gates),
            "gate_set_digest": self.gate_set_digest,
            "results": [r.to_record() for r in self.results],
            "digest": self.digest,
        }

    @classmethod
    def from_record(cls, record: Any) -> "VerificationEvidence":
        if not isinstance(record, dict):
            raise ValueError("evidence record must be an object")
        if record.get("version") != EVIDENCE_VERSION:
            raise ValueError(f"unsupported evidence version: {record.get('version')!r}")
        run_id = record.get("run_id")
        generation = record.get("generation")
        epoch = record.get("epoch")
        required = record.get("required_gates")
        gate_digest = record.get("gate_set_digest")
        results = record.get("results")
        digest = record.get("digest")
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("evidence requires a run id")
        if not isinstance(generation, str) or not generation:
            raise ValueError("evidence requires a generation")
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
            raise ValueError("evidence epoch must be a non-negative integer")
        if not isinstance(required, list) or not all(isinstance(g, str) and g for g in required):
            raise ValueError("evidence required_gates must be a list of gate names")
        if not isinstance(gate_digest, str) or not gate_digest:
            raise ValueError("evidence requires a gate_set_digest")
        if not isinstance(results, list):
            raise ValueError("evidence results must be a list")
        if not isinstance(digest, str) or not digest:
            raise ValueError("evidence requires a digest")
        evidence = cls(
            run_id, generation, epoch,
            tuple(VerificationResult.from_record(r) for r in results),
            tuple(required), gate_digest, digest,
        )
        if not evidence.integrity_valid():
            raise ValueError("evidence digest does not match its content")
        return evidence


def capture_evidence(
    run: Run,
    results: Iterable[VerificationResult],
    required_gates: Iterable[str],
    gate_set_digest: str,
) -> VerificationEvidence:
    draft = VerificationEvidence(
        run.id, run.generation, run.verification_epoch, tuple(results), tuple(required_gates), gate_set_digest, ""
    )
    return VerificationEvidence(
        draft.run_id, draft.generation, draft.epoch, draft.results,
        draft.required_gates, draft.gate_set_digest, draft.recompute_digest(),
    )
