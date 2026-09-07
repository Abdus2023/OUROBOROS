"""Verification engine and canonical gate contract (M0.8, M0.21–M0.23).

The verifier never returns a bare boolean. Each gate yields a
``VerificationResult`` bound to the repository generation and verification
epoch it was executed against. The complete gate configuration is
content-addressed via ``gate_set_digest`` so a gate definition cannot change
silently between verification and promotion.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable

from .generation import repository_generation
from .model import VerificationResult, VerificationStatus

GATES_SCHEMA = "ourob.gates.v1"
GATE_CONTRACT_VERSION = "ouroboros.gate-contract.v1"
DEFAULT_GATE_TIMEOUT = 300


class GateConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class Gate:
    name: str
    command: tuple[str, ...]
    required: bool = True

    def canonical(self) -> dict[str, Any]:
        return {"name": self.name, "required": bool(self.required), "command": list(self.command)}


@dataclass(frozen=True)
class VerificationReport:
    generation: str
    epoch: int
    results: tuple[VerificationResult, ...]
    gate_set_digest: str

    @property
    def passed(self) -> bool:
        return bool(self.results) and all(r.status is VerificationStatus.PASS for r in self.results)

    @property
    def required_passed(self) -> bool:
        return bool(self.results) and all(
            r.status is VerificationStatus.PASS for r in self.results if r.gate in self._required
        )

    @property
    def _required(self) -> frozenset[str]:
        return frozenset(r.gate for r in self.results)


def _python_command(command: Iterable[str]) -> tuple[str, ...]:
    """Pin ``python`` to the running interpreter so gates run in-environment."""
    parts = tuple(command)
    if parts and parts[0] in {"python", "python3"}:
        return (sys.executable,) + parts[1:]
    return parts


def validate_gates(gates: Iterable[Gate]) -> tuple[Gate, ...]:
    gates = tuple(gates)
    if not gates:
        raise GateConfigurationError("at least one gate is required")
    names = [g.name for g in gates]
    for name in names:
        if not isinstance(name, str) or not name or "\0" in name or "\n" in name or name != name.strip():
            raise GateConfigurationError(f"invalid gate name: {name!r}")
    if len(names) != len(set(names)):
        raise GateConfigurationError("duplicate gate names are not permitted")
    for gate in gates:
        if not gate.command or any(not isinstance(part, str) or not part for part in gate.command):
            raise GateConfigurationError(f"invalid gate command for {gate.name}")
        if not isinstance(gate.required, bool):
            raise GateConfigurationError(f"gate.required must be boolean for {gate.name}")
    return gates


def canonical_gate_contract(gates: Iterable[Gate]) -> bytes:
    validated = validate_gates(gates)
    payload = {
        "contract": GATE_CONTRACT_VERSION,
        "gates": [g.canonical() for g in sorted(validated, key=lambda g: g.name)],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def gate_set_digest(gates: Iterable[Gate]) -> str:
    return sha256(canonical_gate_contract(gates)).hexdigest()


def parse_gates(raw: Any) -> tuple[Gate, ...]:
    if not isinstance(raw, dict):
        raise GateConfigurationError("gates document must be a JSON object")
    if raw.get("schema") != GATES_SCHEMA:
        raise GateConfigurationError(f"unsupported gates schema: {raw.get('schema')!r}")
    entries = raw.get("gates")
    if not isinstance(entries, list) or not entries:
        raise GateConfigurationError("gates document must declare a non-empty gates list")
    gates: list[Gate] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) - {"name", "command", "required"}:
            raise GateConfigurationError(f"invalid gate entry: {entry!r}")
        command = entry.get("command")
        if not isinstance(command, list):
            raise GateConfigurationError(f"gate command must be a list: {entry!r}")
        gates.append(Gate(str(entry.get("name", "")), tuple(command), bool(entry.get("required", True))))
    return validate_gates(gates)


def load_gates(path: Path) -> tuple[Gate, ...]:
    path = Path(path)
    if not path.is_file():
        raise GateConfigurationError(f"gates file not found: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GateConfigurationError(f"gates file is not valid JSON: {exc.msg}") from exc
    return parse_gates(raw)


DEFAULT_GATES: tuple[Gate, ...] = (Gate("compileall", ("python", "-m", "compileall", "-q", "ouroboros")),)


class Verifier:
    def __init__(self, repo_root: Path, gates: Iterable[Gate] = DEFAULT_GATES, timeout: int = DEFAULT_GATE_TIMEOUT):
        self.repo_root = Path(repo_root).resolve()
        self.gates = validate_gates(gates)
        self.timeout = timeout

    @property
    def required_gate_names(self) -> tuple[str, ...]:
        return tuple(sorted(g.name for g in self.gates if g.required))

    @property
    def gate_names(self) -> tuple[str, ...]:
        return tuple(sorted(g.name for g in self.gates))

    @property
    def gate_set_digest(self) -> str:
        return gate_set_digest(self.gates)

    def _run_gate(self, gate: Gate) -> tuple[VerificationStatus, str]:
        try:
            completed = subprocess.run(
                _python_command(gate.command),
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            return (VerificationStatus.BLOCKED if gate.required else VerificationStatus.NOT_RUN), str(exc)
        except subprocess.TimeoutExpired as exc:
            return VerificationStatus.FAIL, f"timeout after {exc.timeout}s"
        status = VerificationStatus.PASS if completed.returncode == 0 else VerificationStatus.FAIL
        message = (completed.stdout + completed.stderr).strip()
        return status, message[-4000:]

    def verify(self, epoch: int) -> VerificationReport:
        generation = repository_generation(self.repo_root).id
        results: list[VerificationResult] = []
        for gate in self.gates:
            status, message = self._run_gate(gate)
            evidence_id = sha256(
                f"{generation}\0{epoch}\0{gate.name}\0{status.value}\0{message}".encode("utf-8")
            ).hexdigest()
            results.append(VerificationResult(gate.name, status, evidence_id, generation, epoch, message))
        if repository_generation(self.repo_root).id != generation:
            results = [
                VerificationResult(
                    r.gate, VerificationStatus.STALE, r.evidence_id, generation, epoch,
                    "repository changed during verification",
                )
                for r in results
            ]
        return VerificationReport(generation, epoch, tuple(results), self.gate_set_digest)
