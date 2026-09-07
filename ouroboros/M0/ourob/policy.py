"""Policy engine and mutation classification (M0.4 / M0.6).

Policy *data* lives in ``policies/constitution.json``; the *interpreter*
lives here, inside the trusted kernel package. Ordinary mutations may touch
capability and ordinary surfaces. Kernel, bootstrap, policy and verifier
surfaces require an elevated authorization class that M0 does not grant via
the ordinary mutation path.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any

from .model import Action, ActionKind

CONSTITUTION_SCHEMA = "ourob.constitution.v1"
MUTATING_KINDS: frozenset[ActionKind] = frozenset({ActionKind.WRITE, ActionKind.EDIT})


class MutationClass(StrEnum):
    ORDINARY = "ORDINARY"
    CAPABILITY = "CAPABILITY"
    POLICY = "POLICY"
    VERIFIER = "VERIFIER"
    KERNEL = "KERNEL"
    BOOTSTRAP = "BOOTSTRAP"


ELEVATED_CLASSES: frozenset[MutationClass] = frozenset(
    {MutationClass.POLICY, MutationClass.VERIFIER, MutationClass.KERNEL, MutationClass.BOOTSTRAP}
)

# Surfaces protected by the kernel regardless of constitution content.
# The constitution may add protected surfaces; it may never remove these.
BUILTIN_PROTECTED_PREFIXES: dict[MutationClass, tuple[str, ...]] = {
    MutationClass.KERNEL: ("ourob/kernel/", "ourob/kernel.py", "ourob/state.py", "ourob/model.py"),
    MutationClass.BOOTSTRAP: ("bootstrap/", "ourob/bootstrap.py", "ourob/generation.py", "ourob/recovery.py", "ourob/journal.py", "ourob/trust.py", "ourob/signed_trust.py"),
    MutationClass.POLICY: ("policies/", "ourob/policy.py"),
    MutationClass.VERIFIER: ("verification/", "ourob/verify.py", "ourob/evidence.py", "ourob/promotion.py"),
}

CAPABILITY_PREFIXES: tuple[str, ...] = ("skills/", "ourob/skills.py")


class ConstitutionError(ValueError):
    pass


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    mutation_class: MutationClass


@dataclass(frozen=True)
class Constitution:
    schema: str
    mode: str
    invariants: tuple[str, ...]
    protected_surfaces: tuple[str, ...]
    raw: dict[str, Any] = field(default_factory=dict, compare=False)

    @property
    def fail_closed(self) -> bool:
        return self.mode == "fail_closed"


def load_constitution(path: Path) -> Constitution:
    path = Path(path)
    if not path.is_file():
        raise ConstitutionError(f"constitution not found: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConstitutionError(f"constitution is not valid JSON: {exc.msg}") from exc
    return parse_constitution(raw)


def parse_constitution(raw: Any) -> Constitution:
    if not isinstance(raw, dict):
        raise ConstitutionError("constitution must be a JSON object")
    if raw.get("schema") != CONSTITUTION_SCHEMA:
        raise ConstitutionError(f"unsupported constitution schema: {raw.get('schema')!r}")
    mode = raw.get("mode")
    if mode != "fail_closed":
        raise ConstitutionError(f"constitution mode must be fail_closed, found {mode!r}")
    invariants = raw.get("invariants")
    if not isinstance(invariants, list) or not invariants or not all(isinstance(i, str) and i for i in invariants):
        raise ConstitutionError("constitution must declare a non-empty list of invariant identifiers")
    surfaces = raw.get("protected_surfaces", [])
    if not isinstance(surfaces, list) or not all(isinstance(s, str) and s for s in surfaces):
        raise ConstitutionError("protected_surfaces must be a list of non-empty strings")
    return Constitution(CONSTITUTION_SCHEMA, mode, tuple(invariants), tuple(surfaces), raw)


def normalize_repo_path(path: str) -> str:
    text = PurePosixPath(str(path).replace("\\", "/")).as_posix()
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def _matches(normalized: str, prefix: str) -> bool:
    if prefix.endswith("/"):
        return normalized.startswith(prefix) or normalized == prefix.rstrip("/")
    return normalized == prefix or normalized.startswith(prefix + "/")


class PolicyEngine:
    def __init__(self, constitution: Constitution | None = None, package_prefix: str = ""):
        """``package_prefix`` is the repository-relative directory containing the
        ``ourob`` package (e.g. ``ouroboros/M0``). Paths are matched both with and
        without it so protection holds regardless of where the package sits."""
        self.constitution = constitution
        self.package_prefix = normalize_repo_path(package_prefix).rstrip("/")
        self._extra_protected: tuple[str, ...] = tuple(
            normalize_repo_path(s) for s in (constitution.protected_surfaces if constitution else ())
        )

    def _candidates(self, normalized: str) -> tuple[str, ...]:
        if self.package_prefix and normalized.startswith(self.package_prefix + "/"):
            return (normalized, normalized[len(self.package_prefix) + 1 :])
        return (normalized,)

    def classify(self, path: str) -> MutationClass:
        normalized = normalize_repo_path(path)
        for candidate in self._candidates(normalized):
            for mutation_class, prefixes in BUILTIN_PROTECTED_PREFIXES.items():
                if any(_matches(candidate, prefix) for prefix in prefixes):
                    return mutation_class
        for surface in self._extra_protected:
            if _matches(normalized, surface):
                return self._class_for_surface(surface)
        for candidate in self._candidates(normalized):
            if any(_matches(candidate, prefix) for prefix in CAPABILITY_PREFIXES):
                return MutationClass.CAPABILITY
        return MutationClass.ORDINARY

    @staticmethod
    def _class_for_surface(surface: str) -> MutationClass:
        lowered = surface.lower()
        if "kernel" in lowered:
            return MutationClass.KERNEL
        if "bootstrap" in lowered:
            return MutationClass.BOOTSTRAP
        if "verif" in lowered:
            return MutationClass.VERIFIER
        return MutationClass.POLICY

    def evaluate(self, action: Action) -> PolicyDecision:
        if action.kind not in MUTATING_KINDS:
            return PolicyDecision(True, "non-mutating action", MutationClass.ORDINARY)
        path = str(action.arguments.get("path", ""))
        if not path:
            return PolicyDecision(False, "mutation requires a repository-relative path", MutationClass.ORDINARY)
        if PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts:
            return PolicyDecision(False, f"mutation path must be repository-relative: {path}", MutationClass.ORDINARY)
        mutation_class = self.classify(path)
        if mutation_class in ELEVATED_CLASSES:
            return PolicyDecision(
                False, f"elevated authorization required for {mutation_class.value} mutation: {path}", mutation_class
            )
        return PolicyDecision(True, f"{mutation_class.value.lower()} repository mutation allowed", mutation_class)
