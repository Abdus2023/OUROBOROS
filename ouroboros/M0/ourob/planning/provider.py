"""Provider boundary for model-backed planning (M2.2).

Providers are deliberately unaware of the kernel, filesystem, policy engine,
verification system, and promotion machinery. They only receive a serialized
planning prompt and return untrusted text.
"""
from __future__ import annotations

from typing import Protocol


class PlannerProvider(Protocol):
    def generate(self, prompt: str) -> str:
        """Return untrusted model output; never return an executable Action."""


class UnavailableProvider:
    """Deterministic provider used to exercise model-unavailable behavior."""

    def generate(self, prompt: str) -> str:
        raise RuntimeError("planning provider unavailable")
