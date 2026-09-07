"""Deterministic serialization of planner context (M2.2)."""
from __future__ import annotations

from .context import PlanningContext


def build_prompt(context: PlanningContext, objective: str) -> str:
    """Build a bounded, provenance-labelled prompt from an immutable snapshot.

    Repository text is explicitly data, not instructions. The provider receives
    no authority-bearing objects and cannot alter the context snapshot.
    """
    lines = [
        "[SYSTEM-CONSTRAINT] Planner output is untrusted proposal data.",
        "[SYSTEM-CONSTRAINT] Never claim verification or promotion authority.",
        f"[RUN] {context.run_id}",
        f"[REPOSITORY] {context.repository_id}",
        f"[GENERATION] {context.generation}",
        f"[MUTATION-EPOCH] {context.mutation_epoch}",
        f"[USER-TASK] {objective}",
        "[CONSTRAINTS]",
        *[f"- {item}" for item in context.constraints],
        "[ALLOWED-ACTIONS]",
        *[f"- {item}" for item in context.allowed_action_kinds],
        "[REQUIRED-GATES]",
        *[f"- {item}" for item in context.required_gates],
        "[REPOSITORY-OBSERVATIONS]",
    ]
    lines.extend(f"- [{fact.source}] {fact.value}" for fact in context.facts)
    return "\n".join(lines)
