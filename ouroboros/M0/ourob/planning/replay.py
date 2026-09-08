"""Deterministic replay for recorded planning responses (M2.9).

Replay verifies the complete planning envelope before returning a recorded
response. It never bypasses the normal PlanningBridge or Kernel boundary.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .context import PlanningContext
from .model import PlanningRequest, PlanningResponse
from .validator import digest, request_digest


def canonical_context(context: PlanningContext) -> str:
    """Return deterministic JSON for the immutable planning context."""
    payload = {
        "repository_id": context.repository_id,
        "generation": context.generation,
        "mutation_epoch": context.mutation_epoch,
        "run_id": context.run_id,
        "facts": [
            {"value": fact.value, "source": fact.source} for fact in context.facts
        ],
        "constraints": list(context.constraints),
        "allowed_action_kinds": list(context.allowed_action_kinds),
        "required_gates": list(context.required_gates),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def context_digest(context: PlanningContext) -> str:
    return hashlib.sha256(canonical_context(context).encode("utf-8")).hexdigest()


def planning_envelope_digest(
    request: PlanningRequest,
    context: PlanningContext,
    response: PlanningResponse,
) -> str:
    """Hash request, context, and response identities as one replay envelope."""
    payload = {
        "request": request_digest(request),
        "context": context_digest(context),
        "response": digest(response),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PlanningReplay:
    request: PlanningRequest
    context: PlanningContext
    response: PlanningResponse
    request_digest: str
    context_digest: str
    response_digest: str
    envelope_digest: str

    @classmethod
    def record(
        cls,
        request: PlanningRequest,
        context: PlanningContext,
        response: PlanningResponse,
    ) -> "PlanningReplay":
        return cls(
            request,
            context,
            response,
            request_digest(request),
            context_digest(context),
            digest(response),
            planning_envelope_digest(request, context, response),
        )

    def verify(self, request: PlanningRequest, context: PlanningContext) -> None:
        if request_digest(request) != self.request_digest or request != self.request:
            raise ValueError("replay request identity mismatch")
        if context_digest(context) != self.context_digest or context != self.context:
            raise ValueError("replay context identity mismatch")
        if digest(self.response) != self.response_digest:
            raise ValueError("recorded planning response digest mismatch")
        if planning_envelope_digest(request, context, self.response) != self.envelope_digest:
            raise ValueError("replay planning envelope mismatch")

    def replay(self, request: PlanningRequest, context: PlanningContext) -> PlanningResponse:
        self.verify(request, context)
        return self.response


__all__ = [
    "PlanningReplay",
    "canonical_context",
    "context_digest",
    "planning_envelope_digest",
]
