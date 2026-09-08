"""Deterministic replay for recorded planning responses (M2.9).

Replay verifies the exact planning envelope before returning a recorded
response. It never bypasses the normal PlanningBridge or Kernel boundary.
"""
from __future__ import annotations

from dataclasses import dataclass

from .model import PlanningRequest, PlanningResponse
from .validator import canonical_response, digest, request_digest


@dataclass(frozen=True)
class PlanningReplay:
    request: PlanningRequest
    response: PlanningResponse
    request_digest: str
    response_digest: str

    @classmethod
    def record(cls, request: PlanningRequest, response: PlanningResponse) -> "PlanningReplay":
        return cls(request, response, request_digest(request), digest(response))

    def verify(self, request: PlanningRequest) -> None:
        if request_digest(request) != self.request_digest:
            raise ValueError("replay request identity mismatch")
        if request != self.request:
            raise ValueError("replay request differs from recorded request")

    def replay(self, request: PlanningRequest) -> PlanningResponse:
        self.verify(request)
        if digest(self.response) != self.response_digest:
            raise ValueError("recorded planning response digest mismatch")
        # Return the recorded immutable response only after both identities pass.
        return self.response


__all__ = ["PlanningReplay"]
