"""M1.7 — durable reconstruction of authenticated trust-state evolution.

The initial TrustStore is an external provisioning input. Repository journal
records may carry signed lifecycle statements, but they never become roots of
trust. Recovery verifies each statement against the currently authoritative
store and applies exactly one transition in journal order.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .journal import Journal, JournalIntegrityError
from .model import Event, EventName
from .signed_trust import SignedTrustError, TrustStore
from .trust_lifecycle import TrustTransition, apply_transition


class TrustRecoveryError(RuntimeError):
    pass


def trust_transition_event(statement: TrustTransition) -> Event:
    """Encode an already-authorized statement as a durable journal event.

    This helper does not authorize or apply the statement. The caller must
    provision the external trust store and use ``apply_transition`` (or the
    recovery path) to establish authority.
    """
    return Event(
        EventName.TRUST_TRANSITION_AUTHORIZED.value,
        data={"transition": statement.to_record()},
    )


def recover_trust_store(events: Iterable[Event], initial_store: TrustStore) -> TrustStore:
    """Replay authenticated trust transitions from an external root state.

    The input store is treated as the trust root for the replay. Every
    transition must be signed by the current ACTIVE key and must advance or
    preserve the exact epoch required by its operation. Unknown lifecycle
    events are ignored so a run journal can share the same log.
    """
    # Work on a fresh public-state copy so failed recovery cannot partially
    # mutate the caller's provisioned trust state.
    store = TrustStore.from_record(initial_store.to_record())
    seen_bindings: set[str] = set()
    for event in events:
        if event.name != EventName.TRUST_TRANSITION_AUTHORIZED.value:
            continue
        if event.run_id is not None or event.action_id is not None or event.generation is not None:
            raise TrustRecoveryError("trust transition event must not be run-scoped")
        try:
            statement = TrustTransition.from_record(event.data.get("transition"))
            if statement.binding_digest in seen_bindings:
                raise TrustRecoveryError("trust transition replay detected")
            apply_transition(statement, store)
        except (SignedTrustError, ValueError, TypeError) as exc:
            raise TrustRecoveryError(f"invalid authenticated trust transition: {exc}") from exc
        seen_bindings.add(statement.binding_digest)
    return store


def recover_trust_store_from_journal(journal_path: Path, initial_store: TrustStore) -> TrustStore:
    """Read a validated journal and reconstruct its authenticated trust state."""
    try:
        events = Journal(journal_path).events()
    except JournalIntegrityError as exc:
        raise TrustRecoveryError(f"journal integrity failure: {exc}") from exc
    return recover_trust_store(events, initial_store)
