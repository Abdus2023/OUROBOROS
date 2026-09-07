"""M1.7/M1.8 authenticated trust-state recovery and durable authorization."""
from __future__ import annotations
from pathlib import Path
from typing import Iterable
from .journal import Journal, JournalIntegrityError, JournalRecord
from .model import Event, EventName
from .signed_trust import SignedTrustError, TrustStore
from .trust_lifecycle import TrustTransition, apply_transition, verify_transition
class TrustRecoveryError(RuntimeError): pass

def trust_transition_event(statement: TrustTransition) -> Event:
    """Encode an immutable signed lifecycle authorization as a journal event."""
    return Event(EventName.TRUST_TRANSITION_AUTHORIZED.value, data={"transition": statement.to_record()})

def recover_trust_store(events: Iterable[Event], initial_store: TrustStore) -> TrustStore:
    """Replay authenticated trust transitions from an externally provisioned root."""
    store=TrustStore.from_record(initial_store.to_record())
    seen_bindings:set[str]=set()
    for event in events:
        if event.name != EventName.TRUST_TRANSITION_AUTHORIZED.value: continue
        if event.run_id is not None or event.action_id is not None or event.generation is not None:
            raise TrustRecoveryError("trust transition event must not be run-scoped")
        try:
            statement=TrustTransition.from_record(event.data.get("transition"))
            if statement.binding_digest in seen_bindings: raise TrustRecoveryError("trust transition replay detected")
            apply_transition(statement,store)
        except (SignedTrustError, ValueError, TypeError) as exc:
            raise TrustRecoveryError(f"invalid authenticated trust transition: {exc}") from exc
        seen_bindings.add(statement.binding_digest)
    return store

def recover_trust_store_from_journal(journal_path: Path, initial_store: TrustStore) -> TrustStore:
    try: events=Journal(journal_path).events()
    except JournalIntegrityError as exc: raise TrustRecoveryError(f"journal integrity failure: {exc}") from exc
    return recover_trust_store(events,initial_store)

def append_authorized_transition(journal: Journal, statement: TrustTransition, initial_store: TrustStore) -> JournalRecord:
    """Verify and durably append one trust transition as one serialized operation.

    The current trust state is reconstructed from the fully validated journal
    while the journal's append lock is held. Consequently two concurrent
    authorities cannot both pass verification against the same trust epoch
    and then append conflicting lifecycle statements.
    """
    event=trust_transition_event(statement)
    def validate(existing: list[JournalRecord]) -> None:
        try:
            current=recover_trust_store((record.event for record in existing),initial_store)
            verify_transition(statement,current)
            # Ensure the exact signed statement has not already been durable.
            if any(
                record.event.name == EventName.TRUST_TRANSITION_AUTHORIZED.value
                and record.event.data.get("transition") == statement.to_record()
                for record in existing
            ):
                raise TrustRecoveryError("trust transition replay detected")
        except TrustRecoveryError:
            raise
        except (SignedTrustError, ValueError, TypeError) as exc:
            raise TrustRecoveryError(f"invalid authenticated trust transition: {exc}") from exc
    return journal.append_checked(event,validate)
