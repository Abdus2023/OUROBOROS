"""M1.7/M1.8/M1.20 authenticated trust-state recovery and authorization."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .emergency_recovery import (
    EmergencyRecoveryAuthority,
    EmergencyRecoveryStatement,
    apply_emergency_recovery,
    verify_emergency_recovery,
)
from .journal import Journal, JournalIntegrityError, JournalRecord
from .model import Event, EventName
from .signed_trust import SignedTrustError, TrustStore
from .trust_lifecycle import TrustTransition, apply_transition, verify_transition


class TrustRecoveryError(RuntimeError):
    pass


def trust_transition_event(statement: TrustTransition) -> Event:
    """Encode an immutable signed lifecycle authorization as a journal event."""
    return Event(EventName.TRUST_TRANSITION_AUTHORIZED.value, data={"transition": statement.to_record()})


def emergency_recovery_event(statement: EmergencyRecoveryStatement) -> Event:
    """Encode an externally signed emergency authorization without run scope."""
    return Event(EventName.TRUST_EMERGENCY_RECOVERY_AUTHORIZED.value, data={"recovery": statement.to_record()})


def recover_trust_store(
    events: Iterable[Event],
    initial_store: TrustStore,
    recovery_authority: EmergencyRecoveryAuthority | None = None,
) -> TrustStore:
    """Replay authenticated trust transitions from external roots.

    Ordinary lifecycle events are authenticated by the current trust root.
    Emergency events require the separately provisioned recovery root; they are
    never accepted merely because repository state contains a recovery record.
    """
    store = TrustStore.from_record(initial_store.to_record())
    seen_bindings: set[str] = set()
    for event in events:
        if event.name == EventName.TRUST_TRANSITION_AUTHORIZED.value:
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
        elif event.name == EventName.TRUST_EMERGENCY_RECOVERY_AUTHORIZED.value:
            if event.run_id is not None or event.action_id is not None or event.generation is not None:
                raise TrustRecoveryError("emergency recovery event must not be run-scoped")
            if recovery_authority is None:
                raise TrustRecoveryError("emergency recovery requires an externally provisioned recovery authority")
            try:
                statement = EmergencyRecoveryStatement.from_record(event.data.get("recovery"))
                if statement.binding_digest in seen_bindings:
                    raise TrustRecoveryError("emergency recovery replay detected")
                apply_emergency_recovery(statement, store, recovery_authority)
            except (SignedTrustError, ValueError, TypeError) as exc:
                raise TrustRecoveryError(f"invalid authenticated emergency recovery: {exc}") from exc
            seen_bindings.add(statement.binding_digest)
    return store


def recover_trust_store_from_journal(
    journal_path: Path,
    initial_store: TrustStore,
    recovery_authority: EmergencyRecoveryAuthority | None = None,
) -> TrustStore:
    try:
        events = Journal(journal_path).events()
    except JournalIntegrityError as exc:
        raise TrustRecoveryError(f"journal integrity failure: {exc}") from exc
    return recover_trust_store(events, initial_store, recovery_authority)


def append_authorized_transition(
    journal: Journal,
    statement: TrustTransition,
    initial_store: TrustStore,
) -> JournalRecord:
    """Verify and durably append one ordinary trust transition atomically."""
    event = trust_transition_event(statement)

    def validate(existing: list[JournalRecord]) -> None:
        try:
            current = recover_trust_store((record.event for record in existing), initial_store)
            verify_transition(statement, current)
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

    return journal.append_checked(event, validate)


def append_authorized_emergency_recovery(
    journal: Journal,
    statement: EmergencyRecoveryStatement,
    initial_store: TrustStore,
    recovery_authority: EmergencyRecoveryAuthority,
) -> JournalRecord:
    """Authenticate emergency replacement against the serialized journal head."""
    event = emergency_recovery_event(statement)

    def validate(existing: list[JournalRecord]) -> None:
        try:
            current = recover_trust_store((record.event for record in existing), initial_store, recovery_authority)
            verify_emergency_recovery(statement, current, recovery_authority)
            if any(
                record.event.name == EventName.TRUST_EMERGENCY_RECOVERY_AUTHORIZED.value
                and record.event.data.get("recovery") == statement.to_record()
                for record in existing
            ):
                raise TrustRecoveryError("emergency recovery replay detected")
        except TrustRecoveryError:
            raise
        except (SignedTrustError, ValueError, TypeError) as exc:
            raise TrustRecoveryError(f"invalid authenticated emergency recovery: {exc}") from exc

    return journal.append_checked(event, validate)
