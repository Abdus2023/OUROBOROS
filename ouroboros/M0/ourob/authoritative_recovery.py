"""M1.23 authoritative replay of trust, recovery-root, and recovery-quorum state.

This is the single fail-closed replay path used when the independent
recovery-of-recovery quorum has lifecycle history.  The quorum is an external
root at genesis; journal events can only advance it through authenticated
statements signed by the quorum that is current at that exact position.
"""
from __future__ import annotations

from typing import Iterable

from .emergency_recovery import (
    EmergencyRecoveryAuthority,
    EmergencyRecoveryStatement,
    RecoveryRootTransition,
    apply_emergency_recovery,
    apply_recovery_root_rotation,
    verify_emergency_recovery,
    verify_recovery_root_rotation,
)
from .journal import Journal, JournalIntegrityError
from .model import Event, EventName
from .recovery_of_recovery import (
    RecoveryOfRecoveryAuthority,
    RecoveryOfRecoveryStatement,
    apply_recovery_of_recovery,
    verify_recovery_of_recovery,
)
from .recovery_of_recovery_lifecycle import (
    RecoveryOfRecoveryLifecycleStatement,
    apply_lifecycle_statement,
    verify_lifecycle_statement,
)
from .signed_trust import SignedTrustError, TrustStore
from .trust_lifecycle import TrustTransition, apply_transition


class AuthoritativeRecoveryError(RuntimeError):
    """Raised when authenticated recovery state cannot be reconstructed."""


def _unscoped(event: Event, label: str) -> None:
    if event.run_id is not None or event.action_id is not None or event.generation is not None:
        raise AuthoritativeRecoveryError(f"{label} event must not be run-scoped")


def recover_authoritative_state(
    events: Iterable[Event],
    initial_store: TrustStore,
    recovery_authority: EmergencyRecoveryAuthority | None = None,
    recovery_quorum: RecoveryOfRecoveryAuthority | None = None,
) -> tuple[TrustStore, EmergencyRecoveryAuthority | None, RecoveryOfRecoveryAuthority | None]:
    """Replay every authority-changing event in exact journal order.

    A quorum lifecycle transition takes effect before the next event. Therefore
    a later quorum configuration can never retroactively authorize an earlier
    break-glass recovery statement.
    """
    store = TrustStore.from_record(initial_store.to_record())
    recovery = recovery_authority
    quorum = recovery_quorum
    event_list = tuple(events)
    seen: set[str] = set()
    used_recovery_ids: set[str] = {recovery.key_id} if recovery else set()
    used_quorum_ids: set[str] = set(quorum.keys) if quorum else set()

    for event in event_list:
        try:
            if event.name == EventName.RECOVERY_QUORUM_LIFECYCLE_AUTHORIZED.value:
                _unscoped(event, "recovery-quorum lifecycle")
                if quorum is None:
                    raise AuthoritativeRecoveryError("recovery-quorum lifecycle requires an externally provisioned quorum")
                statement = RecoveryOfRecoveryLifecycleStatement.from_record(event.data.get("lifecycle"))
                if statement.binding_digest in seen:
                    raise AuthoritativeRecoveryError("recovery-quorum lifecycle replay detected")
                if statement.operation.value == "ROTATE_SIGNER" and statement.replacement_key_id in used_quorum_ids:
                    raise AuthoritativeRecoveryError("recovery-quorum replacement key id was already used")
                verify_lifecycle_statement(statement, quorum)
                quorum = apply_lifecycle_statement(statement, quorum)
                seen.add(statement.binding_digest)
                if statement.replacement_key_id is not None:
                    used_quorum_ids.add(statement.replacement_key_id)

            elif event.name == EventName.RECOVERY_OF_RECOVERY_AUTHORIZED.value:
                _unscoped(event, "recovery-of-recovery")
                if recovery is None:
                    raise AuthoritativeRecoveryError("recovery-of-recovery requires an externally provisioned recovery root")
                if quorum is None:
                    raise AuthoritativeRecoveryError("recovery-of-recovery requires an externally provisioned quorum")
                statement = RecoveryOfRecoveryStatement.from_record(event.data.get("recovery"))
                if statement.binding_digest in seen:
                    raise AuthoritativeRecoveryError("recovery-of-recovery replay detected")
                if statement.replacement_key_id in used_recovery_ids:
                    raise AuthoritativeRecoveryError("recovery-root replacement key id was already used")
                verify_recovery_of_recovery(statement, quorum, recovery)
                recovery = apply_recovery_of_recovery(statement, quorum, recovery)
                seen.add(statement.binding_digest)
                used_recovery_ids.add(statement.replacement_key_id)

            elif event.name == EventName.RECOVERY_ROOT_ROTATION_AUTHORIZED.value:
                _unscoped(event, "recovery-root transition")
                if recovery is None:
                    raise AuthoritativeRecoveryError("recovery-root history requires an externally provisioned recovery root")
                statement = RecoveryRootTransition.from_record(event.data.get("transition"))
                if statement.binding_digest in seen:
                    raise AuthoritativeRecoveryError("recovery-root transition replay detected")
                if statement.replacement_key_id in used_recovery_ids:
                    raise AuthoritativeRecoveryError("recovery-root replacement key id was already used")
                verify_recovery_root_rotation(statement, recovery)
                recovery = apply_recovery_root_rotation(statement, recovery)
                seen.add(statement.binding_digest)
                used_recovery_ids.add(statement.replacement_key_id)

            elif event.name == EventName.TRUST_TRANSITION_AUTHORIZED.value:
                _unscoped(event, "trust transition")
                statement = TrustTransition.from_record(event.data.get("transition"))
                if statement.binding_digest in seen:
                    raise AuthoritativeRecoveryError("trust transition replay detected")
                apply_transition(statement, store)
                seen.add(statement.binding_digest)

            elif event.name == EventName.TRUST_EMERGENCY_RECOVERY_AUTHORIZED.value:
                _unscoped(event, "emergency recovery")
                if recovery is None:
                    raise AuthoritativeRecoveryError("emergency recovery requires an externally provisioned recovery root")
                statement = EmergencyRecoveryStatement.from_record(event.data.get("recovery"))
                if statement.binding_digest in seen:
                    raise AuthoritativeRecoveryError("emergency recovery replay detected")
                verify_emergency_recovery(statement, store, recovery)
                apply_emergency_recovery(statement, store, recovery)
                seen.add(statement.binding_digest)
        except AuthoritativeRecoveryError:
            raise
        except (SignedTrustError, ValueError, TypeError) as exc:
            raise AuthoritativeRecoveryError(f"invalid authenticated authority event: {exc}") from exc

    return store, recovery, quorum


def recover_authoritative_state_from_journal(
    journal: Journal,
    initial_store: TrustStore,
    recovery_authority: EmergencyRecoveryAuthority | None = None,
    recovery_quorum: RecoveryOfRecoveryAuthority | None = None,
) -> tuple[TrustStore, EmergencyRecoveryAuthority | None, RecoveryOfRecoveryAuthority | None]:
    try:
        records = journal.records()
    except JournalIntegrityError as exc:
        raise AuthoritativeRecoveryError(f"journal integrity failure: {exc}") from exc
    return recover_authoritative_state(
        (record.event for record in records), initial_store, recovery_authority, recovery_quorum
    )


def recovery_quorum_lifecycle_event(statement: RecoveryOfRecoveryLifecycleStatement) -> Event:
    return Event(
        EventName.RECOVERY_QUORUM_LIFECYCLE_AUTHORIZED.value,
        data={"lifecycle": statement.to_record()},
    )
