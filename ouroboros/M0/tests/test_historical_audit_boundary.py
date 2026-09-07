"""M1.7 conformance: historical audit is explicit and not current recovery."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.journal import Journal
from ourob.model import Event
from ourob.signed_trust import SignedTrustError, TrustStore, sign_checkpoint
from ourob.trust import JournalTrustAnchor
from ourob.trust_lifecycle import apply_transition, sign_rotation

GEN = "a" * 64


def test_retired_checkpoint_requires_explicit_historical_operation(tmp_path):
    journal = Journal(tmp_path / "journal.jsonl")
    for i in range(2):
        journal.append(Event(f"E{i}", "run", generation=GEN, data={"i": i}))

    k0 = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", k0.public_key())
    checkpoint = sign_checkpoint(k0, "k0", 0, JournalTrustAnchor.capture(journal.records(), GEN))

    k1 = Ed25519PrivateKey.generate()
    apply_transition(sign_rotation(k0, store, "k1", k1.public_key()), store)

    with pytest.raises(SignedTrustError, match="RETIRED"):
        journal.read_signed_trusted(checkpoint, store, GEN)

    assert len(journal.read_historical_signed_trusted(checkpoint, store, GEN)) == 2
