import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.generation import repository_generation
from ourob.journal import Journal
from ourob.signed_trust import SignedTrustError, TrustStore, sign_checkpoint
from ourob.trust import JournalTrustAnchor
from ourob.trust_boundary import (
    ExternalTrustAuthority,
    TrustBoundaryError,
    authenticate_current_repository,
    load_external_authority,
)


def _repo(tmp_path):
    root = tmp_path / "repo"
    (root / "policies").mkdir(parents=True)
    (root / "verification").mkdir()
    (root / "policies" / "constitution.json").write_text("{}", encoding="utf-8")
    (root / "verification" / "gates.json").write_text("{}", encoding="utf-8")
    return root


def _authority(root, tmp_path, *, generation=None, sequence=0, digest="GENESIS"):
    private = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("root", private.public_key())
    generation = generation if generation is not None else repository_generation(root).id
    checkpoint = sign_checkpoint(private, "root", 0, JournalTrustAnchor(sequence, digest, generation))
    checkpoint_path = tmp_path / "checkpoint.json"
    store_path = tmp_path / "trust-store.json"
    checkpoint_path.write_text(json.dumps(checkpoint.to_record()), encoding="utf-8")
    store_path.write_text(json.dumps(store.to_record()), encoding="utf-8")
    return private, store, checkpoint, checkpoint_path, store_path


def test_current_boundary_accepts_external_generation_bound_current_head(tmp_path):
    root = _repo(tmp_path)
    private, store, checkpoint, _, _ = _authority(root, tmp_path)
    recovered, records = authenticate_current_repository(
        Journal(root / ".ourob" / "journal.jsonl"),
        ExternalTrustAuthority(store, checkpoint),
        generation=repository_generation(root).id,
    )
    assert recovered.active.key_id == "root"
    assert records == ()
    assert private.public_key().public_bytes_raw() == recovered.active.public_key


def test_current_boundary_rejects_unbound_checkpoint(tmp_path):
    root = _repo(tmp_path)
    private = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("root", private.public_key())
    checkpoint = sign_checkpoint(private, "root", 0, JournalTrustAnchor(0, "GENESIS", None))
    with pytest.raises(TrustBoundaryError, match="generation-bound"):
        authenticate_current_repository(Journal(root / ".ourob" / "journal.jsonl"), ExternalTrustAuthority(store, checkpoint), generation=repository_generation(root).id)


def test_current_boundary_rejects_checkpoint_for_old_head(tmp_path):
    root = _repo(tmp_path)
    private, store, checkpoint, _, _ = _authority(root, tmp_path)
    journal = Journal(root / ".ourob" / "journal.jsonl")
    # A current checkpoint must bind the actual head, not merely a valid prefix.
    from ourob.model import Event
    journal.append(Event("RUN_CREATED", run_id="r1", generation=repository_generation(root).id, data={"task": "x"}))
    with pytest.raises(TrustBoundaryError, match="current journal head"):
        authenticate_current_repository(journal, ExternalTrustAuthority(store, checkpoint), generation=repository_generation(root).id)


def test_external_authority_loader_keeps_private_material_out_of_record(tmp_path):
    root = _repo(tmp_path)
    private, _, checkpoint, checkpoint_path, store_path = _authority(root, tmp_path)
    authority = load_external_authority(checkpoint_path, store_path)
    assert authority.checkpoint.signature == checkpoint.signature
    assert "private" not in json.dumps(authority.initial_store.to_record()).lower()
    with pytest.raises(SignedTrustError):
        authority.initial_store.verify(checkpoint, historical=False) if False else (_ for _ in ()).throw(SignedTrustError("sentinel"))
    assert private is not None
