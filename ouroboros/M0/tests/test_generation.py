from ourob.generation import canonical_manifest, repository_generation


def test_generation_is_deterministic(repo):
    assert repository_generation(repo).id == repository_generation(repo).id


def test_generation_changes_on_content_change(repo):
    before = repository_generation(repo).id
    (repo / "README.md").write_text("changed\n")
    assert repository_generation(repo).id != before


def test_runtime_state_is_excluded(repo):
    before = repository_generation(repo).id
    (repo / ".ourob").mkdir()
    (repo / ".ourob" / "journal.jsonl").write_text("{}\n")
    (repo / "ouroboros" / "M0" / "ourob" / "__pycache__").mkdir(exist_ok=True)
    (repo / "ouroboros" / "M0" / "ourob" / "__pycache__" / "x.pyc").write_bytes(b"\0")
    assert repository_generation(repo).id == before


def test_canonical_manifest_is_order_independent(repo):
    entries = repository_generation(repo).entries
    assert canonical_manifest(entries) == canonical_manifest(tuple(reversed(entries)))
