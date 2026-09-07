# OUROBOROS

Repository-native autonomous engineering runtime.

The repository is simultaneously the runtime source, capability registry, policy/constitution, state journal, verification system, and bootstrap image — and the runtime can engineer this repository without ever being able to declare its own changes valid.

## Layout

```
ouroboros/M0/ourob/      implementation (kernel, policy, skills, verify, evidence, promotion, bootstrap, recovery, planner, cli)
ouroboros/M0/tests/      conformance suite (121 tests)
policies/constitution.json   normative policy data (interpreter lives in ourob/policy.py)
verification/gates.json      declared verification contract
skills/manifest.json         repository-declared capabilities
.ourob/journal.jsonl         hash-chained append-only journal (runtime state, git-ignored)
docs/                        design log
```

## M0 lifecycle

`INTAKE → PLANNED → AUTHORIZED → EXECUTING → OBSERVED → VERIFYING → VERIFIED → PROMOTABLE → PROMOTED`

- Every repository mutation passes through `Kernel.execute()`, is policy-evaluated, observed and journaled.
- Kernel / bootstrap / policy / verifier surfaces are denied on the ordinary mutation path.
- Each mutation advances the repository generation and verification epoch, invalidating prior evidence.
- `VerificationEvidence` binds run, generation, epoch, the canonical gate contract and every gate result under one digest.
- `PromotionAuthority` accepts only integrity-checked, complete, current evidence.
- Cold `Bootstrap` reconstructs capabilities strictly from `skills/manifest.json` and reports `trusted` only if the generation is unchanged across reconstruction.
- `recovery` replays the journal through the fail-closed state machine: no durable event → no recovered authority.

## Quick start

```bash
cd ouroboros/M0 && python -m pytest -q          # conformance suite
export PYTHONPATH=ouroboros/M0                  # or: pip install -e ouroboros/M0
python -m ourob bootstrap                       # cold-start and report trust
python -m ourob generation                      # current repository generation
python -m ourob run --run-id r1 --task "Add a greet capability" --add-capability greet
python -m ourob skills --call greet --arguments '{"name":"World"}'   # → Hello, World!
python -m ourob journal --verify
python -m ourob recover --run r1
```

`python -m ourob run` drives a plan through the full lifecycle and exits non-zero unless the run reaches `PROMOTED`. Plans targeting protected surfaces end in `BLOCKED` and the file is never written.

## Status

M0 (deterministic self-hosting kernel) and M1.1–M1.3 (durable, tamper-evident, authority-preserving recovery) are implemented. See `docs/OUROBOROS_DESIGN_LOG.md` for the full invariant list and next slice (M1.4: fsync / locking / checkpointing).
