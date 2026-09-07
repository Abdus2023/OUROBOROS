# OUROBOROS — Architecture & Implementation Log (M0 → M1.3)

> A repository-native autonomous engineering runtime that can engineer the repository containing its own implementation, while remaining unable to declare its own changes valid.

This document records the design conversation and implementation history of OUROBOROS (`ourob`), from initial architecture through M0 (deterministic self-hosting kernel) and into M1 (durable, crash-safe runtime state).

---

## Table of Contents

1. [Prompt & Framing](#1-prompt--framing)
2. [Proposed Architecture](#2-proposed-architecture)
3. [Bootstrap as a Trust Boundary](#3-bootstrap-as-a-trust-boundary)
4. [Repository Shape](#4-repository-shape)
5. [The Fundamental State Machine](#5-the-fundamental-state-machine)
6. [Verification Vocabulary](#6-verification-vocabulary)
7. [The Self-Engineering Loop](#7-the-self-engineering-loop)
8. [The Bootstrap Invariant](#8-the-bootstrap-invariant)
9. [What Makes This Different From an Ordinary Coding Agent](#9-what-makes-this-different-from-an-ordinary-coding-agent)
10. [Milestone Roadmap](#10-milestone-roadmap)
11. [M0: Make the Kernel Executable](#11-m0-make-the-kernel-executable)
12. [M0 Definition of Done (Invariants)](#12-m0-definition-of-done-invariants)
13. [Implementation Log](#13-implementation-log)
    - [M0.1–M0.3 Domain model, state machine, journal](#m01m03--domain-model-state-machine-journal)
    - [M0.4–M0.6 Policy, skills, kernel](#m04m06--policy-skills-kernel)
    - [M0.7–M0.10 Generation, verification, promotion, bootstrap](#m07m010--generation-verification-promotion-bootstrap)
    - [M0.11 Lifecycle closure](#m011--lifecycle-closure)
    - [M0.12 First self-extension proof](#m012--first-self-extension-proof)
    - [M0.13 Multi-action mutation closure](#m013--multi-action-mutation-closure)
    - [M0.14 Closed self-extension loop](#m014--closed-self-extension-loop)
    - [M0.15 Capability provenance boundary](#m015--capability-provenance-boundary)
    - [M0.16 Generation binding](#m016--generation-binding)
    - [M0.17 Immutable promotion evidence](#m017--immutable-promotion-evidence)
    - [M0.18 Evidence object](#m018--evidence-object)
    - [M0.19 Evidence integrity](#m019--evidence-integrity)
    - [M0.20 Required gate completeness](#m020--required-gate-completeness)
    - [M0.21 Gate identity hardening](#m021--gate-identity-hardening)
    - [M0.22 Gate configuration binding](#m022--gate-configuration-binding)
    - [M0.23 Canonical gate contract](#m023--canonical-gate-contract)
    - [M1.1 Durable journal recovery](#m11--durable-journal-recovery)
    - [M1.2 Tamper-evident journal](#m12--tamper-evident-journal)
    - [M1.3 Crash recovery authority boundary](#m13--crash-recovery-authority-boundary)
14. [Invariant Index](#14-invariant-index)
15. [Next Slice](#15-next-slice)

---

## 1. Prompt & Framing

**Original prompt:**

> A Python autonomous-engineering runtime whose source, skills, policies, state model, verification machinery, and bootstrap mechanism live inside the repository it is capable of engineering.

The right abstraction is not merely an agent framework; it is a **self-hosting engineering system**.

The key invariant:

> The repository is simultaneously the runtime's program, capability registry, policy/constitution, state journal, verification system, and bootstrap image.

And the runtime must never treat its own generated output as authoritative merely because it generated it.

---

## 2. Proposed Architecture

```
                    ┌──────────────────────────────┐
                    │        ENGINEERING TASK       │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │       PLANNER / MODEL         │
                    │  proposes actions, not truth │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │        POLICY KERNEL          │
                    │ authorization / scope / risk │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
        ┌─────────────────────────────────────────────────┐
        │                 SKILL EXECUTION                 │
        │ read · search · edit · write · test · git ...  │
        └──────────────────────┬──────────────────────────┘
                               │
                               ▼
                    ┌──────────────────────────────┐
                    │       OBSERVATION LAYER       │
                    │ files / processes / tests /  │
                    │ git / environment / artifacts │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │       STATE MACHINE           │
                    │ proposed → executing →       │
                    │ verified → promoted/rejected │
                    └──────────────┬───────────────┘
                                   │
                         ┌─────────┴─────────┐
                         ▼                   ▼
                 ┌──────────────┐    ┌──────────────┐
                 │ VERIFICATION │    │   JOURNAL     │
                 │ gates/evidence│    │ append-only   │
                 └──────┬───────┘    └──────────────┘
                        │
                        ▼
                 ┌──────────────┐
                 │  PROMOTION   │
                 │ stage→verify │
                 │ →authorize   │
                 └──────┬───────┘
                        │
                        ▼
              ┌──────────────────────┐
              │       REPOSITORY     │
              │ source + skills +    │
              │ policy + state +    │
              │ verifier + bootstrap │
              └──────────┬───────────┘
                         │
                         ▼
                   ┌────────────┐
                   │ BOOTSTRAP  │
                   │ cold start │
                   │ self-check │
                   └─────┬──────┘
                         │
                         └──────────► new runtime generation
```

---

## 3. Bootstrap as a Trust Boundary

One important change to the initial design: **do not** make a `quine.py` responsible for "regenerating the runtime from a manifest." That creates a dangerous circular authority:

```
runtime
  ↓
declares its own source
  ↓
regenerates itself
  ↓
declares regenerated source valid
```

Instead, make bootstrap a trust boundary:

```
BOOTSTRAP
   │
   ├── identify repository
   ├── load constitution/policies
   ├── validate manifest schema
   ├── verify source/artifact integrity
   ├── construct runtime
   ├── enter STATE.BOOTSTRAP
   │
   ▼
SELF-HOSTED
```

The transition `BOOTSTRAP → SELF_HOSTED` should require independently checkable evidence.

This aligns with the self-conformance model: **PASS is an authorization result produced by verification, not a boolean emitted by the agent.**

---

## 4. Repository Shape

```
ourob/
├── pyproject.toml
├── README.md
│
├── ourob/
│   ├── __init__.py
│   ├── __main__.py
│   │
│   ├── kernel/
│   │   ├── kernel.py
│   │   ├── transition.py
│   │   ├── authority.py
│   │   └── errors.py
│   │
│   ├── model/
│   │   ├── ids.py
│   │   ├── task.py
│   │   ├── action.py
│   │   ├── artifact.py
│   │   └── result.py
│   │
│   ├── skills/
│   │   ├── registry.py
│   │   ├── base.py
│   │   ├── filesystem.py
│   │   ├── process.py
│   │   ├── search.py
│   │   ├── git.py
│   │   └── verify.py
│   │
│   ├── policies/
│   │   ├── policy.py
│   │   ├── filesystem.py
│   │   ├── mutation.py
│   │   ├── budget.py
│   │   └── constitution.py
│   │
│   ├── state/
│   │   ├── machine.py
│   │   ├── events.py
│   │   ├── journal.py
│   │   └── snapshot.py
│   │
│   ├── verification/
│   │   ├── verifier.py
│   │   ├── gates.py
│   │   ├── evidence.py
│   │   └── report.py
│   │
│   ├── bootstrap/
│   │   ├── bootstrap.py
│   │   ├── manifest.py
│   │   └── trust.py
│   │
│   ├── planning/
│   │   ├── planner.py
│   │   ├── scripted.py
│   │   └── llm.py
│   │
│   └── cli.py
│
├── skills/
│   └── manifest.json
│
├── policies/
│   └── constitution.json
│
├── verification/
│   └── gates.json
│
├── bootstrap/
│   └── manifest.json
│
├── .ourob/
│   ├── journal.jsonl
│   ├── snapshots/
│   └── runs/
│
└── tests/
    ├── test_state_machine.py
    ├── test_policy.py
    ├── test_skills.py
    ├── test_verification.py
    ├── test_bootstrap.py
    └── test_self_hosting.py
```

The distinction between the Python package (`ourob/`) and the repository-level directories (`skills/`, `policies/`, `verification/`, `bootstrap/`) is deliberate:

- The Python package is **implementation**.
- The repository-level directories are **declarative engineering substrate**.

That means the runtime can modify its own capabilities without necessarily modifying its kernel.

---

## 5. The Fundamental State Machine

Substantially stricter than a conventional agent loop:

```
NO_TASK
   │
   ▼
INTAKE
   │
   ▼
PLANNED
   │
   ▼
AUTHORIZED
   │
   ▼
EXECUTING
   │
   ├──────────────► BLOCKED
   │
   ▼
OBSERVED
   │
   ▼
VERIFYING
   │
   ├──────────────► FAILED
   │
   ▼
VERIFIED
   │
   ▼
PROMOTABLE
   │
   ▼
PROMOTED
   │
   ▼
SELF_HOSTED
```

And importantly:

```
FAILED ──X──► PROMOTED
BLOCKED ─X──► PROMOTED
PLANNED ─X──► PROMOTED
```

There is no shortcut. A planner can propose `Action(...)` but cannot assert `PASS`. Only the verifier can produce an authoritative verification result.

This follows the kernel/adapter/verifier separation: adapters observe; the kernel decides justified transitions; verification authorizes PASS.

---

## 6. Verification Vocabulary

Do not use only `PASS / FAIL`. Use a structured result:

```
PASS
FAIL
BLOCKED
INCONCLUSIVE
NOT_RUN
STALE
INVALID
SKIPPED
```

with:

```python
VerificationResult(
    status=PASS,
    gate="tests",
    evidence_id="...",
    verification_epoch=42,
)
```

Then `VERIFIED` means something stronger than "tests happened." It means:

```
all required gates passed
AND
evidence is valid
AND
evidence belongs to current repository generation
AND
required scope was covered
AND
no blocking policy violation exists
AND
verification epoch matches current mutation epoch
```

This prevents stale verification from authorizing later mutations — the `verification_epoch` principle.

---

## 7. The Self-Engineering Loop

The first real autonomous capability:

```
TASK:
    "Add a greet skill."
        ↓
INTAKE
        ↓
PLAN
        ↓
POLICY CHECK
        ↓
CREATE:
    skills/greet.py
        ↓
UPDATE:
    skills/manifest.json
        ↓
BOOTSTRAP DISCOVERY
        ↓
IMPORT CHECK
        ↓
UNIT TESTS
        ↓
INTEGRITY CHECK
        ↓
POLICY CHECK
        ↓
VERIFICATION
        ↓
PROMOTION
        ↓
RE-BOOTSTRAP
        ↓
DISCOVER greet
        ↓
EXECUTE greet
        ↓
SELF-HOSTING PROOF
```

The demonstration isn't "the agent created a file." It is:

> The runtime modified its own capability surface, reconstructed its executable state from the modified repository, discovered the new capability, and executed it only after verification.

That is an actual self-hosting demonstration.

---

## 8. The Bootstrap Invariant

```
Rₙ ──engineers──► Rₙ₊₁
                 │
                 ├── verification
                 ├── integrity
                 ├── policy
                 └── bootstrap
                       │
                       ▼
                     Rₙ₊₁
```

Where `Rₙ` = current repository generation and `Rₙ₊₁` = proposed repository generation.

The runtime must never silently become the new generation:

```
CURRENT
   │
   ▼
WORKTREE / STAGING
   │
   ▼
VERIFY
   │
   ├── FAIL → discard/recover
   │
   ▼
AUTHORIZE
   │
   ▼
PROMOTE
   │
   ▼
NEW GENERATION
```

This makes self-modification equivalent to a controlled repository migration.

---

## 9. What Makes This Different From an Ordinary Coding Agent

Ordinary agent:

```
LLM → tools → files
```

This system:

```
                 ┌──────────────┐
                 │    MODEL     │
                 └──────┬───────┘
                        │ proposal
                        ▼
                 ┌──────────────┐
                 │    KERNEL    │
                 └──────┬───────┘
                        │ authorized action
                        ▼
                 ┌──────────────┐
                 │    SKILL     │
                 └──────┬───────┘
                        │ observation
                        ▼
                 ┌──────────────┐
                 │    STATE     │
                 └──────┬───────┘
                        │
                        ▼
                 ┌──────────────┐
                 │  VERIFIER    │
                 └──────┬───────┘
                        │ evidence
                        ▼
                 ┌──────────────┐
                 │  PROMOTION   │
                 └──────┬───────┘
                        │
                        ▼
                    REPOSITORY
                        │
                        ▼
                    BOOTSTRAP
                        │
                        └──────► next generation
```

- The model is replaceable.
- The repository is the persistent intelligence substrate.
- The state machine is authoritative.
- The verifier is authoritative for conformance.
- The policy layer controls mutation.
- Bootstrap establishes trust.

---

## 10. Milestone Roadmap

Do not attempt the full autonomous LLM engineer immediately. Build the deterministic self-hosting kernel first.

### M0 — Repository-native kernel

- ✓ typed state machine
- ✓ append-only journal
- ✓ declarative policies
- ✓ skill registry
- ✓ filesystem skills
- ✓ deterministic planner
- ✓ verification gates
- ✓ repository manifest
- ✓ bootstrap
- ✓ self-integrity verification
- ✓ self-modification demo
- ✓ complete tests

### M1 — Engineering planner

```
task
 → inspect
 → plan
 → mutate
 → verify
 → recover
```

### M2 — LLM planner

```
LLM
 ↓
structured ActionPlan
 ↓
kernel authorization
 ↓
skills
```

### M3 — Self-extension

```
runtime
  ↓
creates skill
  ↓
updates registry
  ↓
verifies
  ↓
reboots
  ↓
uses skill
```

### M4 — Recursive engineering

```
Rₙ
 │
 ├── modifies skills
 ├── modifies policies
 ├── modifies verifier
 └── proposes kernel changes
       │
       ▼
    verification
       │
       ▼
     Rₙ₊₁
```

Kernel/constitution/bootstrap modifications should have a stronger promotion path than ordinary skill modifications.

---

## 11. M0: Make the Kernel Executable

The central design decision:

> **Everything that can cause repository state to change must pass through the kernel.**

No skill directly decides whether its mutation is acceptable.

### 11.1 The Kernel Contract

The kernel owns exactly four things:

```
┌─────────────────────────────────────┐
│             KERNEL                  │
│                                     │
│  1. State transitions               │
│  2. Action authorization            │
│  3. Skill dispatch                  │
│  4. Promotion authorization         │
│                                     │
└─────────────────────────────────────┘
```

It does **not** own:

```
✗ LLM reasoning
✗ filesystem implementation
✗ Git implementation
✗ test implementation
✗ policy definitions
✗ repository-specific knowledge
```

Those remain replaceable components.

### 11.2 Core Domain Objects

```python
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class RunState(StrEnum):
    NO_TASK = "NO_TASK"
    INTAKE = "INTAKE"
    PLANNED = "PLANNED"
    AUTHORIZED = "AUTHORIZED"
    EXECUTING = "EXECUTING"
    OBSERVED = "OBSERVED"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    PROMOTABLE = "PROMOTABLE"
    PROMOTED = "PROMOTED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class ActionKind(StrEnum):
    READ = "READ"
    SEARCH = "SEARCH"
    WRITE = "WRITE"
    EDIT = "EDIT"
    EXECUTE = "EXECUTE"
    VERIFY = "VERIFY"
    GIT = "GIT"


class VerificationStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_RUN = "NOT_RUN"
    STALE = "STALE"
    INVALID = "INVALID"
    SKIPPED = "SKIPPED"


@dataclass(frozen=True)
class Action:
    id: str
    kind: ActionKind
    skill: str
    arguments: dict[str, Any]
    rationale: str = ""


@dataclass(frozen=True)
class VerificationResult:
    gate: str
    status: VerificationStatus
    evidence_id: str
    generation: str
    message: str = ""


@dataclass
class Run:
    id: str
    task: str
    state: RunState = RunState.NO_TASK
    generation: str = ""
    actions: list[Action] = field(default_factory=list)
    verifications: list[VerificationResult] = field(default_factory=list)
```

The important point is that **state, actions and verification are explicit domain objects**.

### 11.3 State Transitions Become a Contract

Do not allow arbitrary `run.state = RunState.PROMOTED`. Instead:

```python
ALLOWED_TRANSITIONS = {
    RunState.NO_TASK: {RunState.INTAKE},
    RunState.INTAKE: {RunState.PLANNED, RunState.BLOCKED},
    RunState.PLANNED: {RunState.AUTHORIZED, RunState.BLOCKED},
    RunState.AUTHORIZED: {RunState.EXECUTING, RunState.BLOCKED},
    RunState.EXECUTING: {RunState.OBSERVED, RunState.FAILED, RunState.BLOCKED},
    RunState.OBSERVED: {RunState.VERIFYING},
    RunState.VERIFYING: {RunState.VERIFIED, RunState.FAILED, RunState.BLOCKED},
    RunState.VERIFIED: {RunState.PROMOTABLE},
    RunState.PROMOTABLE: {RunState.PROMOTED},
}


def transition(run: Run, target: RunState) -> None:
    allowed = ALLOWED_TRANSITIONS.get(run.state, set())
    if target not in allowed:
        raise InvalidTransition(f"{run.state} -> {target} is not permitted")
    run.state = target
```

First **hard invariant**: no legal path `arbitrary_state → PROMOTED`. There must always be a preceding verification path.

### 11.4 The Mutation Boundary

`filesystem.write("ourob/skills/new_skill.py", source)` should **not** be the public mutation interface. Instead:

```python
kernel.execute(
    action=Action(
        id="act-001",
        kind=ActionKind.WRITE,
        skill="filesystem.write",
        arguments={
            "path": "ourob/skills/new_skill.py",
            "content": source,
        },
    )
)
```

The kernel performs:

```
Action
  │
  ▼
Policy evaluation
  │
  ├── DENY
  │
  └── ALLOW
        │
        ▼
      Skill
        │
        ▼
   Observation
        │
        ▼
     Journal
```

Therefore:

```
MODEL ──X──► FILESYSTEM
MODEL ──X──► SUBPROCESS
MODEL ──X──► GIT
```

Instead: `MODEL → ACTION → KERNEL → POLICY → SKILL`.

### 11.5 Policies Are Data

Start with `policies/constitution.json`:

```json
{
  "version": 1,
  "rules": [
    {
      "id": "NO_UNAUTHORIZED_MUTATION",
      "effect": "DENY",
      "when": { "action_kind": ["WRITE", "EDIT", "EXECUTE"] },
      "unless": "ACTION_AUTHORIZED"
    },
    {
      "id": "PROTECT_BOOTSTRAP",
      "effect": "DENY",
      "paths": ["bootstrap/", "ourob/kernel/"],
      "unless": "CONSTITUTIONAL_AMENDMENT"
    },
    {
      "id": "VERIFY_BEFORE_PROMOTION",
      "effect": "DENY",
      "transition": "PROMOTED",
      "unless": "CURRENT_VERIFICATION_PASS"
    }
  ]
}
```

Now the repository contains part of the runtime's **normative authority**. But:

```
policy DATA ≠ policy INTERPRETER
```

The interpreter remains part of the trusted kernel. Otherwise the agent could simply edit `constitution.json` to say "everything is allowed."

### 11.6 Constitutional Paths

The first protected surface:

```
ourob/kernel/
bootstrap/
policies/constitution.json
verification/
```

Protection does not mean "these files can never change." It means **changes to these files require a stronger authorization class**:

```python
class MutationClass(StrEnum):
    ORDINARY = "ORDINARY"
    CAPABILITY = "CAPABILITY"
    POLICY = "POLICY"
    VERIFIER = "VERIFIER"
    KERNEL = "KERNEL"
    BOOTSTRAP = "BOOTSTRAP"
```

The higher classes require stronger evidence.

### 11.7 The Generation Model

Every repository state gets a generation identity:

```
generation = sha256(canonical repository manifest)
```

Suppose `G₁` is the current repository and the agent modifies `skills/greet.py`:

```
G₁
 │
 │ mutation
 ▼
candidate G₂
```

Verification happens **against G₂**. If another mutation happens (`G₂ → G₃`), previous evidence is no longer sufficient:

```
verification(G₂) ≠ verification(G₃)

G₂ evidence
    │
    └──X──► authorize G₃
```

This eliminates **stale verification masquerading as current verification**.

### 11.8 Repository Manifest

`bootstrap/manifest.json`:

```json
{
  "schema": 1,
  "generation": "sha256:...",
  "files": {
    "ourob/__init__.py": "sha256:...",
    "ourob/kernel/kernel.py": "sha256:...",
    "ourob/state/machine.py": "sha256:...",
    "policies/constitution.json": "sha256:...",
    "verification/gates.json": "sha256:..."
  }
}
```

The manifest should **not** contain its own hash (`manifest → hash(manifest) → manifest` is the usual self-reference problem). Instead:

```
repository snapshot
        │
        ▼
canonical file list
        │
        ▼
canonical hashes
        │
        ▼
generation ID
```

The manifest describes the generation. The generation identifies the manifest.

### 11.9 Canonicalization

```python
def canonical_manifest(files: dict[str, str]) -> bytes:
    lines = [f"{path}\0{digest}" for path, digest in sorted(files.items())]
    return ("\n".join(lines) + "\n").encode()


generation = sha256(canonical_manifest(files)).hexdigest()
```

Two independent implementations can calculate the same generation:

```
same repository → same canonical representation → same generation
```

### 11.10 Journal

`.ourob/journal.jsonl` is append-only:

```jsonl
{"event":"RUN_CREATED","run":"run-001","generation":"G1"}
{"event":"ACTION_PROPOSED","run":"run-001","action":"act-001"}
{"event":"POLICY_ALLOWED","run":"run-001","action":"act-001"}
{"event":"ACTION_EXECUTED","run":"run-001","action":"act-001"}
{"event":"OBSERVATION","run":"run-001","observation":"obs-001"}
{"event":"VERIFICATION_STARTED","run":"run-001","generation":"G2"}
{"event":"GATE_RESULT","run":"run-001","gate":"tests","status":"PASS"}
{"event":"PROMOTION_AUTHORIZED","run":"run-001","generation":"G2"}
{"event":"PROMOTED","run":"run-001","generation":"G2"}
```

The runtime can reconstruct: WHAT happened? WHY? UNDER WHICH POLICY? AGAINST WHICH GENERATION? WHAT EVIDENCE? WHAT AUTHORITY?

### 11.11 Verification Must Be an Observation System

The verifier should never `return True` because a subprocess exited successfully. Instead:

```
Gate
 │
 ├── command
 ├── scope
 ├── expected result
 ├── actual result
 ├── stdout/stderr evidence
 ├── duration
 ├── generation
 └── timestamp
```

`verification/gates.json`:

```json
{
  "gates": [
    { "id": "IMPORT",   "command": ["python", "-m", "compileall", "ourob"],          "required": true },
    { "id": "TEST",     "command": ["python", "-m", "pytest", "-q"],                 "required": true },
    { "id": "MANIFEST", "command": ["python", "-m", "ourob", "bootstrap", "verify"], "required": true }
  ]
}
```

Later gates (ruff, mypy, property tests, mutation tests, security/dependency checks, repository-specific gates) can be added without changing the kernel.

### 11.12 The First Autonomous Task

Task: `Add a new skill named greet.`

Planner emits:

```json
{
  "task": "Add a greet skill",
  "actions": [
    { "id": "a1", "kind": "WRITE",  "skill": "filesystem.write", "arguments": { "path": "skills/greet.py",      "content": "..." } },
    { "id": "a2", "kind": "WRITE",  "skill": "filesystem.write", "arguments": { "path": "skills/manifest.json", "content": "..." } },
    { "id": "a3", "kind": "VERIFY", "skill": "verify.repository", "arguments": {} }
  ]
}
```

The model does **not** execute these. The kernel evaluates each action.

### 11.13 Self-Extension Proof

```
G₁
 │
 │ create greet skill
 ▼
G₂
 │
 ├── manifest(G₂)
 ├── policy(G₂)
 ├── tests(G₂)
 └── bootstrap(G₂)
        │
        ▼
      PASS
        │
        ▼
    PROMOTED
        │
        ▼
    BOOTSTRAP
        │
        ▼
   registry(G₂)
        │
        ▼
    greet discovered
```

Final assertion:

```python
assert registry.has("greet")
assert registry.execute("greet", {"name": "World"}) == "Hello, World!"
```

The first **self-hosting theorem-by-execution**:

> A repository modification produced by the runtime can become part of the next runtime generation only after that generation passes its own verification machinery.

### 11.14 Recovery Before LLM

```
EXECUTING
   │
   ├── success ──► OBSERVED
   ├── policy denial ──► BLOCKED
   ├── tool failure ──► FAILED
   └── timeout ──► FAILED

FAILED
  │
  ├── rollback
  ├── re-plan
  └── terminate
```

**Recovery itself is an observable state transition**, not an invisible exception handler.

---

## 12. M0 Definition of Done (Invariants)

| ID | Invariant |
|---|---|
| M0-INV-01 | Every mutation passes through the kernel. |
| M0-INV-02 | Every kernel action passes policy evaluation. |
| M0-INV-03 | PROMOTED requires current verification. |
| M0-INV-04 | Verification is bound to a repository generation. |
| M0-INV-05 | The journal is append-only. |
| M0-INV-06 | Bootstrap can reconstruct the runtime from repository state. |
| M0-INV-07 | The runtime can discover repository-declared skills. |
| M0-INV-08 | A capability can be added by the runtime itself. |
| M0-INV-09 | The newly added capability survives a cold bootstrap. |
| M0-INV-10 | Kernel/bootstrap/policy/verifier changes cannot use the ordinary mutation path. |
| M0-INV-11 | No planner output is authoritative verification evidence. |
| M0-INV-12 | A failed or blocked run cannot reach PROMOTED. |
| M0-META-01 | The mechanism that verifies the runtime must itself be represented in the repository and included in the bootstrap trust boundary. |

The resulting repository-native control plane:

```
             REASON
                │
                ▼
             PROPOSE
                │
                ▼
            AUTHORIZE
                │
                ▼
              ACT
                │
                ▼
            OBSERVE
                │
                ▼
             VERIFY
                │
                ▼
             PROMOTE
                │
                ▼
           BOOTSTRAP
                │
                ▼
         NEXT GENERATION
                │
                └───────────┐
                            ▼
                          REASON
```

---

## 13. Implementation Log

The M0 contract was seeded in `Agentic-Native-Stack` under `ouroboros/M0/README.md` (commit `4a61e0e0f6fd3f08e422bb75bdd40db90e1067dd`). The implementation order:

```
M0.1  Domain model
M0.2  State machine
M0.3  Append-only journal
M0.4  Policy engine
M0.5  Skill registry + capabilities
M0.6  Mutation gateway
M0.7  Generation / manifest
M0.8  Verification engine
M0.9  Bootstrap
M0.10 Deterministic planner
M0.11 Self-modification test
M0.12 Cold-bootstrap proof
```

**M0.6 is the security/conformance boundary:**

> A planner can propose anything. Only the kernel can mutate. Only the verifier can establish verification. Only current-generation evidence can authorize promotion.

Implementation target:

```
ouroboros/M0/
├── pyproject.toml
├── ourob/
│   ├── __init__.py
│   ├── model.py
│   ├── state.py
│   ├── journal.py
│   ├── policy.py
│   ├── skills.py
│   ├── kernel.py
│   ├── generation.py
│   ├── verify.py
│   ├── bootstrap.py
│   └── cli.py
├── policies/
│   └── constitution.json
├── verification/
│   └── gates.json
├── skills/
│   └── manifest.json
└── tests/
    ├── test_state.py
    ├── test_policy.py
    ├── test_kernel.py
    ├── test_generation.py
    ├── test_verification.py
    └── test_self_hosting.py
```

---

### M0.1–M0.3 — Domain model, state machine, journal

- `ourob/model.py` — typed actions, observations, runs, verification results, structured statuses.
- `ourob/state.py` — fail-closed state machine with explicit legal transitions.
- `ourob/journal.py` — append-only JSONL event journal.
- `ourob/__init__.py` — package identity.

Verification carries both `generation` and `verification_epoch`, so a future verifier can reject evidence belonging to an older repository state.

---

### M0.4–M0.6 — Policy, skills, kernel

Added `ourob/policy.py`, `ourob/skills.py`, `ourob/kernel.py`.

Execution path:

```
Action
  │
  ▼
Kernel
  │
  ├── validate run state
  ├── journal ACTION_PROPOSED
  ├── PolicyEngine.evaluate()
  │       │
  │       ├── DENY → BLOCKED
  │       │
  │       └── ALLOW
  ├── SkillRegistry.execute()
  ├── Observation
  └── Journal
```

Protected surfaces (`ourob/kernel/`, `ourob/kernel.py`, `bootstrap/`, `policies/`, `verification/`) are classified into elevated mutation classes: `ORDINARY, CAPABILITY, POLICY, VERIFIER, KERNEL, BOOTSTRAP`.

```
ordinary engineering
       ≠
changing the mechanism that governs engineering
```

The kernel requires an `AUTHORIZED` run before execution. With no authorization transition yet implemented, the system was **fail-closed** rather than silently bypassing its own authority model.

---

### M0.7–M0.10 — Generation, verification, promotion, bootstrap

Added `generation.py`, `verify.py`, `promotion.py`, `bootstrap.py`, `policies/constitution.json`, `verification/gates.json`, `pyproject.toml`, and tests for generation, verification, promotion, and bootstrap.

**Generation identity:**

```
repository state → canonical manifest → SHA-256 → Generation Gₙ
```

Runtime state (`.git/`, `.ourob/`, caches, `__pycache__`) is excluded so the journal does not recursively invalidate its own generation.

**Verification binding:**

```
G₂ + epoch 7 → verification → evidence(G₂, 7)
```

If the repository changes during verification, the evidence becomes `STALE`. A zero exit code is not by itself sufficient for `PASS`.

**Promotion:**

```
VERIFIED
   │
   ├─ current generation?
   ├─ current verification epoch?
   ├─ evidence present?
   └─ every required gate PASS?
          │
          ▼
     PROMOTABLE
          │
          ▼
       PROMOTED
```

**Bootstrap** reconstructs runtime capabilities from repository-declared state and refuses to establish trust when required constitution or verification declarations are missing/invalid.

Tests cover: deterministic generation, excluded mutable runtime state, generation-bound verification, required-gate failure → BLOCKED, stale evidence, promotion authorization, bootstrap trust failure, cold reconstruction of filesystem capabilities.

---

### M0.11 — Lifecycle closure

```
INTAKE
  ↓ plan()
PLANNED
  ↓ authorize()
AUTHORIZED
  ↓ execute()
EXECUTING
  ↓
OBSERVED
  ↓ verify()
VERIFYING
  ↓
VERIFIED
  ↓ promote()
PROMOTABLE
  ↓
PROMOTED
```

Generation and verification-epoch checks at the boundaries; undeclared transitions rejected.

Hardening: the bootstrap validator now matches the `ourob.constitution.v1` / `ourob.gates.v1` schemas and rejects non-`fail_closed` configurations. The filesystem adapter's `Observation` objects match the model and repository paths are checked **after resolution**, preventing symlink/path escapes.

Trust chain:

```
Repository → Generation → Action → Kernel → Policy → Skill → Observation
  → Verification → Promotion Authority → PROMOTED → Cold Bootstrap → Reconstructed Runtime
```

---

### M0.12 — First self-extension proof

Commit `96512b589bc7b8509a34f1bbcafe8254fe72e962`.

```
OUROBOROS
   │
   ├── creates skills/greet.py
   ├── repository state changes
   ├── capability is declared in skills/manifest.json
   └── cold bootstrap
             │
             ▼
       discover "greet"
```

> Self-extension is no longer "the agent wrote some code." It is "the repository contains the new capability and a fresh bootstrap can reconstruct it."

Deliberate gap: the test wrote the manifest outside the kernel — acceptable as a bootstrap proof, but a violation of the strongest invariant if treated as the autonomous path.

---

### M0.13 — Multi-action mutation closure

Commits `40ddb549696dbbbab933ddcad76874c1524d922f` (state machine), `2a27814a4c3c14878e2330b81601f24149861948` (kernel).

A single authorized run may contain multiple repository mutations:

```
AUTHORIZED
    │
    ├── action #1 → OBSERVED
    ├── action #2 → OBSERVED
    ├── action #N → OBSERVED
    └── VERIFYING
```

The transition `OBSERVED → AUTHORIZED → EXECUTING → OBSERVED` is performed only by the kernel. There is no longer a need to mutate the capability manifest outside the mutation gateway.

---

### M0.14 — Closed self-extension loop

Commit `db8bbced6f58d552243928d3ccca9942c50b30de`.

```
TASK → INTAKE → PLAN → AUTHORIZED
  → WRITE skills/greet.py → OBSERVED → AUTHORIZED
  → WRITE skills/manifest.json → OBSERVED
  → VERIFY → VERIFIED → PROMOTABLE → PROMOTED
  → COLD BOOTSTRAP → DISCOVER greet
  → EXECUTE greet("World") → "Hello, World!"
```

Negative conformance assertion:

```
filesystem.write → ourob/kernel.py
                         ↓
                    POLICY DENIED
```

Cold bootstrap temporarily establishes the repository root as the controlled Python import root, so repository-declared skills such as `skills.greet` are reconstructed independently of the original runtime process.

Remaining weakness: bootstrap still reconstructs skills through Python's ambient import machinery.

---

### M0.15 — Capability provenance boundary

Commits `8598a6285dc6b2c2ca59ed9681b4663ae624c990`, `3f6bb3c90ccf7a68630d52ab9ad42452305a1901`.

Manifest validation:

```
manifest
  │
  ├── exact {name,module} schema
  ├── valid identifiers
  ├── repository-relative module
  ├── resolved path must remain inside repo
  ├── file must exist
  ├── register() must exist
  ├── exactly one capability must be added
  └── declared name must actually appear
```

The reconstructed `SkillRegistry` is returned by `BootstrapResult`, so the proof executes the actual cold-boot reconstructed capability. External module references are explicitly rejected.

**M0-INV-13** — Every dynamically reconstructed capability must originate from a manifest-declared module whose resolved source path is contained within the repository generation being bootstrapped.

---

### M0.16 — Generation binding

Commit `8b0924a0f62e566967604aed2d3cfa61eed5b984` — [specification](https://github.com/Abdus2023/Agentic-Native-Stack/blob/main/ouroboros/M0/verification/M0_16_generation_binding.md).

```
G0 = generation(repository)
        │
        ▼
  reconstruct runtime
        │
        ▼
G1 = generation(repository)

trusted ⇔ G0 == G1
```

M0 explicitly separates:

```
Generation identity ≠ Promotion authority ≠ Immutable provenance
```

**M0-INV-14** — Cold bootstrap MUST NOT report a trusted runtime when repository content changes during reconstruction.

---

### M0.17 — Immutable promotion evidence

Commit `01128762502d7133fe2f52fcdc971a53f32862bd` — [specification](https://github.com/Abdus2023/Agentic-Native-Stack/blob/main/ouroboros/M0/verification/M0_17_immutable_promotion_evidence.md).

```
GENERATION                 = identity
VERIFICATION               = evidence
PROMOTION                  = runtime authorization
IMMUTABLE / EXTERNAL ANCHOR = independent authority

self-written "promoted" file ≠ proof of promotion
```

**M0-INV-15** — Promotion MUST never derive independent authority from a mutable repository claim that the runtime itself can rewrite.

A fake `.promotion/current` mechanism was deliberately *not* added — it would create a self-attesting trust loop.

---

### M0.18 — Evidence object

Commits `f3f50cbfe4bdb59bd317e8d04ee7f1d15300e88c` (object), `f0224aaf8939dfb833575396d008cf64395702d4` (`PromotionAuthority` accepts only `VerificationEvidence`), `bd340f3e39c5d2c612f72a819b3fdd8df845b1b8` (kernel wiring).

`VerificationEvidence` is immutable and binds `run_id + generation + verification_epoch + complete gate results`. Validity requires:

```
ALL gates == PASS
AND all results.generation == evidence.generation
AND all results.epoch == evidence.epoch
AND current repository generation == evidence.generation
```

Promotion path:

```
Verifier → VerificationReport → capture_evidence() → VerificationEvidence (frozen)
  → PromotionAuthority
        ├── run identity
        ├── generation
        ├── epoch
        ├── every gate PASS
        └── repository still current
  → PROMOTED
```

`Kernel.execute()` invalidates previously captured evidence (`new action → evidence = None`), so a successful verification cannot silently survive a subsequent mutation.

---

### M0.19 — Evidence integrity

Commits `01f0be9f7e39d2cc5b2dde88b4788effb362f9c0` (canonical digest), `47a4f4738083302a9d3aca221d7803cf11bd1e92` (promotion rejects invalid evidence).

```
VerificationResult[] → canonical serialization → SHA-256
  → VerificationEvidence.digest → integrity_valid() → PromotionAuthority
```

Promotion rejects: wrong run, empty evidence, invalid digest, stale generation, stale epoch, non-PASS gate, repository changed.

---

### M0.20 — Required gate completeness

Commit `30bfe687b4cdcbcd5af507d55f906dc36a370608`.

```
RequiredGates = R
EvidenceGates = E

Promotion eligibility requires:
  E == R
  AND every result == PASS
  AND every result.generation == G
  AND every result.epoch == EPOCH
  AND evidence digest is valid
  AND repository generation == G
```

"All observed gates passed" is no longer equivalent to "the verification contract passed."

---

### M0.21 — Gate identity hardening

Commit `0290fb11e69c008c91c6c6d550c23728d4eb8c93`.

The verifier rejects ambiguous gate configurations **before execution**: non-empty names, no NUL/newline, unique names, valid commands. Duplicate gate names (`compileall`, `compileall`) are structurally invalid rather than producing ambiguous evidence.

---

### M0.22 — Gate configuration binding

Commits `24bb22910c8f2c500743a56adf7a2649c980da07`, `ddb182b409de54c750137840ad141ec044c4f25c`, `a310bb4047a307caba76f06d4d1e46d163104ab5` (promotion enforcement).

Evidence carries a **GateSet Digest** derived from `name + required + command`. Changing `python -m compileall -q ourob` to `python -m pytest` changes the identity even if the gate name remains `compileall`. Promotion reconstructs the current verifier gate contract and compares its digest with the one embedded in the evidence — fail-closed on mismatch.

Identity binding now exists at three levels: repository generation, verification epoch, verification contract.

---

### M0.23 — Canonical gate contract

Commits:

```
35a3a00  M0.23 define canonical gate contract
3e98123  M0.23 bind evidence to canonical gate contract
38a7bb7  M0.23 enforce kernel verifier contract at promotion
5cf4588  M0.23 test canonical gate contract identity
851dbf4  M0.23 test promotion gate contract binding
8f11f40  M0.23 document canonical gate contract
```

- Versioned canonical gate contract: `ouroboros.gate-contract.v1`.
- `Gate.canonical()` produces deterministic UTF-8 JSON, preserving command argument boundaries.
- Gate ordering normalized by unique gate name; `required` participates in the identity.
- Regression tests: order independence, required-flag changes, command changes, arguments containing spaces, stale epochs, changed contracts.

```
              CANDIDATE
                  │
                  ▼
           ┌─────────────┐
           │ Verification │
           └──────┬──────┘
   ┌──────────────┼──────────────┐
   ▼              ▼              ▼
generation      epoch      gate contract
   └──────────────┼──────────────┘
                  ▼
         Immutable Evidence
                  │
                  ▼
         Promotion Authority
                  │
          current contract?
             /         \
           YES          NO
            │            │
            ▼            ▼
         PROMOTE       DENY
```

No CI green is claimed for this state (no associated GitHub Actions run).

---

### M1.1 — Durable journal recovery

Commits `c313583d5aab384e44cedb6be596f7a6c67933e2` (durable `Event`), `7f50926f81b3851eaff15d54f8c8692f39acc733` (structured JSONL persistence), `295e23186cfe620361b9363ffe2eb2f6551cafbd` (`ourob/recovery.py`).

```
journal.jsonl
     │
     ▼
RUN_CREATED
     │
     ▼
replay events sequentially
     │
     ├── validate event
     ├── validate generation
     ├── validate state transition
     ├── restore verification epoch
     └── restore verification results
     │
     ▼
Recovered Run
```

Fails closed when: no records; `RUN_CREATED` isn't first; task/generation missing; unknown event; illegal transition; malformed generation/result/status.

Recovery does not infer privileged state: `VERIFIED`, `PROMOTABLE`, `PROMOTED` appear only through their durable transition records. Also fixed: `kernel.py` constructed `Event(...)` while `model.py` did not define it.

---

### M1.2 — Tamper-evident journal

Commits `9067f0f6c77443c38ea7ae60cf0a2b8e225d91d4`, `e82da172e1e2c7f6e796a08b9ae0ae2c8a3be54e`.

```
record[1]
  previous_digest = GENESIS
  digest = H(record[1])

record[n]
  previous_digest = digest[n-1]
  digest = H(record[n])
```

Each record carries: version, monotonic sequence, previous_digest, UTC timestamp, event payload, SHA-256 digest.

Rejected: modified historical records, broken chains, reordered/missing records, invalid sequence numbers, unsupported versions, malformed JSON, truncated tails, appends after corruption.

---

### M1.3 — Crash recovery authority boundary

**Evidence durably reconstructable:** `VerificationEvidence.to_record()` / `from_record()`; digest recomputed and validated on recovery; complete gate results, required gates, generation, epoch, and gate-contract identity persisted.

**Kernel journals authority explicitly:** `AUTHORIZATION_GRANTED` is durable; re-execution from `OBSERVED` emits a fresh authorization event; successful verification emits `VERIFICATION_EVIDENCE_CAPTURED`; promotion records the exact evidence digest and gate-contract digest.

**Recovery is fail-closed:**

- `AUTHORIZED` cannot be inferred from `ACTION_EXECUTED`.
- `VERIFIED` cannot be inferred from `GATE_RESULT`.
- `PROMOTABLE` requires durable promotion authorization bound to recovered evidence.
- `PROMOTED` requires durable promotion authorization.
- Cross-run events, malformed evidence, invalid digests, incorrect epochs/generations, and invalid ordering are rejected.

Tests (`tests/test_recovery.py`): ordinary replay; forged authorization without durable planning; gate results without evidence capture; tampered evidence digest; promotion without evidence; complete valid chain through `PROMOTED`.

Files touched:

```
ouroboros/M0/ourob/evidence.py
ouroboros/M0/ourob/kernel.py
ouroboros/M0/ourob/recovery.py
ouroboros/M0/tests/test_recovery.py
ouroboros/M0/README.md
```

**Normative invariant:**

> No durable event → no recovered authority.

---

## 14. Invariant Index

| ID | Statement |
|---|---|
| M0-INV-01 | Every mutation passes through the kernel. |
| M0-INV-02 | Every kernel action passes policy evaluation. |
| M0-INV-03 | PROMOTED requires current verification. |
| M0-INV-04 | Verification is bound to a repository generation. |
| M0-INV-05 | The journal is append-only. |
| M0-INV-06 | Bootstrap can reconstruct the runtime from repository state. |
| M0-INV-07 | The runtime can discover repository-declared skills. |
| M0-INV-08 | A capability can be added by the runtime itself. |
| M0-INV-09 | The newly added capability survives a cold bootstrap. |
| M0-INV-10 | Kernel/bootstrap/policy/verifier changes cannot use the ordinary mutation path. |
| M0-INV-11 | No planner output is authoritative verification evidence. |
| M0-INV-12 | A failed or blocked run cannot reach PROMOTED. |
| M0-INV-13 | Every dynamically reconstructed capability originates from a manifest-declared module resolved inside the bootstrapped repository generation. |
| M0-INV-14 | Cold bootstrap MUST NOT report a trusted runtime when repository content changes during reconstruction. |
| M0-INV-15 | Promotion MUST never derive independent authority from a mutable repository claim the runtime itself can rewrite. |
| M0-META-01 | The verification mechanism must itself be represented in the repository and included in the bootstrap trust boundary. |
| M1-INV-01 | No durable event → no recovered authority. |

---

## 15. Next Slice

**M1.4 — Durable journal durability semantics:**

- atomic append / locking
- fsync
- crash-tail policy
- journal checkpointing
- protection against whole-journal rewrite attacks
