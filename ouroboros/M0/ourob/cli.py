"""Command line entry point: ``python -m ourob <command>``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .bootstrap import Bootstrap, BootstrapError
from .generation import repository_generation
from .journal import Journal, JournalIntegrityError
from .model import ActionKind
from .planner import AddCapabilityPlanner, ScriptedPlanner
from .recovery import (RecoveryError, list_runs, recover_from_journal, recover_from_signed_journal,
                       recover_from_trusted_journal)
from .signed_trust import SignedCheckpoint, SignedTrustError, TrustStore
from .trust import JournalTrustAnchor, TrustAnchorError


def _root(args: argparse.Namespace) -> Path:
    return Path(args.repo).resolve() if args.repo else Bootstrap().repo_root


def cmd_generation(args: argparse.Namespace) -> int:
    generation = repository_generation(_root(args))
    if args.manifest:
        print(json.dumps({"generation": generation.id, "files": generation.as_dict()}, indent=2, sort_keys=True))
    else:
        print(generation.id)
    return 0


def cmd_bootstrap(args: argparse.Namespace) -> int:
    result = Bootstrap(_root(args)).cold_start()
    print(json.dumps(result.summary(), indent=2))
    return 0 if result.trusted else 1


def cmd_journal(args: argparse.Namespace) -> int:
    journal = Journal(_root(args) / ".ourob" / "journal.jsonl")
    try:
        records = journal.records()
    except JournalIntegrityError as exc:
        print(f"journal integrity failure: {exc}", file=sys.stderr)
        return 1
    if args.verify:
        print(f"journal ok: {len(records)} records")
        return 0
    if args.anchor:
        # Emit an anchor for the current head so an EXTERNAL authority can store it.
        anchor = JournalTrustAnchor.capture(records, repository_generation(_root(args)).id if args.bind_generation else None)
        print(json.dumps(anchor.to_record()))
        return 0
    for record in records:
        event = record.event
        print(f"{record.sequence:5d} {event.name:32s} run={event.run_id} action={event.action_id or '-'}")
    return 0


def cmd_recover(args: argparse.Namespace) -> int:
    journal_path = _root(args) / ".ourob" / "journal.jsonl"
    try:
        if not args.run:
            for run_id in list_runs(journal_path):
                print(run_id)
            return 0
        if args.checkpoint and args.trust_store:
            checkpoint = SignedCheckpoint.from_record(json.loads(Path(args.checkpoint).read_text()))
            store = TrustStore.from_record(json.loads(Path(args.trust_store).read_text()))
            recovered = recover_from_signed_journal(journal_path, args.run, checkpoint, store)
        elif args.anchor:
            anchor = JournalTrustAnchor.from_record(json.loads(Path(args.anchor).read_text()))
            recovered = recover_from_trusted_journal(journal_path, args.run, anchor)
        elif args.checkpoint or args.trust_store:
            print("signed recovery requires both --checkpoint and --trust-store", file=sys.stderr)
            return 2
        else:
            recovered = recover_from_journal(journal_path, args.run)
    except (RecoveryError, JournalIntegrityError, TrustAnchorError, SignedTrustError, OSError, ValueError) as exc:
        print(f"recovery refused: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "run": recovered.run.id,
        "task": recovered.run.task,
        "state": recovered.run.state.value,
        "generation": recovered.run.generation,
        "epoch": recovered.run.verification_epoch,
        "executed": list(recovered.run.executed_ids),
        "evidence": recovered.evidence.digest if recovered.evidence else None,
    }, indent=2))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    bootstrap = Bootstrap(_root(args))
    try:
        kernel = bootstrap.kernel()
    except BootstrapError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if args.plan:
        plan = ScriptedPlanner(Path(args.plan)).propose(args.task)
    elif args.add_capability:
        plan = AddCapabilityPlanner(bootstrap.repo_root, args.add_capability).propose(args.task)
    else:
        print("run requires --plan FILE or --add-capability NAME", file=sys.stderr)
        return 2
    run = kernel.run_plan(args.run_id, plan)
    print(json.dumps({"run": run.id, "state": run.state.value, "generation": run.generation,
                      "epoch": run.verification_epoch}, indent=2))
    return 0 if run.state.value == "PROMOTED" else 1


def cmd_skills(args: argparse.Namespace) -> int:
    result = Bootstrap(_root(args)).cold_start()
    if not result.trusted:
        print("untrusted bootstrap: " + "; ".join(result.errors), file=sys.stderr)
        return 1
    if args.call:
        arguments = json.loads(args.arguments or "{}")
        print(result.registry.call(args.call, arguments, ActionKind.EXECUTE if args.call not in
                                   ("filesystem.read", "filesystem.write", "filesystem.search") else None))
        return 0
    for name in result.registry.names():
        print(name)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ourob", description="OUROBOROS repository-native engineering runtime")
    parser.add_argument("--repo", help="repository root (default: auto-detected)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("generation", help="print the current repository generation")
    p.add_argument("--manifest", action="store_true")
    p.set_defaults(func=cmd_generation)

    p = sub.add_parser("bootstrap", help="cold-start and report trust")
    p.set_defaults(func=cmd_bootstrap)

    p = sub.add_parser("journal", help="list or verify the journal")
    p.add_argument("--verify", action="store_true")
    p.add_argument("--anchor", action="store_true", help="print a trust anchor for the current head (store it externally)")
    p.add_argument("--bind-generation", action="store_true")
    p.set_defaults(func=cmd_journal)

    p = sub.add_parser("recover", help="recover a run from the journal")
    p.add_argument("--run")
    p.add_argument("--anchor", help="path to an externally held trust anchor JSON (M1.5)")
    p.add_argument("--checkpoint", help="path to a signed checkpoint JSON (M1.6)")
    p.add_argument("--trust-store", help="path to the public trust store JSON (M1.6)")
    p.set_defaults(func=cmd_recover)

    p = sub.add_parser("run", help="drive a plan through the full lifecycle")
    p.add_argument("--run-id", required=True)
    p.add_argument("--task", required=True)
    p.add_argument("--plan")
    p.add_argument("--add-capability")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("skills", help="list or call cold-booted capabilities")
    p.add_argument("--call")
    p.add_argument("--arguments")
    p.set_defaults(func=cmd_skills)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
