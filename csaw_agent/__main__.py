"""Ligne de commande.

    python -m csaw_agent run chemin/vers/challenge.json
    python -m csaw_agent verify-trace runs/<challenge>/<horodatage>/trace.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .challenge import ChallengeError
from .run import run_challenge
from .trace import verify_trace


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="csaw_agent")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="résoudre un challenge")
    p_run.add_argument("challenge_json", type=Path)
    p_run.add_argument("--runs-dir", type=Path, default=Path("runs"))

    p_verify = sub.add_parser("verify-trace", help="vérifier l'intégrité d'une trace")
    p_verify.add_argument("trace", type=Path)

    args = parser.parse_args(argv)

    if args.command == "run":
        try:
            summary = run_challenge(args.challenge_json, args.runs_dir)
        except ChallengeError as exc:
            print(f"erreur : {exc}", file=sys.stderr)
            return 2
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0 if summary["status"] == "resolu" else 1

    ok, message = verify_trace(args.trace)
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
