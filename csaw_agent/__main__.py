"""Ligne de commande.

    python -m csaw_agent run chemin/vers/challenge.json
    python -m csaw_agent run chemin/vers/challenge.json --model ollama:qwen2.5:3b
    python -m csaw_agent run-all dossier/de/challenges --model ollama:qwen2.5:7b
    python -m csaw_agent verify-trace runs/<challenge>/<horodatage>/trace.jsonl
    python -m csaw_agent report runs/<challenge>/<horodatage>/trace.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .challenge import ChallengeError
from .llm import make_model
from .report import write_report
from .run import run_challenge
from .trace import verify_trace


def _add_model_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--runs-dir", type=Path, default=Path("runs"))
    p.add_argument("--model", help="préréglage:modèle, p. ex. ollama:qwen2.5:3b, "
                   "groq:llama-3.3-70b-versatile ; sans --model, pré-scan seul")
    p.add_argument("--base-url", help="URL d'un service compatible OpenAI (Kaggle, vLLM...)")
    p.add_argument("--max-steps", type=int, default=20)


def run_all(root: Path, runs_dir: Path, model, max_steps: int) -> list[dict]:
    """Lance l'agent sur chaque challenge.json trouvé sous `root` et écrit un bilan."""
    results = []
    for path in sorted(Path(root).rglob("challenge.json")):
        try:
            summary = run_challenge(path, runs_dir, model, max_steps)
        except ChallengeError as exc:
            summary = {"status": "erreur_challenge", "error": str(exc)}
        summary["challenge"] = str(path)
        results.append(summary)
        print(f"{summary['status']:<20} {path}", flush=True)
    solved = sum(r["status"] == "resolu" for r in results)
    print(f"\n{solved}/{len(results)} challenge(s) résolu(s)")
    runs_dir.mkdir(parents=True, exist_ok=True)
    (runs_dir / "bilan.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="csaw_agent")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="résoudre un challenge")
    p_run.add_argument("challenge_json", type=Path)
    _add_model_args(p_run)

    p_all = sub.add_parser("run-all", help="résoudre tous les challenges d'un dossier")
    p_all.add_argument("root", type=Path)
    _add_model_args(p_all)

    p_verify = sub.add_parser("verify-trace", help="vérifier l'intégrité d'une trace")
    p_verify.add_argument("trace", type=Path)

    p_report = sub.add_parser("report", help="régénérer le rapport d'un run")
    p_report.add_argument("trace", type=Path)

    args = parser.parse_args(argv)

    if args.command in ("run", "run-all"):
        model = make_model(args.model, args.base_url) if args.model else None
        if args.command == "run-all":
            results = run_all(args.root, args.runs_dir, model, args.max_steps)
            return 0 if results and all(r["status"] == "resolu" for r in results) else 1
        try:
            summary = run_challenge(args.challenge_json, args.runs_dir, model, args.max_steps)
        except ChallengeError as exc:
            print(f"erreur : {exc}", file=sys.stderr)
            return 2
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0 if summary["status"] == "resolu" else 1

    if args.command == "report":
        print(write_report(args.trace))
        return 0

    ok, message = verify_trace(args.trace)
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
