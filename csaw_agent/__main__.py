"""Ligne de commande.

    python -m csaw_agent run chemin/vers/challenge.json
    python -m csaw_agent run chemin/vers/challenge.json --model ollama:qwen2.5:3b
    python -m csaw_agent run-all dossier/de/challenges --model ollama:qwen2.5:7b
    python -m csaw_agent run-all CSAW26_LLMAC_DB/dataset.json --skip-server --model ...
    python -m csaw_agent list CSAW26_LLMAC_DB/dataset.json
    python -m csaw_agent verify-trace runs/<challenge>/<horodatage>/trace.jsonl
    python -m csaw_agent report runs/<challenge>/<horodatage>/trace.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

from .challenge import ChallengeError, ChallengeRef, discover
from .llm import make_model
from .report import write_report
from .run import run_challenge
from .sandbox import Sandbox, SandboxError
from .trace import verify_trace


def _add_model_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--runs-dir", type=Path, default=Path("runs"))
    p.add_argument("--model", help="préréglage:modèle, p. ex. ollama:qwen2.5:3b, "
                   "groq:llama-3.3-70b-versatile ; sans --model, pré-scan seul")
    p.add_argument("--base-url", help="URL d'un service compatible OpenAI (Kaggle, vLLM...)")
    p.add_argument("--max-steps", type=int, default=20)
    p.add_argument("--shell", action="store_true",
                   help="donner au LLM un shell en bac à sable (root requis, voir sandbox.py)")
    p.add_argument("--sandbox-user", default="ctfsandbox")
    p.add_argument("--protect", action="append", type=Path, default=[],
                   help="chemin rendu illisible pour le shell (répétable) ; "
                   "run-all y ajoute la base de challenges")
    p.add_argument("--shell-avec-reseau", action="store_true",
                   help="ne pas isoler le réseau du shell (déconseillé)")


def _add_select_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--category", action="append", dest="categories",
                   help="ne garder que cette catégorie (option répétable)")
    p.add_argument("--only", action="append", help="identifiant de challenge (répétable)")


def select(refs: list[ChallengeRef], categories: list[str] | None = None,
           only: list[str] | None = None) -> list[ChallengeRef]:
    if categories:
        refs = [r for r in refs if r.category in categories]
    if only:
        refs = [r for r in refs if r.id in only]
    return refs


def run_all(root: Path, runs_dir: Path, model, max_steps: int, *,
            categories: list[str] | None = None, only: list[str] | None = None,
            skip_server: bool = False, sandbox=None) -> list[dict]:
    """Lance l'agent sur chaque challenge de la base et écrit un bilan.

    Avec `skip_server`, les challenges qui demandent un service réseau (champ
    `compose` de la base CSAW) sont notés `ignore_serveur` sans être lancés :
    l'agent n'a pas encore d'outil réseau ni de conteneur pour les servir.
    """
    results = []
    runs_dir = Path(runs_dir)
    for ref in select(discover(root), categories, only):
        if skip_server and ref.needs_server:
            summary = {"status": "ignore_serveur"}
        else:
            try:
                summary = run_challenge(ref.json_path, runs_dir, model, max_steps, sandbox)
            except ChallengeError as exc:
                summary = {"status": "erreur_challenge", "error": str(exc)}
            except Exception as exc:  # un challenge qui plante ne doit pas arrêter le lot
                traceback.print_exc()
                summary = {"status": "erreur_interne", "error": f"{type(exc).__name__}: {exc}"}
        summary.update(id=ref.id, category_db=ref.category, challenge=str(ref.json_path))
        results.append(summary)
        print(f"{summary['status']:<20} {ref.category:<10} {ref.id}", flush=True)
        _write_bilan(runs_dir, results)  # écrit après chaque challenge
    launched = [r for r in results if r["status"] != "ignore_serveur"]
    solved = sum(r["status"] == "resolu" for r in results)
    print(f"\n{solved}/{len(launched)} challenge(s) lancé(s) résolu(s)"
          f" ; {len(results) - len(launched)} ignoré(s) faute de serveur")
    _write_bilan(runs_dir, results)
    return results


def _write_bilan(runs_dir: Path, results: list[dict]) -> None:
    runs_dir.mkdir(parents=True, exist_ok=True)
    tmp = runs_dir / "bilan.json.tmp"
    tmp.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(runs_dir / "bilan.json")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="csaw_agent")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="résoudre un challenge")
    p_run.add_argument("challenge_json", type=Path)
    _add_model_args(p_run)

    p_all = sub.add_parser("run-all", help="résoudre tous les challenges d'un dossier")
    p_all.add_argument("root", type=Path, help="dossier de challenges ou dataset.json")
    _add_model_args(p_all)
    _add_select_args(p_all)
    p_all.add_argument("--skip-server", action="store_true",
                       help="ne pas lancer les challenges qui demandent un serveur")

    p_list = sub.add_parser("list", help="lister les challenges d'une base")
    p_list.add_argument("root", type=Path)
    _add_select_args(p_list)

    p_verify = sub.add_parser("verify-trace", help="vérifier l'intégrité d'une trace")
    p_verify.add_argument("trace", type=Path)

    p_report = sub.add_parser("report", help="régénérer le rapport d'un run")
    p_report.add_argument("trace", type=Path)

    args = parser.parse_args(argv)

    if args.command in ("run", "run-all"):
        model = make_model(args.model, args.base_url) if args.model else None
        sandbox = None
        if args.shell:
            protected = list(args.protect)
            if args.command == "run-all":
                base = args.root if args.root.is_dir() else args.root.parent
                protected.append(base)
            else:
                protected.append(args.challenge_json.parent)
            try:
                sandbox = Sandbox(args.sandbox_user, protected,
                                  isolate_network=not args.shell_avec_reseau)
            except SandboxError as exc:
                print(f"erreur : {exc}", file=sys.stderr)
                return 2
            print(f"shell en bac à sable : {sandbox.describe()}", file=sys.stderr)
        if args.command == "run-all":
            results = run_all(args.root, args.runs_dir, model, args.max_steps,
                              categories=args.categories, only=args.only,
                              skip_server=args.skip_server, sandbox=sandbox)
            launched = [r for r in results if r["status"] != "ignore_serveur"]
            return 0 if launched and all(r["status"] == "resolu" for r in launched) else 1
        try:
            summary = run_challenge(args.challenge_json, args.runs_dir, model, args.max_steps,
                                    sandbox)
        except ChallengeError as exc:
            print(f"erreur : {exc}", file=sys.stderr)
            return 2
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0 if summary["status"] == "resolu" else 1

    if args.command == "list":
        refs = select(discover(args.root), args.categories, args.only)
        for r in refs:
            print(f"{r.id:<45} {r.category:<10} {'serveur' if r.needs_server else 'fichiers'}")
        print(f"\n{len(refs)} challenge(s), dont {sum(r.needs_server for r in refs)} avec serveur")
        return 0

    if args.command == "report":
        print(write_report(args.trace))
        return 0

    ok, message = verify_trace(args.trace)
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
