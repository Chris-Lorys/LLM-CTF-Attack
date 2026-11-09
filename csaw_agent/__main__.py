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

import json as _json

from .challenge import ChallengeError, ChallengeRef, discover, server_target
from .compose import ComposeError, challenge_server, docker_available
from .llm import make_model, make_router
from .report import write_report
from .run import run_challenge
from .sandbox import Sandbox, SandboxError
from .trace import verify_trace


def _add_model_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--runs-dir", type=Path, default=Path("runs"))
    p.add_argument("--model", help="préréglage:modèle, p. ex. ollama:qwen2.5:3b, "
                   "groq:llama-3.3-70b-versatile ; sans --model, pré-scan seul")
    p.add_argument("--base-url", help="URL d'un service compatible OpenAI (Kaggle, vLLM...)")
    p.add_argument("--models", help="routage multi-modèles par catégorie, p. ex. "
                   "'crypto=openrouter:deepseek/deepseek-r1:free,"
                   "pwn=openrouter:moonshotai/kimi-k2.6:free,default=gemini:gemini-3.8-flash' "
                   "(remplace --model ; la clé de chaque fournisseur est lue dans "
                   "<FOURNISSEUR>_API_KEY, p. ex. OPENROUTER_API_KEY, GEMINI_API_KEY)")
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


def _compose_path(json_path: Path) -> Path | None:
    for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        candidate = json_path.parent / name
        if candidate.is_file():
            return candidate
    return None


def _challenge_target(json_path: Path):
    try:
        meta = _json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, _json.JSONDecodeError):
        return None
    return server_target(meta) if isinstance(meta, dict) else None


def _run_one(ref: ChallengeRef, runs_dir: Path, model, max_steps: int, sandbox,
             *, skip_server: bool, docker: bool, router=None) -> dict:
    """Résout un challenge, en démarrant son conteneur si c'est un challenge à serveur."""
    if ref.needs_server:
        target = _challenge_target(ref.json_path)
        compose = _compose_path(ref.json_path)
        if docker and target is not None and compose is not None:
            try:
                with challenge_server(compose, target) as local:
                    from .net import NetworkClient
                    return run_challenge(ref.json_path, runs_dir, model, max_steps,
                                         sandbox, net=NetworkClient(local), router=router)
            except ComposeError as exc:
                return {"status": "erreur_serveur", "error": str(exc)}
        if skip_server:
            return {"status": "ignore_serveur"}
        # Ni Docker ni --skip-server : on tente sur les seuls fichiers fournis.
    try:
        return run_challenge(ref.json_path, runs_dir, model, max_steps, sandbox, router=router)
    except ChallengeError as exc:
        return {"status": "erreur_challenge", "error": str(exc)}
    except Exception as exc:  # un challenge qui plante ne doit pas arrêter le lot
        traceback.print_exc()
        return {"status": "erreur_interne", "error": f"{type(exc).__name__}: {exc}"}


def run_all(root: Path, runs_dir: Path, model, max_steps: int, *,
            categories: list[str] | None = None, only: list[str] | None = None,
            skip_server: bool = False, sandbox=None, docker: bool = False, router=None) -> list[dict]:
    """Lance l'agent sur chaque challenge de la base et écrit un bilan.

    Les challenges à serveur (champ `compose` de la base CSAW) ne sont lancés
    que si `docker` est vrai : leur conteneur est alors démarré et l'agent reçoit
    un outil réseau (`http` ou `connect`) borné à ce service. Sans Docker, ou
    avec `skip_server`, ils sont notés `ignore_serveur`.

    Avec `router`, le modèle est choisi par catégorie (routage multi-modèles).
    """
    results = []
    runs_dir = Path(runs_dir)
    docker_ok = docker and docker_available()
    if docker and not docker_ok:
        print("Docker demandé mais indisponible : challenges à serveur ignorés.", flush=True)
    for ref in select(discover(root), categories, only):
        summary = _run_one(ref, runs_dir, model, max_steps, sandbox,
                           skip_server=skip_server, docker=docker_ok, router=router)
        summary.update(id=ref.id, category_db=ref.category, challenge=str(ref.json_path))
        results.append(summary)
        print(f"{summary['status']:<20} {ref.category:<10} {ref.id}", flush=True)
        # Rendre la cause visible dans les journaux (l'artefact n'est pas toujours
        # accessible) : erreur de modèle, de serveur ou interne.
        if summary["status"].startswith("erreur") and summary.get("error"):
            print(f"  └─ {summary['error']}", file=sys.stderr, flush=True)
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
    p_all.add_argument("--docker", action="store_true",
                       help="démarrer le conteneur des challenges à serveur (Docker requis) "
                       "et donner à l'agent un outil réseau borné à ce service")

    p_list = sub.add_parser("list", help="lister les challenges d'une base")
    p_list.add_argument("root", type=Path)
    _add_select_args(p_list)

    p_verify = sub.add_parser("verify-trace", help="vérifier l'intégrité d'une trace")
    p_verify.add_argument("trace", type=Path)

    p_report = sub.add_parser("report", help="régénérer le rapport d'un run")
    p_report.add_argument("trace", type=Path)

    args = parser.parse_args(argv)

    if args.command in ("run", "run-all"):
        router = None
        model = None
        try:
            if args.models:
                router = make_router(args.models, args.base_url)
            elif args.model:
                model = make_model(args.model, args.base_url)
        except ValueError as exc:
            print(f"erreur : {exc}", file=sys.stderr)
            return 2
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
                              skip_server=args.skip_server, sandbox=sandbox,
                              docker=args.docker, router=router)
            launched = [r for r in results if r["status"] != "ignore_serveur"]
            return 0 if launched and all(r["status"] == "resolu" for r in launched) else 1
        try:
            summary = run_challenge(args.challenge_json, args.runs_dir, model, args.max_steps,
                                    sandbox, router=router)
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
