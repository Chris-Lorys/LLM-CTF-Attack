"""Ligne de commande.

    python -m csaw_agent run chemin/vers/challenge.json
    python -m csaw_agent run chemin/vers/challenge.json --model ollama:qwen2.5:3b
    python -m csaw_agent run-all dossier/de/challenges --model ollama:qwen2.5:7b
    python -m csaw_agent run-all CSAW26_LLMAC_DB/dataset.json --skip-server --model ...
    python -m csaw_agent list CSAW26_LLMAC_DB/dataset.json
    python -m csaw_agent verify-trace runs/<challenge>/<horodatage>/trace.jsonl
    python -m csaw_agent report runs/<challenge>/<horodatage>/trace.jsonl
    python -m csaw_agent soumission essais/<id1> essais/<id2> --out soumission
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
from .run import IndiceError, run_challenge, valider_indice
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
    p.add_argument("--cascade", help="cascade frugale : 'preset:modele_gratuit>preset:modele_fort' ; "
                   "le code passe au palier suivant quand la progression mesurée stagne "
                   "(remplace --model et --models)")
    p.add_argument("--patience", type=int, default=6,
                   help="cascade : étapes sans information nouvelle avant d'escalader")
    p.add_argument("--atelier", type=Path, help="dossier d'une bibliothèque d'outils que "
                   "l'agent écrit et réutilise d'un challenge à l'autre (agent forgeron)")
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
             *, skip_server: bool, docker: bool, router=None, indice=None,
             cascade=None, atelier=None) -> dict:
    """Résout un challenge, en démarrant son conteneur si c'est un challenge à serveur."""
    if ref.needs_server:
        target = _challenge_target(ref.json_path)
        compose = _compose_path(ref.json_path)
        if docker and target is not None and compose is not None:
            try:
                with challenge_server(compose, target) as local:
                    from .net import NetworkClient
                    try:
                        return run_challenge(ref.json_path, runs_dir, model, max_steps,
                                             sandbox, net=NetworkClient(local), router=router,
                                             indice=indice, cascade=cascade, atelier=atelier)
                    except ChallengeError as exc:
                        return {"status": "erreur_challenge", "error": str(exc)}
                    except Exception as exc:  # un challenge qui plante ne stoppe pas le lot
                        traceback.print_exc()
                        return {"status": "erreur_interne",
                                "error": f"{type(exc).__name__}: {exc}"}
            except ComposeError as exc:
                return {"status": "erreur_serveur", "error": str(exc)}
            except Exception as exc:  # garde-fou : démarrage/démontage du serveur
                traceback.print_exc()
                return {"status": "erreur_serveur", "error": f"{type(exc).__name__}: {exc}"}
        if skip_server:
            return {"status": "ignore_serveur"}
        # Ni Docker ni --skip-server : on tente sur les seuls fichiers fournis.
    try:
        return run_challenge(ref.json_path, runs_dir, model, max_steps, sandbox, router=router,
                             indice=indice, cascade=cascade, atelier=atelier)
    except ChallengeError as exc:
        return {"status": "erreur_challenge", "error": str(exc)}
    except Exception as exc:  # un challenge qui plante ne doit pas arrêter le lot
        traceback.print_exc()
        return {"status": "erreur_interne", "error": f"{type(exc).__name__}: {exc}"}


def run_all(root: Path, runs_dir: Path, model, max_steps: int, *,
            categories: list[str] | None = None, only: list[str] | None = None,
            skip_server: bool = False, sandbox=None, docker: bool = False, router=None,
            indices: dict[str, str] | None = None, cascade=None, atelier=None) -> list[dict]:
    """Lance l'agent sur chaque challenge de la base et écrit un bilan.

    Les challenges à serveur (champ `compose` de la base CSAW) ne sont lancés
    que si `docker` est vrai : leur conteneur est alors démarré et l'agent reçoit
    un outil réseau (`http` ou `connect`) borné à ce service. Sans Docker, ou
    avec `skip_server`, ils sont notés `ignore_serveur`.

    Avec `router`, le modèle est choisi par catégorie (routage multi-modèles).
    Avec `indices` ({identifiant: indice}), les challenges concernés sont joués en
    approche hybride : l'indice humain est ajouté au prompt et consigné dans la trace.
    """
    results = []
    runs_dir = Path(runs_dir)
    docker_ok = docker and docker_available()
    if docker and not docker_ok:
        print("Docker demandé mais indisponible : challenges à serveur ignorés.", flush=True)
    for ref in select(discover(root), categories, only):
        summary = _run_one(ref, runs_dir, model, max_steps, sandbox,
                           skip_server=skip_server, docker=docker_ok, router=router,
                           indice=(indices or {}).get(ref.id), cascade=cascade, atelier=atelier)
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
    p_run.add_argument("--indice", help="approche hybride : indice humain (jamais la solution "
                       "ni un flag), ajouté au prompt et consigné dans la trace")
    _add_model_args(p_run)

    p_all = sub.add_parser("run-all", help="résoudre tous les challenges d'un dossier")
    p_all.add_argument("root", type=Path, help="dossier de challenges ou dataset.json")
    _add_model_args(p_all)
    _add_select_args(p_all)
    p_all.add_argument("--indices", type=Path,
                       help="approche hybride : fichier JSON {identifiant: indice humain}")
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

    p_sub = sub.add_parser("soumission",
                           help="assembler transcripts/ et ancillary/ à partir d'essais")
    p_sub.add_argument("essais", type=Path, nargs="+",
                       help="dossiers runs/ téléchargés, dans l'ordre chronologique")
    p_sub.add_argument("--out", type=Path, default=Path("soumission"))

    p_abl = sub.add_parser("ablation",
                           help="lancer la matrice d'ablation (variantes × challenges)")
    p_abl.add_argument("root", type=Path, help="dossier de challenges ou dataset.json")
    _add_model_args(p_abl)
    _add_select_args(p_abl)
    p_abl.add_argument("--variante", action="append", dest="variantes",
                       help="ne jouer que cette variante (répétable ; défaut : toutes)")
    p_abl.add_argument("--out", type=Path, default=Path("ablation.json"))

    p_anal = sub.add_parser("ablation-traces",
                            help="analyse rétrospective de traces existantes (coût nul)")
    p_anal.add_argument("traces", type=Path, nargs="+", help="fichiers trace.jsonl")
    p_anal.add_argument("--out", type=Path, default=Path("ablation-retrospective.json"))

    p_cas = sub.add_parser("cascade-traces",
                           help="évaluer la cascade frugale en rejouant des traces (coût nul)")
    p_cas.add_argument("traces", type=Path, nargs="+", help="fichiers trace.jsonl")
    p_cas.add_argument("--out", type=Path, default=Path("cascade-retrospective.json"))

    p_ech = sub.add_parser("echecs",
                           help="dossier de ce que l'agent a tenté sur les non-résolus (coût nul)")
    p_ech.add_argument("traces", type=Path, nargs="+", help="fichiers trace.jsonl")
    p_ech.add_argument("--out", type=Path, default=Path("echecs.md"))

    args = parser.parse_args(argv)

    if args.command == "cascade-traces":
        from .cascade import (escalades_reelles, evaluer_cascade, tableau_cascade,
                              tableau_escalades)
        resultat = evaluer_cascade(args.traces)
        resultat["runs_cascade"] = escalades_reelles(args.traces)
        args.out.write_text(json.dumps(resultat, ensure_ascii=False, indent=2), encoding="utf-8")
        print(tableau_cascade(resultat))
        print("\nRuns joués avec la cascade :\n" + tableau_escalades(resultat["runs_cascade"]))
        return 0

    if args.command == "echecs":
        from .echecs import dossier_echecs
        texte = dossier_echecs(args.traces)
        args.out.write_text(texte, encoding="utf-8")
        print(texte)
        return 0

    if args.command == "ablation-traces":
        from .ablation import analyser_traces
        summary = analyser_traces(args.traces)
        args.out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({k: v for k, v in summary.items() if k != "detail"},
                         ensure_ascii=False, indent=2))
        return 0

    if args.command == "ablation":
        from .ablation import run_ablation, tableau_markdown, variante as _variante
        if not args.only:
            print("erreur : précise les challenges avec --only (challenges à fichiers)",
                  file=sys.stderr)
            return 2
        try:
            if args.models or args.cascade:
                print("erreur : l'ablation fixe un modèle unique (--model), "
                      "pas --models ni --cascade", file=sys.stderr)
                return 2
            model = make_model(args.model, args.base_url) if args.model else None
        except ValueError as exc:
            print(f"erreur : {exc}", file=sys.stderr)
            return 2
        if model is None:
            print("erreur : l'ablation exige un modèle (--model)", file=sys.stderr)
            return 2
        variantes = [_variante(n) for n in args.variantes] if args.variantes else None
        sandbox_factory = None
        if args.shell:
            base = args.root if args.root.is_dir() else args.root.parent
            protected = list(args.protect) + [base]

            def sandbox_factory():
                return Sandbox(args.sandbox_user, protected,
                               isolate_network=not args.shell_avec_reseau)
        summary = run_ablation(args.root, args.only, args.runs_dir, model, args.max_steps,
                               sandbox_factory=sandbox_factory, variantes=variantes)
        args.out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        print("\n" + tableau_markdown(summary))
        return 0

    if args.command == "soumission":
        from .soumission import assemble
        summary = assemble(args.essais, args.out)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 1 if summary["traces_rejetees"] else 0

    if args.command in ("run", "run-all"):
        router = None
        model = None
        cascade = None
        try:
            if args.cascade:
                from .cascade import make_cascade
                spec = args.cascade
                if spec.startswith("@"):  # spec lue dans un fichier (workflow : « > » hors du shell)
                    spec = Path(spec[1:]).read_text(encoding="utf-8").strip()
                cascade = make_cascade(spec, args.base_url, patience=args.patience)
            elif args.models:
                router = make_router(args.models, args.base_url)
            elif args.model:
                model = make_model(args.model, args.base_url)
        except (OSError, ValueError) as exc:
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
        atelier = None
        if args.atelier is not None:
            from .atelier import Atelier
            atelier = Atelier(args.atelier)
        if args.command == "run-all":
            indices = None
            if args.indices is not None:
                try:
                    indices = json.loads(args.indices.read_text(encoding="utf-8"))
                    if not isinstance(indices, dict):
                        raise ValueError("objet JSON {identifiant: indice} attendu")
                    for cid, txt in indices.items():
                        valider_indice(str(txt))
                except (OSError, ValueError) as exc:
                    print(f"erreur : indices refusés : {exc}", file=sys.stderr)
                    return 2
            results = run_all(args.root, args.runs_dir, model, args.max_steps,
                              categories=args.categories, only=args.only,
                              skip_server=args.skip_server, sandbox=sandbox,
                              docker=args.docker, router=router, indices=indices,
                              cascade=cascade, atelier=atelier)
            launched = [r for r in results if r["status"] != "ignore_serveur"]
            return 0 if launched and all(r["status"] == "resolu" for r in launched) else 1
        try:
            summary = run_challenge(args.challenge_json, args.runs_dir, model, args.max_steps,
                                    sandbox, router=router, indice=args.indice,
                                    cascade=cascade, atelier=atelier)
        except (ChallengeError, IndiceError) as exc:
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
