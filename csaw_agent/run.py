"""Orchestration d'un run : ingestion, pré-scan déterministe, boucle LLM, fin.

Ce module fixe ce que tout run doit respecter : un dossier par run, une trace
écrite par le code, un flag vérifié hors LLM. Le LLM n'intervient que si le
pré-scan, gratuit et déterministe, n'a rien trouvé.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from pathlib import Path

from .agent import Agent
from .briefing import build_briefing
from .challenge import Challenge, load_challenge
from .flag import FlagVerifier, find_candidates
from .llm import ChatModel
from .report import write_report
from .tools import Toolbox
from .trace import TraceWriter

_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def _readable_strings(data: bytes, min_len: int = 4) -> str:
    """Équivalent simple de `strings` : suites de caractères imprimables."""
    return "\n".join(m.decode() for m in re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data))


def prescan(challenge: Challenge, verifier: FlagVerifier, trace: TraceWriter,
            tried: set[str] | None = None) -> str | None:
    """Cherche un flag en clair dans la description et les fichiers.

    Pas de LLM ici : regex puis vérification. Couvre les cas triviaux et
    sert de test de bout en bout du socle.
    """
    sources = {"description": challenge.description}
    for f in challenge.files:
        sources[f.name] = _readable_strings(f.path.read_bytes())

    for source, text in sources.items():
        candidates = find_candidates(text)
        trace.log("tool_result", {"tool": "prescan", "source": source,
                                  "candidates": candidates})
        for candidate in candidates:
            if tried is not None:
                tried.add(candidate)
            ok = verifier.check(candidate)
            trace.log("check_flag", {"candidate": candidate, "source": source, "valid": ok})
            if ok:
                return candidate
    return None


MAX_INDICE = 500


class IndiceError(ValueError):
    """Indice humain refusé (vide, trop long, ou contenant un flag)."""


def valider_indice(indice: str) -> str:
    """Un indice humain oriente l'agent, il ne doit jamais contenir la réponse.

    Règlement CSAW : l'humain peut donner des indices, la solution doit venir de
    l'IA. On refuse donc tout indice qui contient une chaîne au format d'un flag.
    """
    texte = indice.strip()
    if not texte:
        raise IndiceError("indice vide")
    if len(texte) > MAX_INDICE:
        raise IndiceError(f"indice trop long ({len(texte)} > {MAX_INDICE} caractères)")
    if find_candidates(texte):
        raise IndiceError("un indice ne doit contenir aucun flag")
    return texte


def run_challenge(json_path: Path, runs_dir: Path = Path("runs"),
                  model: ChatModel | None = None, max_steps: int = 20,
                  sandbox=None, net=None, router=None, ablation=None,
                  indice: str | None = None, cascade=None) -> dict:
    if indice is not None:  # refusé avant de créer quoi que ce soit
        indice = valider_indice(indice)
    started = time.monotonic()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = Path(runs_dir) / _SAFE.sub("_", Path(json_path).parent.name) / stamp
    run_dir.mkdir(parents=True, exist_ok=False)

    trace = TraceWriter(run_dir / "trace.jsonl")
    trace.log("start", {"challenge_json": str(json_path)})

    challenge, verifier = load_challenge(json_path, run_dir)
    trace.log("ingestion", challenge.to_view())
    # Approche hybride : l'indice humain est consigné mot pour mot, avant tout appel
    # au modèle, dans la trace chaînée. Il est donc impossible de l'ajouter ou de
    # le modifier après coup sans que verify-trace le détecte.
    if indice is not None:
        trace.log("ingestion", {"indice_humain": indice, "approche": "hybride"})

    # Routage multi-modèles : le modèle est choisi selon la catégorie du challenge.
    if router is not None:
        trace.log("ingestion", {"routeur": router.describe()})
        model = router.for_category(challenge.category)

    # Cascade frugale : on démarre sur le palier le moins cher.
    if cascade is not None:
        trace.log("ingestion", {"cascade": cascade.describe()})
        model = cascade.paliers[0]

    # En ablation, on peut retirer le pré-scan déterministe (variante B).
    tried: set[str] = set()
    if ablation is not None and not ablation.prescan:
        trace.log("ingestion", {"ablation": ablation.nom, "prescan": False})
        flag = None
    else:
        flag = prescan(challenge, verifier, trace, tried)
    status = "resolu" if flag else "non_resolu"
    category, steps, error = None, 0, None
    escalades: list[dict] = []

    if flag is None and model is not None:
        if sandbox is not None:
            trace.log("sandbox", sandbox.describe())
        if net is not None:
            trace.log("network", net.target.describe())
        toolbox = Toolbox(run_dir / "files", sandbox, net)
        # Variante E : plus d'outils déterministes, le LLM n'a que son raisonnement.
        if ablation is not None and not ablation.outils:
            toolbox.tools.clear()
            trace.log("ingestion", {"ablation": ablation.nom, "outils": False})
        # Briefing de faits rédigé par le code (variante F = retiré).
        briefing_txt = ""
        if ablation is None or ablation.briefing:
            briefing = build_briefing(challenge)
            briefing_txt = briefing.texte()
            trace.log("ingestion", {"briefing": {"faits": briefing.faits,
                                                 "fiches": len(briefing.fiches)}})
        agent = Agent(model, toolbox, verifier, trace, max_steps,
                      ablation=ablation, briefing=briefing_txt, indice=indice,
                      cascade=cascade)
        result = agent.solve(challenge, tried)
        model, escalades = agent.model, agent.escalades
        flag, category, steps, error = result.flag, result.category, result.steps, result.error
        status = result.status if result.status != "budget_epuise" else "non_resolu"

    summary = {
        "status": status,
        "flag": flag,
        "model": model.name if model else None,
        "category": category,
        "llm_steps": steps,
        "attempts": verifier.attempts,
        "duration_s": round(time.monotonic() - started, 3),
        "run_dir": str(run_dir),
        "approche": "hybride" if indice else "autonome",
    }
    if cascade is not None:
        summary["cascade"] = {**cascade.describe(), "escalades": escalades}
    if error:
        summary["error"] = error
    trace.log("end", summary)
    # Le rapport est tiré de la trace une fois celle-ci close : il n'y ajoute rien.
    summary["report"] = str(write_report(trace.path))
    return summary
