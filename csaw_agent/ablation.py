"""Étude d'ablation : mesurer la contribution de chaque brique « par retrait ».

La thèse de l'agent (chap. 4 du cours, « construire l'agent par retrait ») est
que chaque tâche doit revenir au composant le plus simple qui la fait bien, le
LLM gardant ce qu'il fait de mieux. On la met à l'épreuve en retirant une brique
à la fois et en mesurant l'effet, le modèle et le jeu de challenges restant
fixes.

Variantes :
- A_reference    : agent complet.
- B_sans_prescan : on retire la radiographie déterministe initiale.
- C_sans_autoverif : les candidats trouvés dans les sorties d'outils ne sont plus
  vérifiés automatiquement ; le LLM doit appeler check_flag lui-même.
- D_sans_memoire : plus de mémoire de travail (notes + garde anti-répétition).
- E_sans_outils  : plus d'outils déterministes ; le LLM n'a que son raisonnement.

Dans tous les cas, `check_flag` reste hors LLM : aucune variante ne peut déclarer
un faux flag. On mesure donc l'effet sur la *réussite* et le *coût* (étapes LLM),
jamais sur l'intégrité, qui est garantie par construction.

Deux usages, sans dépense d'API pour le second :
- `run_ablation` : lance expérimentalement la matrice (variantes × challenges).
- `analyser_traces` : lecture rétrospective des traces déjà produites (quelle brique
  a réellement trouvé chaque flag, combien d'étapes évitées), à coût nul.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path


@dataclass(frozen=True)
class Ablation:
    """Interrupteurs de briques. Tout à True = agent de référence."""

    nom: str
    description: str
    prescan: bool = True        # pré-scan déterministe avant le LLM
    auto_verif: bool = True     # vérification auto des candidats dans les sorties d'outils
    memoire: bool = True        # notes retenues + garde anti-répétition
    outils: bool = True         # outils déterministes (sinon LLM seul)
    briefing: bool = True       # briefing de faits établis par le code au départ
    hypotheses: bool = True     # registre d'hypothèses suivi par le code


# La matrice : la référence, puis une brique retirée à la fois.
REFERENCE = Ablation("A_reference", "agent complet (toutes les briques)")
VARIANTES: list[Ablation] = [
    REFERENCE,
    replace(REFERENCE, nom="B_sans_prescan",
            description="sans pré-scan déterministe", prescan=False),
    replace(REFERENCE, nom="C_sans_autoverif",
            description="sans vérification auto des sorties d'outils", auto_verif=False),
    replace(REFERENCE, nom="D_sans_memoire",
            description="sans mémoire de travail (notes + anti-répétition)", memoire=False),
    replace(REFERENCE, nom="E_sans_outils",
            description="sans outils déterministes (LLM seul)", outils=False),
    replace(REFERENCE, nom="F_sans_briefing",
            description="sans briefing de faits (prompt de départ générique)", briefing=False),
    replace(REFERENCE, nom="G_sans_hypotheses",
            description="sans registre d'hypothèses suivi par le code", hypotheses=False),
]


def variante(nom: str) -> Ablation:
    for v in VARIANTES:
        if v.nom == nom:
            return v
    raise KeyError(f"variante d'ablation inconnue : {nom!r} "
                   f"(connues : {', '.join(v.nom for v in VARIANTES)})")


# --- Analyse rétrospective (coût nul : lit des traces existantes) ------------

def _lire_trace(path: Path) -> list[dict]:
    records = []
    with Path(path).open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def analyser_trace(path: Path) -> dict:
    """Résume, pour une trace, ce que chaque brique a apporté.

    - `source_flag` : d'où vient le flag validé (prescan / auto:<outil> / llm / aucun).
    - `candidats_rejetes` : nombre de check_flag faux (gabarits trompeurs écartés).
    - `repetitions_bloquees` : actions identiques évitées par la garde.
    - `etapes_llm` : nombre d'actions du LLM.
    """
    records = _lire_trace(path)
    source_flag = None
    candidats_rejetes = 0
    repetitions = 0
    etapes = 0
    vu_tool_call = False
    for r in records:
        typ = r.get("type")
        payload = r.get("payload", {})
        if typ == "tool_call":
            etapes += 1
            vu_tool_call = True
        elif typ == "check_flag":
            if payload.get("valid"):
                # Pré-scan : flag validé avant toute action du LLM.
                source_flag = "prescan" if not vu_tool_call else payload.get("source")
            else:
                candidats_rejetes += 1
        elif typ == "decision" and payload.get("repetition"):
            repetitions += 1
    return {
        "trace": str(path),
        "source_flag": source_flag,
        "candidats_rejetes": candidats_rejetes,
        "repetitions_bloquees": repetitions,
        "etapes_llm": etapes,
    }


def analyser_traces(paths: list[Path]) -> dict:
    """Agrège l'analyse rétrospective sur un ensemble de traces (résolues ou non)."""
    lignes = [analyser_trace(p) for p in paths]
    resolues = [l for l in lignes if l["source_flag"]]
    par_source: dict[str, int] = {}
    for l in resolues:
        par_source[l["source_flag"]] = par_source.get(l["source_flag"], 0) + 1
    return {
        "traces": len(lignes),
        "resolues": len(resolues),
        "flags_par_source": par_source,
        "candidats_rejetes_total": sum(l["candidats_rejetes"] for l in lignes),
        "repetitions_bloquees_total": sum(l["repetitions_bloquees"] for l in lignes),
        "detail": lignes,
    }


# --- Orchestration expérimentale --------------------------------------------

def run_ablation(root: Path, ids: list[str], runs_dir: Path, model, max_steps: int,
                 *, sandbox_factory=None, variantes: list[Ablation] | None = None) -> dict:
    """Lance la matrice (variantes × challenges) et renvoie un bilan comparatif.

    L'ablation se fait sur des challenges à fichiers (sans serveur) : on y isole
    l'effet des briques sans dépendre de Docker ni d'un service réseau. Un
    challenge à serveur dans `ids` est ignoré, avec une mention.

    `sandbox_factory()` fabrique un bac à sable neuf par run (il protège des chemins
    et peut être à usage unique) ; None = pas de bac à sable. Chaque variante écrit
    ses runs dans `runs_dir/<variante>/`.
    """
    from .challenge import discover
    from .run import run_challenge

    variantes = variantes or VARIANTES
    refs = [r for r in discover(root) if r.id in set(ids)]
    resultats: list[dict] = []

    for ab in variantes:
        for ref in refs:
            if ref.needs_server:
                resultats.append({"variante": ab.nom, "challenge": ref.id,
                                  "categorie": ref.category, "statut": "ignore_serveur",
                                  "resolu": False, "etapes_llm": None, "source_flag": None})
                continue
            sandbox = sandbox_factory() if (ab.outils and sandbox_factory is not None) else None
            sous_dir = Path(runs_dir) / ab.nom
            try:
                summary = run_challenge(ref.json_path, sous_dir, model, max_steps,
                                        sandbox if ab.outils else None, ablation=ab)
            except Exception as exc:  # une variante qui plante n'arrête pas la matrice
                summary = {"status": "erreur_interne", "flag": None,
                           "error": f"{type(exc).__name__}: {exc}"}
            resultats.append({
                "variante": ab.nom, "challenge": ref.id, "categorie": ref.category,
                "statut": summary.get("status"), "resolu": summary.get("status") == "resolu",
                "etapes_llm": summary.get("llm_steps"),
                "source_flag": _source_du_flag(summary),
            })
            print(f"{ab.nom:<18} {ref.id:<28} {summary.get('status')}", flush=True)

    return {"model": getattr(model, "name", str(model)), "challenges": ids,
            "variantes": [v.nom for v in variantes],
            "bilan": _bilan_par_variante(resultats), "detail": resultats}


def _source_du_flag(summary: dict) -> str | None:
    rapport = summary.get("report")
    if not rapport or summary.get("status") != "resolu":
        return None
    try:
        return analyser_trace(Path(rapport).with_name("trace.jsonl"))["source_flag"]
    except (OSError, ValueError):
        return None


def _bilan_par_variante(resultats: list[dict]) -> dict:
    bilan: dict[str, dict] = {}
    for r in resultats:
        b = bilan.setdefault(r["variante"], {"resolus": 0, "total": 0, "etapes": []})
        if r["statut"] == "ignore_serveur":
            continue
        b["total"] += 1
        if r["resolu"]:
            b["resolus"] += 1
        if isinstance(r["etapes_llm"], int):
            b["etapes"].append(r["etapes_llm"])
    for b in bilan.values():
        b["etapes_moy"] = round(sum(b["etapes"]) / len(b["etapes"]), 1) if b["etapes"] else None
        del b["etapes"]
    return bilan


def tableau_markdown(bilan: dict) -> str:
    """Rend le bilan comparatif en tableau Markdown, référence en tête."""
    noms = {v.nom: v.description for v in VARIANTES}
    lignes = ["| Variante | Brique retirée | Résolus | Étapes LLM moy. |",
              "|---|---|---|---|"]
    b = bilan["bilan"]
    for nom in bilan["variantes"]:
        row = b.get(nom, {})
        retiree = "— (référence)" if nom == "A_reference" else noms.get(nom, nom)
        lignes.append(f"| {nom} | {retiree} | {row.get('resolus', 0)}/{row.get('total', 0)} "
                      f"| {row.get('etapes_moy', '—')} |")
    return "\n".join(lignes) + "\n"
