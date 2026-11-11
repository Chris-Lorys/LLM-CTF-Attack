"""Dossier des échecs : ce que l'agent a déjà tenté sur chaque challenge non résolu.

Sert à préparer l'approche hybride : l'humain lit ce que l'agent a essayé
avant d'écrire un indice d'orientation (jamais une solution). Tout est tiré
des traces par du code, sans LLM, comme le rapport. On ne lit que nos traces :
jamais les dossiers de solution de la base.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

PENSEES = 6       # dernières pensées gardées pour la tentative la plus longue
COMMANDES = 12    # commandes shell distinctes listées
EXTRAIT = 220


def _court(text, n: int = EXTRAIT) -> str:
    text = text if isinstance(text, str) else json.dumps(text, ensure_ascii=False)
    text = " ".join(text.split())
    return text if len(text) <= n else text[:n] + " […]"


def _lire(trace: Path) -> dict:
    events = [json.loads(l) for l in trace.read_text(encoding="utf-8").split("\n") if l.strip()]
    view = next((e["payload"] for e in events if e["type"] == "ingestion"), {})
    end = next((e["payload"] for e in reversed(events) if e["type"] == "end"), {})
    calls = [e["payload"] for e in events if e["type"] == "tool_call"]
    stops = [e["payload"] for e in events
             if e["type"] == "decision" and "stop" in e["payload"]]
    return {
        "challenge": trace.parent.parent.name,
        "nom": view.get("name", "?"),
        "categorie": view.get("category", "?"),
        "serveur": bool(view.get("needs_server")),
        "statut": end.get("status", "interrompu"),
        "modele": end.get("model") or "aucun",
        "etapes": end.get("llm_steps", 0) or 0,
        "outils": Counter(c["tool"] for c in calls),
        "commandes": [c["args"].get("command") for c in calls
                      if c["tool"] == "shell" and isinstance(c.get("args"), dict)
                      and isinstance(c["args"].get("command"), str)],
        "pensees": [c["pensee"] for c in calls if isinstance(c.get("pensee"), str)],
        "refuses": sum(1 for e in events if e["type"] == "check_flag"
                       and not e["payload"]["valid"]),
        "arret": [_court(s.get("reason") or s.get("error") or s["stop"], 160) for s in stops],
    }


def dossier_echecs(traces: list[Path]) -> str:
    """Markdown : pour chaque challenge jamais résolu, les tentatives et leur contenu."""
    par_challenge: dict[str, list[dict]] = defaultdict(list)
    for t in traces:
        try:
            par_challenge[(r := _lire(Path(t)))["challenge"]].append(r)
        except (OSError, ValueError, KeyError):
            continue
    resolus = {c for c, rs in par_challenge.items() if any(r["statut"] == "resolu" for r in rs)}
    echecs = sorted(c for c in par_challenge if c not in resolus)

    lignes = [f"# Dossier des échecs ({len(echecs)} challenge(s) jamais résolu(s), "
              f"{len(resolus)} résolu(s) écartés)", ""]
    for c in echecs:
        rs = par_challenge[c]
        utiles = [r for r in rs if r["etapes"]]
        ref = max(rs, key=lambda r: r["etapes"])
        lignes += [f"## {ref['nom']} ({ref['categorie']}{', serveur' if ref['serveur'] else ''})",
                   "", f"- Tentatives : {len(rs)} (dont {len(utiles)} où le modèle a agi)"]
        for r in sorted(rs, key=lambda r: -r["etapes"]):
            if r["etapes"]:
                lignes.append(f"  - {r['modele']} : {r['statut']}, {r['etapes']} actions")
        tous = Counter()
        for r in rs:
            tous.update(r["outils"])
        if tous:
            lignes.append("- Outils utilisés (toutes tentatives) : "
                          + ", ".join(f"{k} ×{v}" for k, v in tous.most_common()))
        refus = sum(r["refuses"] for r in rs)
        if refus:
            lignes.append(f"- Candidats de flag refusés par check_flag : {refus}")
        cmds = list(dict.fromkeys(_court(x, 120) for r in rs for x in r["commandes"]))
        if cmds:
            lignes.append(f"- Commandes shell distinctes ({len(cmds)}, extrait) :")
            lignes += [f"  - `{x.replace('`', chr(39))}`" for x in cmds[:COMMANDES]]
        if ref["pensees"]:
            lignes.append(f"- Dernières pensées de la tentative la plus longue ({ref['modele']}) :")
            lignes += [f"  - {_court(p)}" for p in ref["pensees"][-PENSEES:]]
        if ref["arret"]:
            lignes.append(f"- Arrêt : {'; '.join(ref['arret'])}")
        lignes.append("")
    return "\n".join(lignes)
