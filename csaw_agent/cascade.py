"""Cascade frugale pilotée par la progression.

Un modèle économique (gratuit) travaille d'abord seul. À chaque étape, le code
mesure si l'agent apprend encore quelque chose ou s'il tourne en rond :

- gain d'information : une sortie d'outil qui apporte des lignes jamais vues,
  une note retenue, une hypothèse enregistrée ou tranchée ;
- échec : erreur d'outil, action répétée bloquée, flag refusé, hypothèse déjà
  réfutée, réponse illisible.

Quand l'agent stagne (trop d'étapes sans gain, ou trop d'échecs d'affilée),
c'est le code, et non le modèle, qui décide de passer la main au palier suivant,
plus fort et plus cher. Le nouveau modèle ne reçoit pas l'historique brut mais
un état compact établi par le code : notes, hypothèses, actions déjà faites,
candidats déjà refusés. Le modèle cher n'est donc payé que là où le modèle
gratuit a prouvé, par une mesure, qu'il ne progressait plus.

Le même moniteur rejoue les traces existantes (coût nul) pour mesurer où la
cascade aurait escaladé et combien d'étapes le modèle seul a dépensées en vain.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .llm import ChatModel, make_model

PATIENCE = 6      # étapes LLM d'affilée sans gain d'information
ECHECS_MAX = 3    # échecs consécutifs
SEUIL_LIGNES = 3  # lignes jamais vues pour qu'une sortie compte comme un gain
MIN_LIGNE = 4     # lignes plus courtes ignorées (bruit : « ok », « --- »)
ACTIONS_RESUME = 15
CANDIDATS_RESUME = 10


def _lignes(texte: str) -> set[str]:
    return {" ".join(l.split()) for l in str(texte).splitlines() if len(l.strip()) >= MIN_LIGNE}


@dataclass
class Progression:
    """Signal de progression, mesuré par le code à partir des événements de la trace."""

    patience: int = PATIENCE
    echecs_max: int = ECHECS_MAX
    seuil_lignes: int = SEUIL_LIGNES
    lignes_vues: set[str] = field(default_factory=set)
    sans_gain: int = 0
    echecs: int = 0

    def _gain(self) -> None:
        self.sans_gain, self.echecs = 0, 0

    def _echec(self) -> None:
        self.echecs += 1

    def observe(self, kind: str, payload: dict) -> None:
        if kind == "llm_response":
            self.sans_gain += 1  # chaque étape coûte ; seul un gain remet le compteur à zéro
        elif kind == "tool_result":
            if payload.get("tool") == "prescan":  # fait par le code avant le modèle : base
                self.lignes_vues |= _lignes(payload.get("output", ""))
            elif payload.get("ok"):
                nouvelles = _lignes(payload.get("output", "")) - self.lignes_vues
                self.lignes_vues |= nouvelles
                if len(nouvelles) >= self.seuil_lignes:
                    self._gain()
            else:
                self._echec()
        elif kind == "decision":
            if "note" in payload:
                self._gain()
            elif "hypothese" in payload:
                msg = str(payload["hypothese"])
                if msg.startswith("Hypothèse déjà réfutée"):
                    self._echec()
                elif "enregistrée" in msg or "marquée" in msg:
                    self._gain()
            elif "repetition" in payload:
                self._echec()
        elif kind == "check_flag":
            if payload.get("source") == "llm" and not payload.get("valid"):
                self._echec()
        elif kind == "prompt":
            msgs = payload.get("messages") or []
            if (len(msgs) == 1 and str(msgs[0].get("content", "")).startswith("Réponse illisible")):
                self._echec()

    def stagne(self) -> str | None:
        if self.echecs >= self.echecs_max:
            return f"{self.echecs} échecs consécutifs"
        if self.sans_gain >= self.patience:
            return f"{self.sans_gain} étapes sans information nouvelle"
        return None

    def reinitialiser(self) -> None:
        """Nouveau palier : on garde ce qui a été vu, on repart à zéro sur la stagnation."""
        self.sans_gain, self.echecs = 0, 0


@dataclass
class Cascade:
    """Paliers de modèles, du moins cher au plus fort."""

    paliers: list[ChatModel]
    patience: int = PATIENCE
    echecs_max: int = ECHECS_MAX

    def __post_init__(self):
        if not self.paliers:
            raise ValueError("une cascade demande au moins un modèle")

    def moniteur(self) -> Progression:
        return Progression(self.patience, self.echecs_max)

    @property
    def name(self) -> str:
        return "cascade(" + " > ".join(m.name for m in self.paliers) + ")"

    def describe(self) -> dict:
        return {"paliers": [m.name for m in self.paliers],
                "patience": self.patience, "echecs_max": self.echecs_max}


def make_cascade(spec: str, base_url: str | None = None, patience: int = PATIENCE,
                 echecs_max: int = ECHECS_MAX) -> Cascade:
    """`preset:modele_gratuit>preset:modele_fort[>...]`, du moins cher au plus fort."""
    specs = [s.strip() for s in spec.split(">") if s.strip()]
    if len(specs) < 2:
        raise ValueError("une cascade demande au moins deux paliers : 'gratuit>fort'")
    return Cascade([make_model(s, base_url) for s in specs], patience, echecs_max)


class TraceObservee:
    """Écrit dans la trace et nourrit le moniteur avec les mêmes événements."""

    def __init__(self, trace, moniteur: Progression):
        self._trace, self.moniteur = trace, moniteur

    def log(self, kind: str, payload: dict, **meta) -> dict:
        self.moniteur.observe(kind, payload)
        return self._trace.log(kind, payload, **meta)

    def __getattr__(self, name):
        return getattr(self._trace, name)


def etat_compact(palier: int, total: int, raison: str, notes: list[str], bloc_hypotheses: str,
                 actions: list[str], refuses: list[str]) -> str:
    """Passation au palier suivant : un état établi par le code, pas l'historique brut."""
    lignes = [f"Reprise par un modèle plus fort (palier {palier + 1}/{total}). "
              f"Le système a mesuré que l'agent précédent stagnait : {raison}.",
              "État établi par le système :"]
    if notes:
        lignes.append("Notes retenues :\n" + "\n".join(f"- {n}" for n in notes))
    if bloc_hypotheses:
        lignes.append(bloc_hypotheses)
    if actions:
        lignes.append("Actions déjà faites (ne pas les refaire à l'identique) :\n"
                      + "\n".join(f"- {a}" for a in actions[-ACTIONS_RESUME:]))
    if refuses:
        lignes.append("Candidats déjà refusés par check_flag : "
                      + ", ".join(refuses[-CANDIDATS_RESUME:]))
    lignes.append("Repars de cet état : formule une hypothèse nouvelle plutôt que de refaire "
                  "ce qui a échoué.")
    return "\n\n".join(lignes)


# --- Évaluation rétrospective sur des traces existantes (coût nul) -------------

def rejouer(trace: Path, patience: int = PATIENCE, echecs_max: int = ECHECS_MAX) -> dict | None:
    """Où la cascade aurait-elle escaladé sur cette trace ? None si le modèle n'a pas agi."""
    events = [json.loads(l) for l in Path(trace).read_text(encoding="utf-8").split("\n")
              if l.strip()]
    end = next((e["payload"] for e in reversed(events) if e["type"] == "end"), {})
    etapes = end.get("llm_steps") or 0
    if not etapes:
        return None
    mon = Progression(patience, echecs_max)
    detection, etape = None, 0
    for e in events:
        if e["type"] == "llm_response":
            etape = e["payload"].get("step", etape + 1)
            if detection is None and mon.stagne():
                detection = etape  # le moniteur vérifie avant chaque appel au modèle
        mon.observe(e["type"], e["payload"])
    resolu = end.get("status") == "resolu"
    return {
        "challenge": Path(trace).parent.parent.name,
        "modele": end.get("model") or "?",
        "resolu": resolu,
        "etapes": etapes,
        "detection": detection,
        # Étapes que le modèle seul a dépensées après la détection : budget qu'une
        # cascade aurait confié au palier suivant.
        "apres_detection": (etapes - detection + 1) if detection else 0,
        "fausse_alerte": bool(resolu and detection),
    }


def evaluer_cascade(traces: list[Path], patiences=(4, 6, 8, 10),
                    echecs_max: int = ECHECS_MAX) -> dict:
    """Balayage de la patience : compromis fausses alertes / étapes dépensées en vain."""
    lignes = []
    for p in patiences:
        rs = [r for t in traces if (r := _rejouer_sans_erreur(t, p, echecs_max))]
        echecs = [r for r in rs if not r["resolu"]]
        resolus = [r for r in rs if r["resolu"]]
        detectes = [r for r in echecs if r["detection"]]
        lignes.append({
            "patience": p,
            "traces": len(rs),
            "resolues": len(resolus),
            "fausses_alertes": sum(r["fausse_alerte"] for r in resolus),
            "echecs": len(echecs),
            "echecs_detectes": len(detectes),
            "etape_detection_moy": round(sum(r["detection"] for r in detectes) / len(detectes), 1)
            if detectes else None,
            "etapes_echecs": sum(r["etapes"] for r in echecs),
            "etapes_apres_detection": sum(r["apres_detection"] for r in echecs),
        })
    return {"echecs_max": echecs_max, "balayage": lignes}


def _rejouer_sans_erreur(trace, patience, echecs_max):
    try:
        return rejouer(Path(trace), patience, echecs_max)
    except (OSError, ValueError, KeyError):
        return None


def tableau_cascade(resultat: dict) -> str:
    out = ["| Patience | Traces | Résolues (fausses alertes) | Échecs détectés | "
           "Étape de détection moy. | Étapes des échecs dépensées après détection |",
           "|---|---|---|---|---|---|"]
    for l in resultat["balayage"]:
        part = (f"{l['etapes_apres_detection']}/{l['etapes_echecs']}"
                + (f" ({100 * l['etapes_apres_detection'] // l['etapes_echecs']} %)"
                   if l["etapes_echecs"] else ""))
        out.append(f"| {l['patience']} | {l['traces']} | {l['resolues']} "
                   f"({l['fausses_alertes']}) | {l['echecs_detectes']}/{l['echecs']} | "
                   f"{l['etape_detection_moy'] if l['etape_detection_moy'] is not None else '—'} "
                   f"| {part} |")
    return "\n".join(out)
