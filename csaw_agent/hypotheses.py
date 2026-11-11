"""Registre d'hypothèses suivi par le code.

Deuxième moitié de la technique de prompt « le code écrit les faits, le modèle
écrit les hypothèses, le code arbitre ». Le modèle déclare ce qu'il croit, par
l'action `hypothese` ; le code tient le registre, son état (ouverte, confirmée,
réfutée) et empêche de revenir sur une piste déjà réfutée sans le savoir.

Le code n'invente aucune hypothèse et ne décide pas seul qu'une piste est
fausse : il enregistre ce que le modèle déclare et le lui rend de façon fiable,
là où un historique tronqué le lui ferait oublier. C'est la même idée que les
notes de travail, mais structurée et opposable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_HYP = 12
MAX_TEXTE = 200
STATUTS = ("ouverte", "confirmee", "refutee")


def _norme(texte: str) -> str:
    """Forme comparable d'une hypothèse (pour repérer un doublon d'une réfutée)."""
    return re.sub(r"[^a-z0-9]+", " ", texte.lower()).strip()


@dataclass
class Hypothese:
    hid: str
    texte: str
    statut: str = "ouverte"


@dataclass
class HypothesisRegister:
    hyps: list[Hypothese] = field(default_factory=list)
    _n: int = 0

    def _par_id(self, hid: str) -> Hypothese | None:
        return next((h for h in self.hyps if h.hid == hid), None)

    def declarer(self, texte: str) -> tuple[str, str]:
        """Enregistre une hypothèse. Renvoie (message pour le modèle, id ou '').

        Si elle reprend une hypothèse déjà réfutée, elle est refusée et le modèle
        est averti plutôt que de repartir sur une fausse piste.
        """
        texte = texte.strip()[:MAX_TEXTE]
        if not texte:
            return ("hypothese attend {\"texte\": \"...\"}.", "")
        n = _norme(texte)
        for h in self.hyps:
            if _norme(h.texte) == n:
                if h.statut == "refutee":
                    return (f"Hypothèse déjà réfutée ({h.hid}). Change de piste.", "")
                return (f"Hypothèse déjà ouverte ({h.hid}).", h.hid)
        self._n += 1
        hid = f"H{self._n}"
        self.hyps = (self.hyps + [Hypothese(hid, texte)])[-MAX_HYP:]
        return (f"Hypothèse {hid} enregistrée.", hid)

    def statuer(self, hid: str, statut: str) -> str:
        if statut not in ("confirmee", "refutee"):
            return "statut attendu : 'confirmee' ou 'refutee'."
        h = self._par_id(hid)
        if h is None:
            return f"hypothèse {hid} inconnue."
        h.statut = statut
        return f"{hid} marquée {statut}."

    def ouvertes(self) -> list[Hypothese]:
        return [h for h in self.hyps if h.statut == "ouverte"]

    def bloc_prompt(self) -> str:
        """Rendu injecté dans le contexte : l'état courant des hypothèses."""
        if not self.hyps:
            return ""
        lignes = []
        for h in self.hyps:
            marque = {"ouverte": "?", "confirmee": "✓", "refutee": "✗"}[h.statut]
            lignes.append(f"  {marque} {h.hid} : {h.texte}")
        return "État des hypothèses (tenu par le système) :\n" + "\n".join(lignes)

    def relance(self) -> str:
        """Message de déblocage quand l'agent tourne en rond."""
        refutees = [h.hid for h in self.hyps if h.statut == "refutee"]
        base = "Tu sembles bloqué. Formule une hypothèse nouvelle avec l'action hypothese"
        if refutees:
            base += f", différente des réfutées ({', '.join(refutees)})"
        return base + ", puis teste-la par une action concrète."
