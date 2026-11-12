"""Atelier : bibliothèque d'outils que l'agent écrit lui-même et réutilise.

« Agent forgeron » : plutôt que de réinventer un décodeur ou un parseur à chaque
challenge, l'agent peut déclarer qu'un script qu'il vient d'écrire est réutilisable.
Le code — pas le modèle — le valide (il doit compiler), le range dans une
bibliothèque qui survit d'un challenge à l'autre, et le propose aux challenges
suivants. C'est la démarche « par retrait » appliquée à la mémoire outillée :
le modèle écrit la logique une fois, le code en fait un outil fiable et persistant.

Chaque conservation et chaque réutilisation sont des décisions tracées : on peut
donc vérifier, dans la trace chaînée, quand un outil est né et quand il a resservi.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

NOM = re.compile(r"[a-z][a-z0-9_]{1,39}")  # nom d'outil : slug court, sûr comme nom de fichier
MAX_SOURCE = 65536
MAX_DESC = 200


class AtelierError(ValueError):
    """Conservation refusée (nom invalide, script qui ne compile pas, trop long)."""


@dataclass
class OutilSauve:
    nom: str
    description: str
    categorie: str
    origine: str  # challenge où l'outil est né
    lignes: int


class Atelier:
    """Bibliothèque persistante d'outils écrits par l'agent.

    Un dossier sur disque : `<nom>.py` par outil, plus `index.json` (métadonnées).
    Partagé entre les runs d'un même `run-all`, donc un outil né sur un challenge
    est proposé aux suivants.
    """

    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._index = self.root / "index.json"

    def _charger_index(self) -> dict[str, dict]:
        if not self._index.is_file():
            return {}
        try:
            data = json.loads(self._index.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _ecrire_index(self, index: dict[str, dict]) -> None:
        self._index.write_text(json.dumps(index, ensure_ascii=False, indent=2),
                               encoding="utf-8")

    def liste(self) -> list[OutilSauve]:
        index = self._charger_index()
        outils = []
        for nom, meta in sorted(index.items()):
            if (self.root / f"{nom}.py").is_file():
                outils.append(OutilSauve(nom, meta.get("description", ""),
                                         meta.get("categorie", ""), meta.get("origine", ""),
                                         meta.get("lignes", 0)))
        return outils

    def garder(self, nom: str, description: str, source: str,
               categorie: str = "", origine: str = "") -> OutilSauve:
        """Valide et range un script. Le code vérifie qu'il compile avant de le garder."""
        if not NOM.fullmatch(nom):
            raise AtelierError("nom d'outil invalide (minuscules, chiffres, _ ; 2 à 40 "
                               "caractères, une lettre d'abord)")
        description = (description or "").strip()
        if not description:
            raise AtelierError("donne une courte description de l'outil")
        if len(source.encode()) > MAX_SOURCE:
            raise AtelierError("script trop long (64 Ko maximum)")
        try:
            compile(source, f"{nom}.py", "exec")
        except SyntaxError as exc:
            raise AtelierError(f"le script ne compile pas : {exc}") from exc

        (self.root / f"{nom}.py").write_text(source, encoding="utf-8")
        index = self._charger_index()
        outil = OutilSauve(nom, description[:MAX_DESC], categorie, origine,
                           source.count("\n") + 1)
        index[nom] = {"description": outil.description, "categorie": categorie,
                      "origine": origine, "lignes": outil.lignes}
        self._ecrire_index(index)
        return outil

    def charger(self, nom: str) -> str | None:
        """Source d'un outil rangé, ou None s'il n'existe pas."""
        fichier = self.root / f"{nom}.py"
        if not NOM.fullmatch(nom) or not fichier.is_file():
            return None
        return fichier.read_text(encoding="utf-8")

    def bloc_briefing(self) -> str:
        """Liste des outils disponibles, à injecter dans le prompt de départ."""
        outils = self.liste()
        if not outils:
            return ""
        lignes = ["Outils déjà écrits par l'agent sur d'autres challenges (action "
                  "utiliser_outil pour copier l'un d'eux dans tes fichiers, puis "
                  "lance-le avec shell) :"]
        for o in outils:
            tag = f" [{o.categorie}]" if o.categorie else ""
            lignes.append(f"- {o.nom}{tag} : {o.description}")
        return "\n".join(lignes)
