"""Encadrement des données non fiables (défense contre la prompt injection).

Tout ce qui vient d'un challenge (description, fichiers, sorties d'outils)
peut contenir des instructions déguisées. Ces données sont nettoyées,
tronquées et placées entre deux balises portant un identifiant aléatoire,
que le contenu ne peut pas deviner pour refermer le bloc lui-même.
Le prompt système dit au LLM que ce bloc est une donnée, mais la vraie
protection reste ailleurs, en code : outils typés, politique d'exécution,
flag hors de portée.
"""

from __future__ import annotations

import re
import secrets

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

DEFAULT_LIMIT = 8000


def sanitize(text: str, limit: int = DEFAULT_LIMIT) -> str:
    text = _ANSI.sub("", text)
    text = _CONTROL.sub("", text)
    if len(text) > limit:
        cut = len(text) - limit
        text = text[:limit] + f"\n[... {cut} caractères tronqués ...]"
    return text


def wrap_untrusted(text: str, source: str, limit: int = DEFAULT_LIMIT) -> str:
    """Retourne le texte encadré, prêt à être inséré dans un message au LLM."""
    nonce = secrets.token_hex(8)
    body = sanitize(text, limit)
    return (
        f'<donnees_non_fiables source="{source}" id="{nonce}">\n'
        f"{body}\n"
        f'</donnees_non_fiables id="{nonce}">'
    )
