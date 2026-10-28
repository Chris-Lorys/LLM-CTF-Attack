"""Vérification du flag (étape 6 du pipeline).

Outil déterministe : le flag attendu reste dans cet objet, et le reste de
l'agent ne reçoit qu'un booléen. Le LLM ne peut donc ni lire ni deviner la
réponse par ce canal.
"""

from __future__ import annotations

import hmac
import re
import unicodedata

# Forme générique d'un flag : préfixe{contenu}. Les préfixes varient selon
# les CTF (csawctf, flag, CTF...), d'où un motif large.
FLAG_PATTERN = re.compile(r"[A-Za-z0-9_\-]{2,20}\{[^\s{}]{1,200}\}")


def normalize_flag(candidate: str) -> str:
    """Retire les espaces et caractères invisibles autour du flag."""
    text = unicodedata.normalize("NFKC", candidate)
    text = "".join(ch for ch in text if unicodedata.category(ch) not in ("Cc", "Cf"))
    return text.strip().strip("`'\"")


def find_candidates(text: str) -> list[str]:
    """Repère les chaînes qui ressemblent à un flag, sans doublons, dans l'ordre."""
    seen: dict[str, None] = {}
    for match in FLAG_PATTERN.findall(text):
        seen.setdefault(match, None)
    return list(seen)


class FlagVerifier:
    def __init__(self, expected: str):
        self._expected = normalize_flag(expected)
        self.attempts = 0

    def check(self, candidate: str) -> bool:
        self.attempts += 1
        got = normalize_flag(candidate).encode()
        return hmac.compare_digest(got, self._expected.encode())

    def __repr__(self) -> str:
        # Évite d'écrire le flag dans un journal par accident.
        return f"FlagVerifier(attempts={self.attempts})"
