"""Ingestion d'un challenge (étape 1 du pipeline).

Lit le fichier .json du challenge, sépare le flag attendu (qui part dans le
vérificateur et n'est jamais montré au LLM) du reste des métadonnées, et
copie les fichiers dans un espace de travail propre au run.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path

from .flag import FlagVerifier

# Catégories reconnues ; tout le reste est ramené à "misc".
CATEGORIES = ("pwn", "web", "rev", "forensics", "crypto", "misc")

# Alias rencontrés dans les jeux de challenges publics.
_CATEGORY_ALIASES = {
    "reverse": "rev",
    "reversing": "rev",
    "re": "rev",
    "binary": "pwn",
    "exploitation": "pwn",
    "forensic": "forensics",
    "cryptography": "crypto",
    "web exploitation": "web",
}


class ChallengeError(ValueError):
    """Le fichier de challenge est absent, illisible ou incomplet."""


def normalize_category(raw: str | None) -> str:
    if not raw:
        return "misc"
    value = raw.strip().lower()
    value = _CATEGORY_ALIASES.get(value, value)
    return value if value in CATEGORIES else "misc"


@dataclass(frozen=True)
class ChallengeFile:
    name: str
    path: Path
    size: int
    sha256: str


@dataclass(frozen=True)
class Challenge:
    """Ce que l'agent a le droit de voir. Le flag attendu n'y figure pas."""

    name: str
    category: str
    description: str
    files: tuple[ChallengeFile, ...]
    server: str | None = None
    extra: dict = field(default_factory=dict)

    def to_view(self) -> dict:
        """Vue sérialisable, destinée au LLM et à la trace."""
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "server": self.server,
            "files": [
                {"name": f.name, "size": f.size, "sha256": f.sha256} for f in self.files
            ],
        }


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _server_from(meta: dict) -> str | None:
    # Formats courants : "server", ou "box" + "internal_port" (NYU CTF Bench).
    if meta.get("server"):
        return str(meta["server"])
    box, port = meta.get("box"), meta.get("internal_port") or meta.get("port")
    if box and port:
        return f"{box}:{port}"
    return box or None


def load_challenge(json_path: Path, workspace: Path) -> tuple[Challenge, FlagVerifier]:
    """Charge un challenge et copie ses fichiers dans `workspace/files`.

    Retourne la vue du challenge et un vérificateur qui détient le flag.
    Les fichiers copiés sont mis en lecture seule.
    """
    json_path = Path(json_path)
    if not json_path.is_file():
        raise ChallengeError(f"fichier introuvable : {json_path}")
    try:
        meta = json.loads(json_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ChallengeError(f"JSON invalide dans {json_path} : {exc}") from exc
    if not isinstance(meta, dict):
        raise ChallengeError("le challenge doit être un objet JSON")

    flag = meta.get("flag")
    if not isinstance(flag, str) or not flag.strip():
        raise ChallengeError("champ 'flag' absent : impossible de vérifier le résultat")

    base = json_path.parent
    dest = Path(workspace) / "files"
    dest.mkdir(parents=True, exist_ok=True)

    files: list[ChallengeFile] = []
    for rel in meta.get("files", []) or []:
        src = (base / rel).resolve()
        # Un challenge ne doit pas pouvoir faire copier un fichier hors de son dossier.
        if base.resolve() not in src.parents:
            raise ChallengeError(f"chemin de fichier hors du challenge : {rel}")
        if not src.is_file():
            raise ChallengeError(f"fichier du challenge manquant : {rel}")
        target = dest / src.name
        shutil.copyfile(src, target)
        target.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        files.append(ChallengeFile(src.name, target, target.stat().st_size, _sha256(target)))

    known = {"name", "category", "description", "files", "flag", "server", "box",
             "internal_port", "port"}
    challenge = Challenge(
        name=str(meta.get("name") or json_path.parent.name),
        category=normalize_category(meta.get("category")),
        description=str(meta.get("description") or ""),
        files=tuple(files),
        server=_server_from(meta),
        extra={k: v for k, v in meta.items() if k not in known},
    )
    return challenge, FlagVerifier(flag)
