"""Ingestion d'un challenge (étape 1 du pipeline).

Lit le fichier .json du challenge, sépare le flag attendu (qui part dans le
vérificateur et n'est jamais montré au LLM) du reste des métadonnées, et
copie les fichiers dans un espace de travail propre au run.
"""

from __future__ import annotations

import hashlib
import json
import re
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


# Défense en profondeur : même si un challenge.json listait par erreur un de ces
# fichiers, il ne serait pas montré à l'agent. La base CSAW 2026 range les
# solutions des organisateurs à côté des fichiers des joueurs (solution/,
# solve.py, writeup.md, flag.txt...) ; le règlement interdit de s'en servir.
_FORBIDDEN = re.compile(
    r"(^|/)(solutions?|solver(_files)?|solve)(/|$)"
    r"|(^|/)(solve|full_solve|solver|exploit|sol)[^/]*\.(py|txt|md|sh|sage)$"
    r"|(^|/)[^/]*write[-_]?up[^/]*$"
    r"|(^|/)flag(\.txt)?$",
    re.IGNORECASE,
)


def is_forbidden(rel: str) -> bool:
    """Vrai si le chemin ressemble à une solution, un write-up ou le flag lui-même."""
    return bool(_FORBIDDEN.search(rel.replace("\\", "/")))


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
    needs_server: bool = False
    excluded: tuple[str, ...] = ()
    extra: dict = field(default_factory=dict)

    def to_view(self) -> dict:
        """Vue sérialisable, destinée au LLM et à la trace."""
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "server": self.server,
            "needs_server": self.needs_server,
            "files": [
                {"name": f.name, "size": f.size, "sha256": f.sha256} for f in self.files
            ],
            "excluded": list(self.excluded),
        }


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _server_from(meta: dict) -> str | None:
    # Formats courants : "server", ou "box" + "internal_port" (+ "proto") comme
    # dans NYU CTF Bench et la base CSAW 2026.
    if meta.get("server"):
        return str(meta["server"])
    box, port = meta.get("box"), meta.get("internal_port") or meta.get("port")
    if not box:
        return None
    address = f"{box}:{port}" if port else str(box)
    proto = meta.get("proto")
    if proto in ("http", "https"):
        return f"{proto}://{address}/"
    if proto:
        return f"{proto} {address}"
    return address


def _fill_placeholders(text: str, meta: dict) -> str:
    """Remplace {box} et {port} dans la description (format CSAW 2026)."""
    box = meta.get("box")
    port = meta.get("internal_port") or meta.get("port")
    if box:
        text = text.replace("{box}", str(box))
    if port:
        text = text.replace("{port}", str(port))
    return text


def _target_name(rel: str, taken: set[str]) -> str:
    """Nom à plat dans l'espace de travail : le nom de base, sinon le chemin aplati."""
    name = Path(rel).name
    if name in taken:
        name = rel.replace("/", "_").replace("\\", "_")
    while name in taken:
        name = "_" + name
    taken.add(name)
    return name


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
    excluded: list[str] = []
    taken: set[str] = set()
    for rel in meta.get("files", []) or []:
        if not isinstance(rel, str):
            raise ChallengeError(f"entrée de 'files' invalide : {rel!r}")
        if is_forbidden(rel):
            excluded.append(rel)
            continue
        src = (base / rel).resolve()
        # Un challenge ne doit pas pouvoir faire copier un fichier hors de son dossier.
        if base.resolve() not in src.parents:
            raise ChallengeError(f"chemin de fichier hors du challenge : {rel}")
        if not src.is_file():
            raise ChallengeError(f"fichier du challenge manquant : {rel}")
        name = _target_name(rel, taken)
        target = dest / name
        shutil.copyfile(src, target)
        target.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        files.append(ChallengeFile(name, target, target.stat().st_size, _sha256(target)))

    known = {"name", "category", "description", "files", "flag", "server", "box",
             "internal_port", "port", "proto", "compose", "server_description"}
    server = _server_from(meta)
    challenge = Challenge(
        name=str(meta.get("name") or json_path.parent.name),
        category=normalize_category(meta.get("category")),
        description=_fill_placeholders(str(meta.get("description") or ""), meta),
        files=tuple(files),
        server=server,
        needs_server=bool(meta.get("compose")) or server is not None,
        excluded=tuple(excluded),
        extra={k: v for k, v in meta.items() if k not in known},
    )
    return challenge, FlagVerifier(flag)


# --- Base de challenges ----------------------------------------------------------

@dataclass(frozen=True)
class ChallengeRef:
    """Entrée d'une base : identifiant, chemin du challenge.json et métadonnées utiles au tri."""

    id: str
    json_path: Path
    category: str
    needs_server: bool


def _ref(cid: str, json_path: Path, category: str | None = None) -> ChallengeRef:
    try:
        meta = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        meta = {}
    if not isinstance(meta, dict):
        meta = {}
    return ChallengeRef(
        id=cid,
        json_path=json_path,
        category=normalize_category(category or meta.get("category")),
        needs_server=bool(meta.get("compose")) or _server_from(meta) is not None,
    )


def discover(root: Path) -> list[ChallengeRef]:
    """Liste les challenges d'une base.

    `root` peut être l'index `dataset.json` de la base CSAW 2026 (identifiants
    du type 2026q-cry-polly), un dossier qui contient cet index, ou n'importe
    quel dossier de challenges (recherche récursive des challenge.json).
    """
    root = Path(root)
    index = root / "dataset.json" if root.is_dir() else root
    if index.is_file() and index.suffix == ".json" and index.name != "challenge.json":
        data = json.loads(index.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ChallengeError(f"index invalide : {index}")
        refs = []
        for cid, entry in data.items():
            if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                raise ChallengeError(f"entrée invalide dans l'index : {cid}")
            json_path = (index.parent / entry["path"] / "challenge.json").resolve()
            if index.parent.resolve() not in json_path.parents:
                raise ChallengeError(f"chemin hors de la base : {entry['path']}")
            refs.append(_ref(cid, json_path, entry.get("category")))
        return refs
    if root.is_file():
        return [_ref(root.parent.name, root)]
    return [_ref(p.parent.name, p) for p in sorted(root.rglob("challenge.json"))]
