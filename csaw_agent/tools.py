"""Outils déterministes mis à disposition du LLM (étape 4 du pipeline).

Approche « par retrait » : tout ce qu'un programme fait mieux qu'un modèle de
langage (décoder, calculer, lire des octets, comparer un flag) est confié à du
code. Le LLM choisit l'outil et ses arguments ; il ne fait jamais le calcul.

Chaque outil a des arguments typés et vérifiés avant exécution. Les outils ne
lisent que les fichiers copiés dans l'espace de travail du run : un argument
comme "../../etc/passwd" est refusé.
"""

from __future__ import annotations

import base64
import codecs
import hashlib
import math
import re
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .flag import FLAG_PATTERN

MAX_OUTPUT = 4000


class ToolError(ValueError):
    """Appel d'outil invalide : outil inconnu, argument manquant ou mal typé."""


@dataclass(frozen=True)
class Param:
    name: str
    type: type
    description: str
    required: bool = True
    default: object = None


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    params: tuple[Param, ...]
    func: Callable[..., str]

    def signature(self) -> str:
        parts = []
        for p in self.params:
            opt = "" if p.required else f" = {p.default!r}"
            parts.append(f"{p.name}: {p.type.__name__}{opt}")
        return f"{self.name}({', '.join(parts)}) : {self.description}"


class Toolbox:
    """Outils liés à l'espace de travail d'un run."""

    def __init__(self, files_dir: Path):
        self.files_dir = Path(files_dir).resolve()
        self.tools: dict[str, Tool] = {}
        self._register()

    # --- Validation ---------------------------------------------------------

    def call(self, name: str, args: dict) -> str:
        tool = self.tools.get(name)
        if tool is None:
            raise ToolError(f"outil inconnu : {name!r}")
        if not isinstance(args, dict):
            raise ToolError("les arguments doivent être un objet JSON")
        unknown = set(args) - {p.name for p in tool.params}
        if unknown:
            raise ToolError(f"arguments inconnus pour {name} : {sorted(unknown)}")
        kwargs = {}
        for p in tool.params:
            if p.name not in args:
                if p.required:
                    raise ToolError(f"argument manquant pour {name} : {p.name}")
                kwargs[p.name] = p.default
                continue
            value = args[p.name]
            # bool est une sous-classe d'int : on le refuse là où un entier est attendu.
            if not isinstance(value, p.type) or (p.type is int and isinstance(value, bool)):
                raise ToolError(f"{name}.{p.name} doit être de type {p.type.__name__}")
            kwargs[p.name] = value
        output = tool.func(**kwargs)
        if len(output) > MAX_OUTPUT:
            output = output[:MAX_OUTPUT] + f"\n[... sortie tronquée à {MAX_OUTPUT} caractères]"
        return output

    def _file(self, name: str) -> Path:
        path = (self.files_dir / name).resolve()
        if path.parent != self.files_dir or not path.is_file():
            raise ToolError(f"fichier inconnu : {name!r} (voir list_files)")
        return path

    def _source(self, data: str, file: str) -> bytes:
        if bool(data) == bool(file):
            raise ToolError("donner exactement un des deux arguments : data ou file")
        return self._file(file).read_bytes() if file else data.encode()

    # --- Outils -------------------------------------------------------------

    def _register(self) -> None:
        def add(name, description, params, func):
            self.tools[name] = Tool(name, description, tuple(params), func)

        add("list_files", "liste les fichiers du challenge avec leur taille", [],
            self.list_files)
        add("file_info", "type probable (octets magiques), taille, entropie, sha256",
            [Param("file", str, "nom du fichier")], self.file_info)
        add("read_file", "lit un fichier en texte ou en hexadécimal",
            [Param("file", str, "nom du fichier"),
             Param("offset", int, "décalage en octets", False, 0),
             Param("length", int, "nombre d'octets", False, 2000),
             Param("mode", str, "'text' ou 'hex'", False, "text")], self.read_file)
        add("strings", "suites de caractères imprimables d'un fichier",
            [Param("file", str, "nom du fichier"),
             Param("min_len", int, "longueur minimale", False, 4)], self.strings)
        add("decode", "applique une chaîne de transformations ; ops séparées par '|' parmi "
            + ", ".join(sorted(_DECODERS)) + ", rot:N, xor:CLEHEX",
            [Param("ops", str, "p. ex. 'base64|rot13'"),
             Param("data", str, "texte à décoder", False, ""),
             Param("file", str, "ou nom du fichier à décoder", False, "")], self.decode)
        add("xor_bruteforce", "essaie les 256 clés XOR d'un octet, garde les sorties lisibles",
            [Param("data", str, "données en hexadécimal", False, ""),
             Param("file", str, "ou nom du fichier", False, "")], self.xor_bruteforce)
        add("check_flag", "vérifie un flag candidat ; répond seulement vrai ou faux",
            [Param("candidate", str, "le flag proposé")], _handled_by_agent)
        add("give_up", "abandonne le challenge en expliquant pourquoi",
            [Param("reason", str, "raison de l'abandon")], _handled_by_agent)

    def list_files(self) -> str:
        rows = [f"{p.name}\t{p.stat().st_size} octets"
                for p in sorted(self.files_dir.iterdir()) if p.is_file()]
        return "\n".join(rows) or "(aucun fichier)"

    def file_info(self, file: str) -> str:
        data = self._file(file).read_bytes()
        return (f"taille : {len(data)} octets\n"
                f"type probable : {guess_type(data)}\n"
                f"entropie : {entropy(data):.2f} bits/octet\n"
                f"sha256 : {hashlib.sha256(data).hexdigest()}")

    def read_file(self, file: str, offset: int, length: int, mode: str) -> str:
        if offset < 0 or length <= 0:
            raise ToolError("offset >= 0 et length > 0 attendus")
        chunk = self._file(file).read_bytes()[offset:offset + min(length, MAX_OUTPUT)]
        if mode == "hex":
            return "\n".join(f"{offset + i:08x}  {chunk[i:i + 16].hex(' ')}"
                             for i in range(0, len(chunk), 16))
        if mode == "text":
            return chunk.decode("utf-8", errors="replace")
        raise ToolError("mode doit valoir 'text' ou 'hex'")

    def strings(self, file: str, min_len: int) -> str:
        data = self._file(file).read_bytes()
        found = re.findall(rb"[\x20-\x7e]{%d,}" % max(1, min_len), data)
        return "\n".join(s.decode() for s in found) or "(aucune chaîne)"

    def decode(self, ops: str, data: str, file: str) -> str:
        value = self._source(data, file)
        for op in [o.strip() for o in ops.split("|") if o.strip()]:
            value = apply_op(op, value)
        return value.decode("utf-8", errors="replace")

    def xor_bruteforce(self, data: str, file: str) -> str:
        if data:
            try:
                raw = bytes.fromhex(data)
            except ValueError as exc:
                raise ToolError("data doit être de l'hexadécimal") from exc
        else:
            raw = self._source("", file)
        hits = []
        for key in range(256):
            out = bytes(b ^ key for b in raw[:4096])
            printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in out) / max(1, len(out))
            text = out.decode("latin-1")
            if FLAG_PATTERN.search(text) or printable > 0.95:
                hits.append(f"clé 0x{key:02x} : {text[:200]!r}")
        return "\n".join(hits) or "aucune clé ne donne un texte lisible"


def _handled_by_agent(**_) -> str:  # pragma: no cover - interceptés par la boucle
    raise AssertionError("outil traité directement par la boucle de l'agent")


# --- Fonctions pures -----------------------------------------------------------

def _b64(value: bytes) -> bytes:
    cleaned = re.sub(rb"\s", b"", value)
    return base64.b64decode(cleaned + b"=" * (-len(cleaned) % 4))


_DECODERS: dict[str, Callable[[bytes], bytes]] = {
    "base64": _b64,
    "base32": lambda v: base64.b32decode(re.sub(rb"\s", b"", v).upper()
                                         + b"=" * (-len(re.sub(rb"\s", b"", v)) % 8)),
    "base85": lambda v: base64.b85decode(v.strip()),
    "ascii85": lambda v: base64.a85decode(v.strip(), adobe=v.strip().startswith(b"<~")),
    "hex": lambda v: bytes.fromhex(re.sub(r"[\s:]|0x", "", v.decode())),
    "rot13": lambda v: codecs.encode(v.decode("latin-1"), "rot13").encode("latin-1"),
    "url": lambda v: urllib.parse.unquote_to_bytes(v),
    "reverse": lambda v: v[::-1],
    "binary": lambda v: bytes(int(b, 2) for b in v.decode().split()),
}


def _rot(value: bytes, n: int) -> bytes:
    out = bytearray()
    for b in value:
        if 65 <= b <= 90:
            b = 65 + (b - 65 + n) % 26
        elif 97 <= b <= 122:
            b = 97 + (b - 97 + n) % 26
        out.append(b)
    return bytes(out)


def apply_op(op: str, value: bytes) -> bytes:
    name, _, arg = op.partition(":")
    try:
        if name == "rot":
            return _rot(value, int(arg))
        if name == "xor":
            key = bytes.fromhex(arg)
            if not key:
                raise ToolError("xor:CLEHEX attend une clé non vide")
            return bytes(b ^ key[i % len(key)] for i, b in enumerate(value))
        if name in _DECODERS:
            return _DECODERS[name](value)
    except ToolError:
        raise
    except Exception as exc:  # binascii.Error, ValueError, UnicodeDecodeError...
        raise ToolError(f"échec de l'opération {op!r} : {exc}") from exc
    raise ToolError(f"opération inconnue : {op!r}")


_MAGIC = [
    (b"\x7fELF", "exécutable ELF"),
    (b"MZ", "exécutable Windows (PE)"),
    (b"\x89PNG\r\n\x1a\n", "image PNG"),
    (b"\xff\xd8\xff", "image JPEG"),
    (b"GIF8", "image GIF"),
    (b"PK\x03\x04", "archive ZIP (ou docx/jar/apk)"),
    (b"%PDF", "document PDF"),
    (b"\x1f\x8b", "archive gzip"),
    (b"BZh", "archive bzip2"),
    (b"\xfd7zXZ\x00", "archive xz"),
    (b"7z\xbc\xaf\x27\x1c", "archive 7z"),
    (b"Rar!", "archive RAR"),
    (b"\xd4\xc3\xb2\xa1", "capture réseau pcap"),
    (b"\x0a\x0d\x0d\x0a", "capture réseau pcapng"),
    (b"RIFF", "conteneur RIFF (WAV/AVI)"),
    (b"SQLite format 3\x00", "base SQLite"),
    (b"-----BEGIN", "bloc PEM (clé ou certificat)"),
]


def guess_type(data: bytes) -> str:
    for magic, label in _MAGIC:
        if data.startswith(magic):
            return label
    if not data:
        return "fichier vide"
    sample = data[:4096]
    if all(32 <= b < 127 or b in (9, 10, 13) for b in sample):
        if re.fullmatch(rb"[A-Za-z0-9+/=\s]+", sample) and len(sample.strip()) % 4 == 0:
            return "texte ASCII (ressemble à du base64)"
        if re.fullmatch(rb"[0-9a-fA-F\s]+", sample):
            return "texte ASCII (ressemble à de l'hexadécimal)"
        return "texte ASCII"
    return "données binaires"


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())
