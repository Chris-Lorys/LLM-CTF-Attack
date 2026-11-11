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
import io
import math
import os
import re
import stat
import tarfile
import urllib.parse
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .flag import FLAG_PATTERN
from .net import NetworkError as _NetworkError

MAX_OUTPUT = 4000

# Limites de l'extraction d'archives (une archive de challenge est une donnée non fiable :
# bombe de décompression, chemins piégés, liens symboliques).
MAX_MEMBERS = 500
MAX_MEMBER_SIZE = 64 << 20
MAX_EXTRACTED = 256 << 20


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

    def __init__(self, files_dir: Path, sandbox=None, net=None):
        self.files_dir = Path(files_dir).resolve()
        self.sandbox = sandbox
        self.net = net
        self.written: set[str] = set()
        if sandbox is not None:
            sandbox.attach(self.files_dir)
        self.tools: dict[str, Tool] = {}
        self._register()

    # --- Validation ---------------------------------------------------------

    def call(self, name: str, args: dict) -> str:
        tool = self.tools.get(name)
        if tool is None:
            hint = ("passe par l'outil shell pour les commandes Linux" if "shell" in self.tools
                    else "il n'y a pas de shell")
            raise ToolError(f"outil inconnu : {name!r} ; {hint}. Outils disponibles : "
                            f"{', '.join(self.tools)}")
        if not isinstance(args, dict):
            raise ToolError("les arguments doivent être un objet JSON")
        unknown = set(args) - {p.name for p in tool.params}
        if unknown:
            raise ToolError(f"arguments inconnus pour {name} : {sorted(unknown)} ; "
                            f"signature : {tool.signature()}")
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
            # Le LLM cite souvent un fichier extrait par son nom d'origine
            # (capsule.json au lieu de evidence.zip__capsule.json).
            matches = [p for p in self.files_dir.iterdir()
                       if p.name.endswith("__" + name) and p.is_file()] if "/" not in name else []
            if len(matches) == 1 and matches[0].resolve().parent == self.files_dir:
                return matches[0].resolve()
            raise ToolError(f"fichier inconnu : {name!r} (voir list_files)")
        return path

    def _source(self, data: str, file: str) -> bytes:
        # Les petits modèles envoient souvent les deux arguments, l'un vide, ou les
        # deux remplis : data, plus précis, l'emporte.
        if data:
            return data.encode()
        if file:
            return self._file(file).read_bytes()
        raise ToolError("donner data (texte) ou file (nom de fichier)")

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
        add("extract", "extrait une archive zip ou tar(.gz/.bz2/.xz) ; les fichiers extraits "
            "s'ajoutent à list_files sous le nom <archive>__<chemin>",
            [Param("file", str, "nom de l'archive"),
             Param("password", str, "mot de passe d'un zip chiffré", False, "")],
            self.extract)
        if self.sandbox is not None:
            add("shell", "commande bash dans le dossier des fichiers, sans réseau, utilisateur "
                "sans privilèges (file, strings, unzip, 7z, sqlite3, tshark, objdump, "
                "python3...) ; les fichiers créés deviennent lisibles par les autres outils",
                [Param("command", str, "la commande, p. ex. 'file *'"),
                 Param("timeout", int, "délai en secondes (max 120)", False, 30)],
                self.shell)
        if self.net is not None:
            if self.net.target.proto in ("http", "https"):
                add("http", "requête HTTP vers le serveur du challenge (cookies de session "
                    "gardés entre appels) ; ne vise que ce serveur",
                    [Param("path", str, "chemin, p. ex. /login?id=1"),
                     Param("method", str, "GET, POST...", False, "GET"),
                     Param("body", str, "corps (POST)", False, ""),
                     Param("headers", dict, "en-têtes supplémentaires", False, None),
                     Param("follow", bool, "suivre les redirections", False, True)],
                    self.http)
            else:
                add("connect", "envoie des octets au service TCP du challenge et lit la "
                    "réponse ; connexion gardée ouverte ; \\n, \\xNN interprétés",
                    [Param("data", str, "à envoyer (vide = juste lire)", False, ""),
                     Param("recv", bool, "lire la réponse", False, True),
                     Param("newline", bool, "ajouter un saut de ligne", False, True),
                     Param("raw", bool, "ne pas interpréter les échappements", False, False)],
                    self.connect)
        add("check_flag", "vérifie un flag candidat ; répond seulement vrai ou faux",
            [Param("candidate", str, "le flag proposé")], _handled_by_agent)
        add("write_file", "écrit un fichier texte (script, données) dans le dossier des "
            "fichiers ; pratique pour un script python lancé ensuite par shell",
            [Param("name", str, "nom du fichier, p. ex. solve.py"),
             Param("content", str, "contenu du fichier")], self.write_file)
        add("note", "retient un fait établi (clé, offset, indice) : les notes restent "
            "visibles jusqu'à la fin, alors que l'historique ancien est effacé",
            [Param("text", str, "le fait à retenir, en une phrase")], _handled_by_agent)
        add("hypothese", "déclare une hypothèse de travail, ou met à jour son statut ; le "
            "système en tient le registre et t'empêche de revenir sur une piste réfutée",
            [Param("texte", str, "l'hypothèse, en une phrase", False, ""),
             Param("id", str, "id d'une hypothèse à statuer, p. ex. H1", False, ""),
             Param("statut", str, "'confirmee' ou 'refutee' (avec id)", False, "")],
            _handled_by_agent)
        add("give_up", "abandonne le challenge en expliquant pourquoi",
            [Param("reason", str, "raison de l'abandon")], _handled_by_agent)

    def shell(self, command: str, timeout: int) -> str:
        if not command.strip():
            raise ToolError("commande vide")
        result = self.sandbox.run(command, timeout)
        return f"[code de sortie : {result.returncode}]\n{result.output}"

    def http(self, path: str, method: str, body: str, headers, follow: bool) -> str:
        if headers is not None and not all(isinstance(k, str) and isinstance(v, str)
                                           for k, v in headers.items()):
            raise ToolError("headers doit être un objet de chaînes")
        try:
            return self.net.request(method, path, body, headers, follow)
        except _NetworkError as exc:
            raise ToolError(str(exc)) from exc

    def connect(self, data: str, recv: bool, newline: bool, raw: bool) -> str:
        try:
            return self.net.send(data, recv=recv, newline=newline, raw=raw)
        except _NetworkError as exc:
            raise ToolError(str(exc)) from exc

    def write_file(self, name: str, content: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}", name):
            raise ToolError("nom de fichier invalide (lettres, chiffres, . _ - seulement)")
        if len(content) > 65536:
            raise ToolError("contenu trop long (64 Ko maximum)")
        target = self.files_dir / name
        if os.path.lexists(target):
            if name not in self.written:
                raise ToolError(f"{name} existe déjà et n'a pas été écrit par write_file")
            target.unlink()
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        self.written.add(name)
        return f"{name} écrit ({len(content.encode())} octets)"

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
                raw = bytes.fromhex(_strip_hex(data))
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


    def extract(self, file: str, password: str) -> str:
        path = self._file(file)
        data = path.read_bytes()
        try:
            members = list(_read_archive(data, password))
        except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError) as exc:
            if guess_type(data[:16]) in ("archive 7z", "archive RAR"):
                raise ToolError("extract ne lit que zip et tar ; pour 7z ou RAR, utilise "
                                f"shell : 7z x {path.name} (option -pMOTDEPASSE)") from exc
            raise ToolError(f"archive illisible : {str(exc).splitlines()[0]}") from exc
        except RuntimeError as exc:  # zip chiffré sans le bon mot de passe
            raise ToolError(f"archive protégée : {exc}") from exc
        stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", path.name)
        rows = []
        for member, content in members:
            flat = re.sub(r"[^A-Za-z0-9_.-]+", "_", member.strip("/").replace("/", "__"))
            if len(stem) + len(flat) > 180:  # limite de 255 octets par nom de fichier
                digest = hashlib.sha256(member.encode()).hexdigest()[:10]
                flat = f"{digest}_{flat[-120:]}"
            target = self.files_dir / f"{stem}__{flat}"
            # lexists : un lien symbolique posé par le shell ne doit pas être suivi
            # (l'extraction tourne en root, hors du bac à sable).
            if os.path.lexists(target):
                rows.append(f"{target.name}\t(déjà extrait)")
                continue
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
            with os.fdopen(fd, "wb") as fh:
                fh.write(content)
            target.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            rows.append(f"{target.name}\t{len(content)} octets\t{guess_type(content[:4096])}")
        return "\n".join(rows) or "(archive vide)"


def _read_archive(data: bytes, password: str):
    """Rend (chemin, contenu) pour chaque fichier ordinaire, avec des limites strictes.

    Rien n'est écrit sur disque ici : les chemins de l'archive ne servent qu'à
    nommer les fichiers, ce qui écarte les attaques par ../ ou par lien.
    """
    total = 0

    def account(name: str, size: int) -> None:
        nonlocal total
        total += size
        if size > MAX_MEMBER_SIZE or total > MAX_EXTRACTED:
            raise ToolError(f"archive trop volumineuse une fois extraite ({name})")

    if zipfile.is_zipfile(io.BytesIO(data)):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = [i for i in zf.infolist() if not i.is_dir()]
            if len(infos) > MAX_MEMBERS:
                raise ToolError(f"trop de fichiers dans l'archive ({len(infos)})")
            for info in infos:
                account(info.filename, info.file_size)
                with zf.open(info, pwd=password.encode() or None) as fh:
                    content = fh.read(MAX_MEMBER_SIZE + 1)
                account(info.filename, max(0, len(content) - info.file_size))
                yield info.filename, content
        return
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        infos = [m for m in tf.getmembers() if m.isfile()]
        if len(infos) > MAX_MEMBERS:
            raise ToolError(f"trop de fichiers dans l'archive ({len(infos)})")
        for info in infos:
            account(info.name, info.size)
            yield info.name, tf.extractfile(info).read()


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


def _strip_hex(text: str) -> str:
    """Tolère les écritures courantes d'un hexadécimal : 0x18, 0x41 0x42, 41:42."""
    return re.sub(r"0x|[\s:,]", "", text.strip(), flags=re.IGNORECASE)


def apply_op(op: str, value: bytes) -> bytes:
    name, _, arg = op.partition(":")
    rot = re.fullmatch(r"rot(\d+)", name)
    if rot and name not in _DECODERS:  # rot1, rot10... écrits sans deux-points
        name, arg = "rot", rot.group(1)
    try:
        if name == "rot":
            return _rot(value, int(arg))
        if name == "xor":
            try:
                key = bytes.fromhex(_strip_hex(arg))
            except ValueError:  # clé texte (xor:s4lt26) plutôt qu'hexadécimale
                key = arg.encode()
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
