"""Briefing de faits : le code écrit les faits, le modèle écrit les hypothèses.

Technique de prompt de l'agent. Au lieu d'un prompt de départ identique pour
tous les challenges, le code radiographie d'abord les fichiers (formats,
structure, données en trop, entropie) et rédige deux choses :

1. des **faits établis** : des constats certains, tirés des octets par du code
   déterministe. Le modèle n'a pas à les redécouvrir et ne peut pas les
   halluciner ;
2. des **fiches de méthode** génériques, choisies d'après les formats détectés
   (jamais d'après le nom du challenge) : par où commencer, en général, face à
   un exécutable, une image, une base SQLite...

Règlement CSAW : aucune fiche ne contient de solution ni de write-up. Ce sont
des points de départ généraux par type de fichier, valables pour n'importe quel
challenge. Les éléments tirés des fichiers (noms de tables, de sections) sont
filtrés à des identifiants courts avant d'entrer dans le prompt.
"""

from __future__ import annotations

import math
import re
import sqlite3
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .challenge import Challenge

MAX_FAITS = 30
MAX_FICHES = 4
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,39}$")

# Signatures cherchées à l'intérieur d'un fichier (contenu imbriqué, polyglotte).
_SIGNATURES = [
    (b"PK\x03\x04", "ZIP"),
    (b"%PDF-", "PDF"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"\x7fELF", "ELF"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"SQLite format 3\x00", "SQLite"),
]

_MACHINES = {3: "x86 (32 bits)", 62: "x86-64", 40: "ARM", 183: "AArch64", 8: "MIPS",
             243: "RISC-V", 20: "PowerPC"}

# Fonctions dont la seule présence, lue en clair dans le binaire, est un fait utile.
_SYMBOLES_NOTABLES = (
    "gets", "strcpy", "strcat", "sprintf", "scanf", "system", "execve", "popen",
    "mprotect", "ptrace", "srand", "rand", "memcmp", "strcmp", "strncmp", "seccomp_load",
)


# --- Fiches de méthode : générales, par format ou catégorie -------------------
# Points de départ généraux, du type qu'on trouve dans n'importe quel cours de CTF.
# Aucune ne vise un challenge précis.

FICHES: dict[str, str] = {
    "elf": (
        "Exécutable ELF : relever l'architecture et les protections (readelf -h -l -S), "
        "lister les symboles et les chaînes, puis désassembler (objdump -d) pour retrouver la "
        "logique de vérification de l'entrée. En rétro-ingénierie, reconstituer l'algorithme et "
        "l'inverser dans un script plutôt que le lire à la main ; s'il se déchiffre lui-même, "
        "reproduire la transformation par du code."),
    "pe": (
        "Exécutable Windows (PE) : chaînes et objdump -d pour localiser la vérification ; même "
        "démarche qu'un ELF (reconstituer la logique, puis l'inverser dans un script)."),
    "image": (
        "Image : lire les métadonnées (exiftool), parcourir la structure (blocs PNG, segments "
        "JPEG), repérer des données après le marqueur de fin, puis examiner les bits de poids "
        "faible canal par canal, le tout dans un script."),
    "zip": (
        "Archive : lister le contenu et les commentaires avant d'extraire. Si elle est chiffrée, "
        "chercher le mot de passe dans les autres fichiers et la description d'abord."),
    "imbrique": (
        "Signature d'un autre format repérée en plein milieu du fichier : découper à partir de "
        "l'offset indiqué (script Python) et analyser le morceau comme un fichier à part entière."),
    "sqlite": (
        "Base SQLite : lister les tables et lire les lignes (sqlite3). Regarder aussi un éventuel "
        "journal -wal : il peut contenir des enregistrements absents de la base principale."),
    "capture": (
        "Capture réseau : suivre les flux (tshark), isoler le protocole applicatif et "
        "reconstituer les données transférées."),
    "texte_encode": (
        "Texte qui ressemble à un encodage (base64, hexadécimal) : décoder par étapes avec "
        "l'outil decode et observer le résultat à chaque passe."),
    "crypto": (
        "Challenge de cryptographie : lire le script fourni pour identifier le schéma et ses "
        "paramètres, chercher la propriété qui le rend faible (petit exposant, module partagé, "
        "faible densité...), puis monter l'attaque correspondante dans un script."),
    "web": (
        "Service web : cartographier les routes et les paramètres, observer la gestion de session "
        "et des entrées, et tester les écarts entre ce que le serveur attend et ce qu'il accepte."),
    "pwn": (
        "Binaire de la catégorie pwn : d'abord caractériser, sans rien envoyer — architecture et "
        "protections (readelf, présence d'un canari, pile exécutable ou non, PIE), puis la "
        "fonction d'entrée et le format attendu. Reproduire et tester le comportement en local "
        "avant toute interaction avec le serveur du challenge."),
}

# Quels mots-clés du guess_type déclenchent quelle fiche.
_FICHE_PAR_TYPE = [
    ("ELF", "elf"), ("PE", "pe"), ("Windows", "pe"),
    ("PNG", "image"), ("JPEG", "image"), ("GIF", "image"),
    ("ZIP", "zip"), ("docx", "zip"), ("jar", "zip"),
    ("SQLite", "sqlite"), ("pcap", "capture"),
    ("base64", "texte_encode"), ("hexad", "texte_encode"),
]


@dataclass
class Briefing:
    faits: list[str] = field(default_factory=list)
    fiches: list[str] = field(default_factory=list)

    def texte(self) -> str:
        """Rend le briefing tel qu'il sera inséré dans le prompt de départ."""
        parts = []
        if self.faits:
            parts.append("Faits établis par une analyse automatique des fichiers "
                         "(certains, à ne pas revérifier) :\n"
                         + "\n".join(f"- {f}" for f in self.faits[:MAX_FAITS]))
        if self.fiches:
            parts.append("Pistes de méthode générales, d'après les formats détectés "
                         "(à adapter, ce ne sont pas des solutions) :\n"
                         + "\n".join(f"- {f}" for f in self.fiches[:MAX_FICHES]))
        return "\n\n".join(parts)


def _safe_ident(name: str) -> str | None:
    """Garde un nom tiré d'un fichier seulement s'il est court et anodin."""
    return name if _IDENT.match(name) else None


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def _elf_faits(data: bytes) -> list[str]:
    """Faits sûrs lus dans l'en-tête ELF, sans désassembler."""
    faits = []
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return faits
    bits = "64 bits" if data[4] == 2 else "32 bits"
    endian = "<" if data[5] == 1 else ">"
    machine = struct.unpack_from(endian + "H", data, 18)[0]
    faits.append(f"exécutable ELF {bits}, architecture {_MACHINES.get(machine, machine)}")
    etype = struct.unpack_from(endian + "H", data, 16)[0]
    faits.append("lié en position indépendante (PIE)" if etype == 3
                 else "exécutable à adresse fixe (non-PIE)" if etype == 2 else f"type ELF {etype}")
    # Symboles notables repérés en clair dans la table de chaînes, sans analyse fine.
    vus = [s for s in _SYMBOLES_NOTABLES if b"\x00" + s.encode() + b"\x00" in data]
    if vus:
        faits.append("symboles présents : " + ", ".join(vus[:12]))
    if b".text" in data and b"\x00" + b"UPX!" in data:
        faits.append("indices de compression UPX (binaire empaqueté)")
    return faits


def _sqlite_faits(path: Path) -> list[str]:
    faits = []
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        noms = [n for n in (_safe_ident(t) for t in tables) if n]
        if noms:
            faits.append(f"base SQLite, tables : {', '.join(noms[:12])}")
        con.close()
    except sqlite3.Error:
        faits.append("base SQLite (en-tête présent, lecture directe impossible)")
    for suffixe in ("-wal", "-journal"):
        if path.with_name(path.name + suffixe).exists():
            faits.append(f"journal SQLite « {path.name}{suffixe} » présent : "
                         "peut contenir des enregistrements absents de la base principale")
    return faits


def _file_faits(name: str, data: bytes, guessed: str) -> list[str]:
    """Constats certains pour un fichier donné."""
    faits = [f"« {name} » : {len(data)} octets, {guessed}, entropie {_entropy(data):.2f} bits/octet"]
    if _entropy(data) > 7.5 and "texte" not in guessed:
        faits.append(f"« {name} » a une entropie très élevée : contenu compressé ou chiffré probable")
    faits += _elf_faits(data)
    # Contenu d'un autre format repéré après le début (polyglotte / fichier joint).
    for sig, label in _SIGNATURES:
        pos = data.find(sig, 8)
        if pos != -1:
            faits.append(f"« {name} » contient une signature {label} à l'offset {pos} "
                         "(fichier imbriqué possible)")
            break
    return faits


def _fiches_pour(types_vus: set[str], category: str) -> list[str]:
    cles: list[str] = []
    for mot, cle in _FICHE_PAR_TYPE:
        if any(mot in t for t in types_vus) and cle not in cles:
            cles.append(cle)
    # Fiche imbriqué si un fichier en cache un autre (décidé dans les faits, pas ici).
    cat_fiche = {"crypto": "crypto", "web": "web", "pwn": "pwn", "rev": "elf"}.get(category)
    if cat_fiche and cat_fiche not in cles:
        cles.insert(0, cat_fiche)
    return [FICHES[c] for c in cles if c in FICHES]


def build_briefing(challenge: Challenge) -> Briefing:
    """Radiographie déterministe du challenge → faits établis + fiches de méthode.

    N'ouvre que les fichiers fournis au joueur (déjà filtrés à l'ingestion : les
    solutions des organisateurs ne sont jamais copiées), jamais le flag attendu.
    """
    from .tools import guess_type  # import tardif : évite une boucle d'import

    faits: list[str] = []
    types_vus: set[str] = set()
    a_imbrique = False
    for f in challenge.files:
        data = f.path.read_bytes()
        guessed = guess_type(data[:4096])
        types_vus.add(guessed)
        ff = _file_faits(f.name, data, guessed)
        faits += ff
        if any("imbriqué" in x for x in ff):
            a_imbrique = True
        if "SQLite" in guessed:
            faits += _sqlite_faits(f.path)
    if not challenge.files:
        faits.append("aucun fichier fourni : tout se joue sur la description "
                     "et, s'il existe, le service réseau")
    if challenge.needs_server:
        faits.append("ce challenge expose un service réseau : le flag est "
                     "généralement obtenu en dialoguant avec lui")

    fiches = _fiches_pour(types_vus, challenge.category)
    if a_imbrique:
        fiches.insert(0, FICHES["imbrique"])
    return Briefing(faits=faits, fiches=fiches[:MAX_FICHES])
