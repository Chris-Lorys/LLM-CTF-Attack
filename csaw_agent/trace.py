"""Trace complète et non retouchée (étape 7 du pipeline).

Chaque événement est une ligne JSON ajoutée à la fin du fichier, jamais
réécrite. Chaque ligne porte le hachage SHA-256 de la précédente : modifier,
supprimer ou réordonner une ligne casse la chaîne, ce que `verify_trace`
détecte.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64

EVENT_TYPES = (
    "start",
    "ingestion",
    "prompt",
    "llm_response",
    "tool_call",
    "tool_result",
    "decision",
    "check_flag",
    "end",
)


def _digest(record: dict) -> str:
    body = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


class TraceWriter:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() and self.path.stat().st_size:
            raise FileExistsError(f"trace déjà présente, refus d'écraser : {self.path}")
        self._seq = 0
        self._prev = GENESIS

    def log(self, event_type: str, payload: dict, **meta) -> dict:
        if event_type not in EVENT_TYPES:
            raise ValueError(f"type d'événement inconnu : {event_type}")
        record = {
            "seq": self._seq,
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "type": event_type,
            "payload": payload,
            **meta,
            "prev_hash": self._prev,
        }
        record["hash"] = _digest(record)
        # Ouverture en ajout à chaque écriture : rien n'est perdu si l'agent plante.
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            fh.flush()
        self._seq += 1
        self._prev = record["hash"]
        return record


def verify_trace(path: Path) -> tuple[bool, str]:
    """Vérifie la chaîne de hachages. Retourne (ok, message)."""
    prev = GENESIS
    with Path(path).open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                return False, f"ligne {lineno} : JSON invalide"
            stored = record.pop("hash", None)
            if record.get("seq") != lineno - 1:
                return False, f"ligne {lineno} : numéro de séquence inattendu"
            if record.get("prev_hash") != prev:
                return False, f"ligne {lineno} : chaînage rompu"
            if _digest(record) != stored:
                return False, f"ligne {lineno} : contenu modifié"
            prev = stored
    return True, "trace intègre"
