"""Orchestration minimale d'un run : ingestion, pré-scan déterministe, fin.

La boucle LLM (stratégie, outils, adaptation) viendra se brancher entre le
pré-scan et la fin. Ce module fixe déjà ce que tout run doit respecter :
un dossier par run, une trace écrite par le code, un flag vérifié hors LLM.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from pathlib import Path

from .challenge import Challenge, load_challenge
from .flag import FlagVerifier, find_candidates
from .trace import TraceWriter

_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def _readable_strings(data: bytes, min_len: int = 4) -> str:
    """Équivalent simple de `strings` : suites de caractères imprimables."""
    return "\n".join(m.decode() for m in re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data))


def prescan(challenge: Challenge, verifier: FlagVerifier, trace: TraceWriter) -> str | None:
    """Cherche un flag en clair dans la description et les fichiers.

    Pas de LLM ici : regex puis vérification. Couvre les cas triviaux et
    sert de test de bout en bout du socle.
    """
    sources = {"description": challenge.description}
    for f in challenge.files:
        sources[f.name] = _readable_strings(f.path.read_bytes())

    for source, text in sources.items():
        candidates = find_candidates(text)
        trace.log("tool_result", {"tool": "prescan", "source": source,
                                  "candidates": candidates})
        for candidate in candidates:
            ok = verifier.check(candidate)
            trace.log("check_flag", {"candidate": candidate, "source": source, "valid": ok})
            if ok:
                return candidate
    return None


def run_challenge(json_path: Path, runs_dir: Path = Path("runs")) -> dict:
    started = time.monotonic()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = Path(runs_dir) / _SAFE.sub("_", Path(json_path).parent.name) / stamp
    run_dir.mkdir(parents=True, exist_ok=False)

    trace = TraceWriter(run_dir / "trace.jsonl")
    trace.log("start", {"challenge_json": str(json_path)})

    challenge, verifier = load_challenge(json_path, run_dir)
    trace.log("ingestion", challenge.to_view())

    flag = prescan(challenge, verifier, trace)
    status = "resolu" if flag else "non_resolu"

    summary = {
        "status": status,
        "flag": flag,
        "attempts": verifier.attempts,
        "duration_s": round(time.monotonic() - started, 3),
        "run_dir": str(run_dir),
    }
    trace.log("end", summary)
    return summary
