"""Orchestration d'un run : ingestion, pré-scan déterministe, boucle LLM, fin.

Ce module fixe ce que tout run doit respecter : un dossier par run, une trace
écrite par le code, un flag vérifié hors LLM. Le LLM n'intervient que si le
pré-scan, gratuit et déterministe, n'a rien trouvé.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from pathlib import Path

from .agent import Agent
from .challenge import Challenge, load_challenge
from .flag import FlagVerifier, find_candidates
from .llm import ChatModel
from .report import write_report
from .tools import Toolbox
from .trace import TraceWriter

_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def _readable_strings(data: bytes, min_len: int = 4) -> str:
    """Équivalent simple de `strings` : suites de caractères imprimables."""
    return "\n".join(m.decode() for m in re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data))


def prescan(challenge: Challenge, verifier: FlagVerifier, trace: TraceWriter,
            tried: set[str] | None = None) -> str | None:
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
            if tried is not None:
                tried.add(candidate)
            ok = verifier.check(candidate)
            trace.log("check_flag", {"candidate": candidate, "source": source, "valid": ok})
            if ok:
                return candidate
    return None


def run_challenge(json_path: Path, runs_dir: Path = Path("runs"),
                  model: ChatModel | None = None, max_steps: int = 20) -> dict:
    started = time.monotonic()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = Path(runs_dir) / _SAFE.sub("_", Path(json_path).parent.name) / stamp
    run_dir.mkdir(parents=True, exist_ok=False)

    trace = TraceWriter(run_dir / "trace.jsonl")
    trace.log("start", {"challenge_json": str(json_path)})

    challenge, verifier = load_challenge(json_path, run_dir)
    trace.log("ingestion", challenge.to_view())

    tried: set[str] = set()
    flag = prescan(challenge, verifier, trace, tried)
    status = "resolu" if flag else "non_resolu"
    category, steps = None, 0

    if flag is None and model is not None:
        agent = Agent(model, Toolbox(run_dir / "files"), verifier, trace, max_steps)
        result = agent.solve(challenge, tried)
        flag, category, steps = result.flag, result.category, result.steps
        status = result.status if result.status != "budget_epuise" else "non_resolu"

    summary = {
        "status": status,
        "flag": flag,
        "model": model.name if model else None,
        "category": category,
        "llm_steps": steps,
        "attempts": verifier.attempts,
        "duration_s": round(time.monotonic() - started, 3),
        "run_dir": str(run_dir),
    }
    trace.log("end", summary)
    # Le rapport est tiré de la trace une fois celle-ci close : il n'y ajoute rien.
    summary["report"] = str(write_report(trace.path))
    return summary
