"""Dossier des échecs : tiré des traces, sans LLM, résolus écartés."""

import json
from pathlib import Path

from csaw_agent.echecs import dossier_echecs
from csaw_agent.llm import ScriptedModel
from csaw_agent.run import run_challenge

FIXTURES = Path(__file__).parent / "fixtures"


def act(action, pensee="t", **args):
    return json.dumps({"categorie": "crypto", "pensee": pensee, "action": action, "args": args})


def test_dossier_liste_les_tentatives_et_ecarte_les_resolus(tmp_path):
    echec = run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path, ScriptedModel([
        act("strings", pensee="je cherche du texte lisible", path="message.txt"),
        act("give_up", pensee="rien trouvé", reason="aucune piste"),
    ]))
    resolu = run_challenge(FIXTURES / "demo-clair" / "challenge.json", tmp_path / "b", None)
    assert resolu["status"] == "resolu" and echec["status"] != "resolu"
    traces = [Path(s["run_dir"]) / "trace.jsonl" for s in (echec, resolu)]
    texte = dossier_echecs(traces)
    assert "1 challenge(s) jamais résolu(s), 1 résolu(s) écartés" in texte
    assert "strings ×1" in texte and "je cherche du texte lisible" in texte
    assert "aucune piste" in texte
