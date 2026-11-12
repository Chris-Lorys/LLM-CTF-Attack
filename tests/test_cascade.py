"""Cascade frugale : le code mesure la progression et décide d'escalader."""

import json
from pathlib import Path

import pytest

from csaw_agent.__main__ import main
from csaw_agent.cascade import (Cascade, Progression, evaluer_cascade, make_cascade, rejouer,
                                tableau_cascade)
from csaw_agent.llm import LLMError, ScriptedModel
from csaw_agent.run import run_challenge
from csaw_agent.trace import verify_trace

FIXTURES = Path(__file__).parent / "fixtures"
ENCODE = FIXTURES / "demo-encode" / "challenge.json"
FLAG = "demo{base64_decode}"


def act(action, **args):
    return json.dumps({"categorie": "crypto", "pensee": "t", "action": action, "args": args})


class Named(ScriptedModel):
    def __init__(self, name, replies):
        super().__init__(replies)
        self.name = name


def _events(run_dir):
    return [json.loads(l) for l in (Path(run_dir) / "trace.jsonl").read_text().splitlines()]


def test_progression_gain_puis_stagnation():
    m = Progression(patience=3)
    m.observe("llm_response", {"step": 1})
    m.observe("tool_result", {"tool": "strings", "ok": True, "output": "aaaa\nbbbb\ncccc"})
    assert m.sans_gain == 0 and m.stagne() is None  # trois lignes nouvelles : gain
    for step in (2, 3, 4):  # même sortie : aucune ligne nouvelle
        m.observe("llm_response", {"step": step})
        m.observe("tool_result", {"tool": "strings", "ok": True, "output": "aaaa\nbbbb\ncccc"})
    assert "sans information nouvelle" in m.stagne()
    m.reinitialiser()
    assert m.stagne() is None and "aaaa" in m.lignes_vues  # on garde ce qui a été vu


def test_progression_echecs_consecutifs():
    m = Progression(echecs_max=3)
    m.observe("tool_result", {"tool": "shell", "ok": False, "output": "erreur"})
    m.observe("decision", {"step": 2, "repetition": "shell"})
    m.observe("check_flag", {"candidate": "x{y}", "source": "llm", "valid": False})
    assert "3 échecs" in m.stagne()
    m.observe("decision", {"step": 4, "note": "fait utile"})  # une note est un gain
    assert m.stagne() is None


def test_cascade_spec():
    c = make_cascade("ollama:petit>ollama:grand", patience=4)
    assert [m.name.split("@")[0] for m in c.paliers] == ["petit", "grand"]
    assert c.patience == 4 and c.name.startswith("cascade(")
    with pytest.raises(ValueError):
        make_cascade("ollama:seul")


def test_escalade_sur_repetition_et_passation(tmp_path):
    lire = act("read_file", path="message.txt")
    petit = Named("petit", [lire, lire, lire, lire, lire])  # tourne en rond
    fort = Named("fort", [act("check_flag", candidate=FLAG)])
    c = Cascade([petit, fort], patience=10, echecs_max=3)
    s = run_challenge(ENCODE, tmp_path, max_steps=10, cascade=c)
    assert s["status"] == "resolu" and s["model"] == "fort"
    assert len(s["cascade"]["escalades"]) == 1
    esc = s["cascade"]["escalades"][0]
    assert esc["de"] == "petit" and esc["vers"] == "fort" and "échecs" in esc["raison"]
    # Le modèle fort reçoit un état compact, pas l'historique où le petit s'est perdu.
    premier = fort.received[0]
    assert len(premier) == 2 and "Reprise par un modèle plus fort" in premier[1]["content"]
    assert "read_file" in premier[1]["content"]
    ev = _events(s["run_dir"])
    assert any(e["type"] == "decision" and "escalade" in e["payload"] for e in ev)
    assert verify_trace(Path(s["run_dir"]) / "trace.jsonl")[0]
    rapport = (Path(s["run_dir"]) / "rapport.md").read_text()
    assert "Cascade frugale" in rapport and "escalade décidée par le code" in rapport


def test_escalade_sur_erreur_du_modele(tmp_path):
    class Panne(Named):
        def complete(self, messages):
            raise LLMError("HTTP 429")
    fort = Named("fort", [act("check_flag", candidate=FLAG)])
    s = run_challenge(ENCODE, tmp_path, max_steps=5,
                      cascade=Cascade([Panne("petit", []), fort]))
    assert s["status"] == "resolu"
    assert "erreur du modèle" in s["cascade"]["escalades"][0]["raison"]


def test_sans_palier_restant_le_comportement_est_inchange(tmp_path):
    lire = act("read_file", path="message.txt")
    seul = Named("seul", [lire] * 6)
    s = run_challenge(ENCODE, tmp_path, max_steps=6, cascade=Cascade([seul], echecs_max=2))
    assert s["status"] == "non_resolu" and s["cascade"]["escalades"] == []


def test_rejouer_et_balayage(tmp_path):
    lire = act("read_file", path="message.txt")
    s = run_challenge(ENCODE, tmp_path, ScriptedModel([lire] * 8), max_steps=8)
    r = rejouer(Path(s["run_dir"]) / "trace.jsonl", patience=4, echecs_max=3)
    assert not r["resolu"] and r["detection"] is not None and r["apres_detection"] > 0
    ok = run_challenge(ENCODE, tmp_path / "b", ScriptedModel([act("check_flag", candidate=FLAG)]))
    traces = [Path(x["run_dir"]) / "trace.jsonl" for x in (s, ok)]
    res = evaluer_cascade(traces, patiences=(4, 8))
    assert res["balayage"][0]["fausses_alertes"] == 0
    assert "Patience" in tableau_cascade(res)


def test_cli_cascade_traces(tmp_path, capsys):
    s = run_challenge(ENCODE, tmp_path, ScriptedModel([act("give_up", reason="x")]))
    out = tmp_path / "c.json"
    assert main(["cascade-traces", str(Path(s["run_dir"]) / "trace.jsonl"), "--out", str(out)]) == 0
    assert json.loads(out.read_text())["balayage"]


def test_cli_cascade_depuis_un_fichier(tmp_path, capsys):
    spec = tmp_path / "cascade.txt"
    spec.write_text("ollama:seul\n")  # un seul palier : refusé avec un message clair
    code = main(["run", str(ENCODE), "--cascade", f"@{spec}", "--runs-dir", str(tmp_path / "r")])
    assert code == 2 and "au moins deux paliers" in capsys.readouterr().err


def test_escalades_reelles_dans_les_traces(tmp_path):
    from csaw_agent.cascade import escalades_reelles, tableau_escalades
    lire = act("read_file", path="message.txt")
    c = Cascade([Named("petit", [lire] * 5), Named("fort", [act("check_flag", candidate=FLAG)])])
    s = run_challenge(ENCODE, tmp_path, max_steps=10, cascade=c)
    sans = run_challenge(ENCODE, tmp_path / "b", ScriptedModel([act("give_up", reason="x")]))
    runs = escalades_reelles([Path(x["run_dir"]) / "trace.jsonl" for x in (s, sans)])
    assert len(runs) == 1 and runs[0]["statut"] == "resolu" and len(runs[0]["escalades"]) == 1
    assert "échecs" in tableau_escalades(runs)
