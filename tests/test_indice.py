"""Approche hybride : indice humain, tracé mot pour mot, jamais un flag."""

import json
from pathlib import Path

import pytest

from csaw_agent.__main__ import main
from csaw_agent.llm import ScriptedModel
from csaw_agent.run import IndiceError, MAX_INDICE, run_challenge, valider_indice
from csaw_agent.trace import verify_trace

FIXTURES = Path(__file__).parent / "fixtures"
INDICE = "le message semble encodé, essaie les décodages usuels"


def act(action, **args):
    return json.dumps({"categorie": "crypto", "pensee": "t", "action": action, "args": args})


def _events(run_dir):
    return [json.loads(l) for l in (Path(run_dir) / "trace.jsonl").read_text().splitlines()]


def test_valider_indice_refuse_vide_trop_long_et_flag():
    assert valider_indice(f"  {INDICE}  ") == INDICE
    with pytest.raises(IndiceError):
        valider_indice("   ")
    with pytest.raises(IndiceError):
        valider_indice("x" * (MAX_INDICE + 1))
    with pytest.raises(IndiceError, match="flag"):
        valider_indice("la réponse est demo{base64_decode}")


def test_indice_refuse_ne_cree_aucun_run(tmp_path):
    with pytest.raises(IndiceError):
        run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path,
                      ScriptedModel([act("give_up", reason="x")]), indice="csaw{triche}")
    assert not any(tmp_path.iterdir())


def test_indice_trace_avant_le_modele_et_dans_le_prompt(tmp_path):
    s = run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path,
                      ScriptedModel([act("give_up", reason="x")]), indice=INDICE)
    assert s["approche"] == "hybride"
    ev = _events(s["run_dir"])
    i_indice = next(i for i, e in enumerate(ev)
                    if e["type"] == "ingestion" and e["payload"].get("indice_humain") == INDICE)
    i_prompt = next(i for i, e in enumerate(ev) if e["type"] == "prompt")
    assert i_indice < i_prompt  # consigné avant le premier appel au modèle
    assert INDICE in ev[i_prompt]["payload"]["messages"][1]["content"]
    assert verify_trace(Path(s["run_dir"]) / "trace.jsonl")[0]
    rapport = (Path(s["run_dir"]) / "rapport.md").read_text()
    assert "hybride" in rapport and INDICE in rapport


def test_sans_indice_l_approche_est_autonome(tmp_path):
    s = run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path,
                      ScriptedModel([act("give_up", reason="x")]))
    assert s["approche"] == "autonome"
    assert "autonome" in (Path(s["run_dir"]) / "rapport.md").read_text()


def test_cli_indices_refuse_un_fichier_avec_flag(tmp_path, capsys):
    f = tmp_path / "indices.json"
    f.write_text(json.dumps({"demo-encode": "regarde demo{base64_decode}"}))
    code = main(["run-all", str(FIXTURES), "--indices", str(f), "--runs-dir", str(tmp_path / "r")])
    assert code == 2
    assert "indices refusés" in capsys.readouterr().err
