"""Atelier : l'agent écrit un outil, le code le garde et le propose au challenge suivant."""

import json
from pathlib import Path

import pytest

from csaw_agent.atelier import Atelier, AtelierError
from csaw_agent.llm import ScriptedModel
from csaw_agent.run import run_challenge

FIXTURES = Path(__file__).parent / "fixtures"
ENCODE = FIXTURES / "demo-encode" / "challenge.json"
FLAG = "demo{base64_decode}"


def act(action, **args):
    return json.dumps({"categorie": "rev", "pensee": "t", "action": action, "args": args})


def _events(run_dir):
    return [json.loads(l) for l in (Path(run_dir) / "trace.jsonl").read_text().splitlines()]


def test_garder_valide_et_liste(tmp_path):
    a = Atelier(tmp_path / "lib")
    outil = a.garder("decode_vm", "désassemble la VM", "x = 1\nprint(x)\n",
                     categorie="rev", origine="machine_head")
    assert outil.nom == "decode_vm" and outil.lignes == 3
    assert [o.nom for o in a.liste()] == ["decode_vm"]
    assert a.charger("decode_vm").startswith("x = 1")
    assert "decode_vm [rev]" in a.bloc_briefing()


def test_garder_refuse_nom_description_et_syntaxe(tmp_path):
    a = Atelier(tmp_path / "lib")
    with pytest.raises(AtelierError):
        a.garder("Mauvais Nom", "ok", "print(1)")
    with pytest.raises(AtelierError):
        a.garder("outil", "", "print(1)")
    with pytest.raises(AtelierError, match="compile"):
        a.garder("outil", "desc", "def f(:\n")  # syntaxe invalide : refusé


def test_bibliotheque_vide_ne_donne_pas_de_bloc(tmp_path):
    assert Atelier(tmp_path / "lib").bloc_briefing() == ""


def test_charger_inconnu(tmp_path):
    a = Atelier(tmp_path / "lib")
    assert a.charger("absent") is None
    assert a.charger("../secret") is None  # nom hors motif : jamais de chemin


def test_garder_puis_reutiliser_sur_le_challenge_suivant(tmp_path):
    atelier = Atelier(tmp_path / "lib")
    # Challenge 1 : le modèle écrit un script et demande à le garder.
    script = "import sys\nprint('outil réutilisable')\n"
    run1 = run_challenge(
        ENCODE, tmp_path / "r1",
        ScriptedModel([
            act("write_file", name="solve.py", content=script),
            act("garder_outil", file="solve.py", nom="mon_decodeur", description="décode"),
            act("give_up", reason="demo"),
        ]), max_steps=5, atelier=atelier)
    ev1 = _events(run1["run_dir"])
    garde = next(e for e in ev1 if e["type"] == "tool_result" and e["payload"]["tool"] == "garder_outil")
    assert garde["payload"]["ok"] and "rangé" in garde["payload"]["output"]
    assert (tmp_path / "lib" / "mon_decodeur.py").read_text() == script

    # Challenge 2 : l'outil est annoncé dans le prompt et peut être repris.
    run2 = run_challenge(
        ENCODE, tmp_path / "r2",
        ScriptedModel([
            act("utiliser_outil", nom="mon_decodeur"),
            act("give_up", reason="demo"),
        ]), max_steps=5, atelier=atelier)
    ev2 = _events(run2["run_dir"])
    prompt = next(e for e in ev2 if e["type"] == "prompt")
    assert "mon_decodeur" in json.dumps(prompt["payload"], ensure_ascii=False)
    repris = next(e for e in ev2 if e["type"] == "tool_result"
                  and e["payload"]["tool"] == "utiliser_outil")
    assert repris["payload"]["ok"] and (Path(run2["run_dir"]) / "files" / "mon_decodeur.py").is_file()


def test_garder_refuse_un_fichier_non_ecrit(tmp_path):
    atelier = Atelier(tmp_path / "lib")
    run = run_challenge(
        ENCODE, tmp_path / "r",
        ScriptedModel([
            act("garder_outil", file="message.txt", nom="triche", description="x"),
            act("give_up", reason="demo"),
        ]), max_steps=5, atelier=atelier)
    res = next(e for e in _events(run["run_dir"]) if e["type"] == "tool_result"
               and e["payload"]["tool"] == "garder_outil")
    assert not res["payload"]["ok"] and "write_file" in res["payload"]["output"]
    assert atelier.liste() == []


def test_sans_atelier_les_actions_ne_sont_pas_proposees(tmp_path):
    run = run_challenge(ENCODE, tmp_path / "r",
                        ScriptedModel([act("give_up", reason="demo")]), max_steps=5)
    prompt = next(e for e in _events(run["run_dir"]) if e["type"] == "prompt")
    texte = json.dumps(prompt["payload"], ensure_ascii=False)
    assert "garder_outil" not in texte and "utiliser_outil" not in texte
