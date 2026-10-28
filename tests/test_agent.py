import json
from pathlib import Path

import pytest

from csaw_agent.agent import parse_action
from csaw_agent.llm import ScriptedModel, make_model
from csaw_agent.run import run_challenge
from csaw_agent.tools import Toolbox, ToolError, apply_op, guess_type
from csaw_agent.trace import verify_trace

FIXTURES = Path(__file__).parent / "fixtures"
EXPECTED = "demo{base64_decode}"


def _events(summary):
    trace = Path(summary["run_dir"]) / "trace.jsonl"
    assert verify_trace(trace)[0]
    return [json.loads(line) for line in trace.read_text().splitlines()]


def act(action, categorie="crypto", **args):
    return json.dumps({"categorie": categorie, "pensee": "test", "action": action, "args": args})


# --- Interprétation des réponses du LLM -------------------------------------

def test_parse_action_tolere_le_bloc_de_code_et_le_texte():
    reply = 'Voici mon plan.\n```json\n{"action": "list_files", "args": {}}\n```'
    assert parse_action(reply)["action"] == "list_files"


def test_parse_action_refuse_une_reponse_sans_action():
    with pytest.raises(ValueError):
        parse_action("je pense que c'est du base64")


# --- Outils ------------------------------------------------------------------

def test_decode_en_chaine():
    assert apply_op("rot13", apply_op("base64", b"cXJ6YnsxfQ==")) == b"demo{1}"
    assert apply_op("xor:01", b"enns") == b"door"
    assert apply_op("rot:3", b"abc") == b"def"


def test_toolbox_refuse_les_chemins_et_les_mauvais_types(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    box = Toolbox(tmp_path)
    with pytest.raises(ToolError):
        box.call("read_file", {"file": "../a.txt"})
    with pytest.raises(ToolError):
        box.call("read_file", {"file": "a.txt", "length": "10"})
    with pytest.raises(ToolError):
        box.call("rm", {})
    assert box.call("read_file", {"file": "a.txt"}) == "x"


def test_guess_type():
    assert guess_type(b"\x7fELF\x02") == "exécutable ELF"
    assert "base64" in guess_type(b"ZGVtbw==")


# --- Interface modèle --------------------------------------------------------

def test_make_model_presets():
    m = make_model("ollama:qwen2.5:3b")
    assert m.model == "qwen2.5:3b" and m.base_url.startswith("http://localhost:11434")
    m = make_model("mon-modele", "https://exemple.kaggle/v1")
    assert m.model == "mon-modele" and m.base_url == "https://exemple.kaggle/v1"


# --- Boucle complète avec un modèle scripté ---------------------------------

def test_boucle_resout_le_cas_encode_par_verification_automatique(tmp_path):
    model = ScriptedModel([
        act("file_info", file="message.txt"),
        act("decode", ops="base64", file="message.txt"),
    ])
    summary = run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path, model)
    assert summary["status"] == "resolu"
    assert summary["flag"] == EXPECTED
    assert summary["category"] == "crypto"
    assert summary["llm_steps"] == 2

    events = _events(summary)
    checks = [e["payload"] for e in events if e["type"] == "check_flag"]
    assert checks == [{"candidate": EXPECTED, "source": "auto:decode", "valid": True}]


def test_le_flag_attendu_n_est_jamais_envoye_au_modele(tmp_path):
    model = ScriptedModel([act("list_files"), act("give_up", reason="test")])
    summary = run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path, model)
    assert summary["status"] == "abandon"
    assert EXPECTED not in json.dumps(model.received)


def test_adaptation_apres_erreurs(tmp_path):
    model = ScriptedModel([
        "pas du JSON",
        act("decode", ops="base99", file="message.txt"),
        act("check_flag", candidate="demo{faux}"),
        act("check_flag", candidate=EXPECTED),
    ])
    summary = run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path, model)
    assert summary["status"] == "resolu"
    # Chaque erreur a été renvoyée au modèle pour qu'il corrige sa stratégie.
    feedback = [m["content"] for m in model.received[-1] if m["role"] == "user"]
    assert any("illisible" in f for f in feedback)
    assert any("opération inconnue" in f for f in feedback)
    assert any("FAUX" in f for f in feedback)


def test_sortie_d_outil_encadree_comme_non_fiable(tmp_path):
    model = ScriptedModel([act("read_file", file="message.txt"), act("give_up", reason="x")])
    run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path, model)
    last_user = [m for m in model.received[-1] if m["role"] == "user"][-1]["content"]
    assert '<donnees_non_fiables source="outil read_file"' in last_user


def test_budget_epuise(tmp_path):
    model = ScriptedModel([act("list_files")] * 3)
    summary = run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path, model,
                            max_steps=3)
    assert summary["status"] == "non_resolu"
    assert _events(summary)[-2]["payload"]["stop"] == "budget_epuise"


def test_modele_injoignable(tmp_path):
    model = make_model("ollama:inexistant", "http://127.0.0.1:9/v1")
    summary = run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path, model)
    assert summary["status"] == "erreur_llm"
