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


# --- Rapport et lancement en lot ---------------------------------------------

def test_rapport_tire_de_la_trace(tmp_path):
    model = ScriptedModel([
        act("decode", ops="base64", file="message.txt"),
        act("check_flag", candidate="qrzb{faux|`x`}"),
        act("decode", ops="base64|rot13", file="message.txt"),
    ])
    summary = run_challenge(FIXTURES / "demo-rot-base64" / "challenge.json", tmp_path, model)
    assert summary["status"] == "resolu"
    report = Path(summary["report"]).read_text()
    events = _events(summary)
    assert "demo{deux\\_couches}" in report and "oui, source : auto:decode" in report
    assert events[-1]["hash"] in report and "intègre" in report
    assert "flag refusé" in report
    # Un contenu venu du LLM ou du challenge ne casse pas le tableau.
    assert "\\|\\`x\\`" in report


def test_rapport_signale_une_trace_falsifiee(tmp_path):
    from csaw_agent.report import build_report
    summary = run_challenge(FIXTURES / "demo-clair" / "challenge.json", tmp_path)
    trace = Path(summary["run_dir"]) / "trace.jsonl"
    trace.write_text(trace.read_text().replace('"valid": false', '"valid": true'))
    assert "ÉCHEC" in build_report(trace)


def test_run_all_ecrit_un_bilan(tmp_path):
    from csaw_agent.__main__ import run_all
    results = run_all(FIXTURES, tmp_path, None, 5)
    assert len(results) == 4
    bilan = json.loads((tmp_path / "bilan.json").read_text())
    assert {r["status"] for r in bilan} == {"resolu", "non_resolu"}


# --- Extraction d'archives -----------------------------------------------------

def _zip(entries: dict[str, bytes]) -> bytes:
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_extract_zip_a_plat_et_sans_evasion(tmp_path):
    from csaw_agent.tools import Toolbox
    files = tmp_path / "files"
    files.mkdir()
    (files / "a.zip").write_bytes(_zip({"dir/note.txt": b"bonjour", "../../evil.txt": b"x"}))
    box = Toolbox(files)
    out = box.call("extract", {"file": "a.zip"})
    assert "a.zip__dir__note.txt" in out
    assert not (tmp_path / "evil.txt").exists()
    assert box.call("read_file", {"file": "a.zip__dir__note.txt"}) == "bonjour"
    assert "déjà extrait" in box.call("extract", {"file": "a.zip"})


def test_extract_refuse_une_non_archive(tmp_path):
    import pytest
    from csaw_agent.tools import Toolbox, ToolError
    files = tmp_path / "files"
    files.mkdir()
    (files / "t.txt").write_text("pas une archive")
    with pytest.raises(ToolError):
        Toolbox(files).call("extract", {"file": "t.txt"})


# --- Fautes relevées dans le premier essai Kaggle (qwen2.5:7b) --------------

def test_parse_action_repare_les_echappements_hex():
    from csaw_agent.agent import parse_action
    text = '{"action": "check_flag", "args": {"candidate": "ab\\x0bcd"}}'
    assert parse_action(text)["args"]["candidate"] == "ab\x0bcd"


def test_parse_action_garde_un_antislash_echappe():
    from csaw_agent.agent import parse_action
    text = '{"action": "decode", "args": {"data": "a\\\\x41"}}'
    assert parse_action(text)["args"]["data"] == "a\\x41"


def test_parse_action_entier_hexadecimal():
    from csaw_agent.agent import parse_action
    text = '{"action": "read_file", "args": {"file": "a", "offset": 0x200, "data": "0x41"}}'
    args = parse_action(text)["args"]
    assert args["offset"] == 512 and args["data"] == "0x41"


def test_parse_action_reponse_vide():
    import pytest
    from csaw_agent.agent import parse_action
    with pytest.raises(ValueError, match="vide"):
        parse_action("   ")


def test_decode_tolere_data_et_file(tmp_path):
    from csaw_agent.tools import Toolbox
    files = tmp_path / "files"
    files.mkdir()
    (files / "m.txt").write_text("aGVsbG8=")
    box = Toolbox(files)
    assert box.call("decode", {"ops": "base64", "file": "m.txt", "data": ""}) == "hello"
    assert box.call("decode", {"ops": "base64", "data": "aGk=", "file": "m.txt"}) == "hi"


def test_xor_cle_avec_prefixe_0x():
    from csaw_agent.tools import apply_op
    assert apply_op("xor:0x01", b"\x00\x01") == b"\x01\x00"


def test_outil_inconnu_liste_les_outils(tmp_path):
    import pytest
    from csaw_agent.tools import Toolbox, ToolError
    with pytest.raises(ToolError, match="read_file"):
        Toolbox(tmp_path).call("nc", {})


# --- Robustesse du lot et liens symboliques posés par le shell ---------------

def test_run_all_continue_apres_un_plantage(tmp_path, monkeypatch):
    import json
    from csaw_agent import __main__ as cli
    for name in ("a", "b"):
        d = tmp_path / "db" / name
        d.mkdir(parents=True)
        (d / "challenge.json").write_text(json.dumps({"name": name, "flag": "x{y}"}))
    real = cli.run_challenge

    def flaky(path, *a, **k):
        if path.parent.name == "a":
            raise RuntimeError("boum")
        return real(path, *a, **k)

    monkeypatch.setattr(cli, "run_challenge", flaky)
    results = cli.run_all(tmp_path / "db", tmp_path / "runs", None, 3)
    assert [r["status"] for r in results] == ["erreur_interne", "non_resolu"]
    assert len(json.loads((tmp_path / "runs" / "bilan.json").read_text())) == 2


def test_outils_ne_suivent_pas_un_lien_vers_l_exterieur(tmp_path):
    import io
    import zipfile
    import pytest
    from csaw_agent.tools import Toolbox, ToolError
    secret = tmp_path / "secret.txt"
    secret.write_text("demo{fuite}")
    files = tmp_path / "files"
    files.mkdir()
    (files / "lien").symlink_to(secret)
    box = Toolbox(files)
    with pytest.raises(ToolError):
        box.call("read_file", {"file": "lien"})
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("x.txt", "contenu")
    (files / "a.zip").write_bytes(buf.getvalue())
    (files / "a.zip__x.txt").symlink_to(tmp_path / "cible")  # lien pendant
    assert "déjà extrait" in box.call("extract", {"file": "a.zip"})
    assert not (tmp_path / "cible").exists()


# --- Fautes relevées dans l'essai 2 (shell, qwen2.5:7b) ----------------------

def test_parse_action_recupere_un_shell_aux_guillemets_non_echappes():
    from csaw_agent.agent import parse_action
    text = ('{"categorie": "forensics", "action": "shell", "args": {"command": '
            '"tshark -r c.pcap -Y "ip.dst == 10.0.0.1" -T fields", "timeout": 20}}')
    action = parse_action(text)
    assert action["args"] == {"command": 'tshark -r c.pcap -Y "ip.dst == 10.0.0.1" -T fields',
                              "timeout": 20}


def test_noms_de_fichiers_sans_espaces(tmp_path):
    import json
    from csaw_agent.challenge import load_challenge
    chal = tmp_path / "c"
    chal.mkdir()
    (chal / "12345678 (1).wav").write_bytes(b"RIFF")
    (chal / "challenge.json").write_text(json.dumps(
        {"name": "c", "files": ["12345678 (1).wav"], "flag": "x{y}"}))
    challenge, _ = load_challenge(chal / "challenge.json", tmp_path / "ws")
    assert challenge.files[0].name == "12345678_1_.wav"


def test_extract_nom_trop_long_et_nom_d_origine(tmp_path):
    from csaw_agent.tools import Toolbox
    files = tmp_path / "files"
    files.mkdir()
    long_name = "d/" + "x" * 300 + ".bin"
    (files / "a.zip").write_bytes(_zip({long_name: b"long", "capsule.json": b"{}"}))
    box = Toolbox(files)
    box.call("extract", {"file": "a.zip"})
    assert all(len(p.name) < 255 for p in files.iterdir())
    assert box.call("read_file", {"file": "capsule.json"}) == "{}"


def test_action_repetee_non_relancee(tmp_path):
    import json
    from csaw_agent.agent import Agent
    from csaw_agent.challenge import load_challenge
    from csaw_agent.llm import ScriptedModel
    from csaw_agent.tools import Toolbox
    from csaw_agent.trace import TraceWriter
    challenge, verifier = load_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path)
    same = json.dumps({"action": "list_files", "args": {}})
    model = ScriptedModel([same, same, json.dumps({"action": "give_up", "args": {"reason": "x"}})])
    trace = TraceWriter(tmp_path / "trace.jsonl")
    Agent(model, Toolbox(tmp_path / "files"), verifier, trace, 5).solve(challenge)
    events = [json.loads(l) for l in (tmp_path / "trace.jsonl").read_text().splitlines()]
    assert sum(e["type"] == "tool_result" for e in events) == 1
    assert any(e["payload"].get("repetition") for e in events if e["type"] == "decision")


def test_note_reste_visible_apres_l_historique(tmp_path):
    import json
    from csaw_agent.agent import HISTORY_WINDOW, Agent
    from csaw_agent.challenge import load_challenge
    from csaw_agent.llm import ScriptedModel
    from csaw_agent.trace import TraceWriter
    challenge, verifier = load_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path)
    actions = [json.dumps({"action": "note", "args": {"text": "la clé est 0x42"}})]
    actions += [json.dumps({"action": "read_file", "args": {"file": "message.txt", "offset": i}})
                for i in range(HISTORY_WINDOW)]
    actions.append(json.dumps({"action": "give_up", "args": {"reason": "x"}}))
    seen = []

    class Spy(ScriptedModel):
        def complete(self, messages):
            seen.append(messages)
            return super().complete(messages)

    Agent(Spy(actions), Toolbox(tmp_path / "files"), verifier,
          TraceWriter(tmp_path / "t.jsonl"), 30).solve(challenge)
    last = seen[-1]
    assert "la clé est 0x42" in last[1]["content"]
    assert len(last) <= 2 + HISTORY_WINDOW
    assert all("la clé est 0x42" not in m["content"] for m in last[2:3] if m["role"] == "assistant")
