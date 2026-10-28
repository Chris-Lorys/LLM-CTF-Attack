import json
from pathlib import Path

import pytest

from csaw_agent.challenge import ChallengeError, load_challenge, normalize_category
from csaw_agent.flag import FlagVerifier, find_candidates
from csaw_agent.run import run_challenge
from csaw_agent.trace import TraceWriter, verify_trace
from csaw_agent.untrusted import wrap_untrusted

FIXTURES = Path(__file__).parent / "fixtures"


# --- Ingestion -------------------------------------------------------------

def test_flag_absent_de_la_vue(tmp_path):
    challenge, _ = load_challenge(FIXTURES / "demo-clair" / "challenge.json", tmp_path)
    assert "demo{socle_ok}" not in json.dumps(challenge.to_view())
    assert challenge.category == "forensics"


def test_fichiers_copies_en_lecture_seule(tmp_path):
    challenge, _ = load_challenge(FIXTURES / "demo-clair" / "challenge.json", tmp_path)
    copied = challenge.files[0].path
    assert copied.parent == tmp_path / "files"
    # On teste les bits de permission : root passerait outre un open("w").
    assert copied.stat().st_mode & 0o222 == 0


def test_refuse_un_chemin_hors_du_challenge(tmp_path):
    chal = tmp_path / "evil"
    chal.mkdir()
    (chal / "challenge.json").write_text(json.dumps(
        {"name": "evil", "files": ["../../etc/passwd"], "flag": "x{y}"}))
    with pytest.raises(ChallengeError):
        load_challenge(chal / "challenge.json", tmp_path / "ws")


def test_refuse_un_challenge_sans_flag(tmp_path):
    chal = tmp_path / "c"
    chal.mkdir()
    (chal / "challenge.json").write_text(json.dumps({"name": "c"}))
    with pytest.raises(ChallengeError):
        load_challenge(chal / "challenge.json", tmp_path / "ws")


@pytest.mark.parametrize("raw,expected", [
    ("Reverse", "rev"), ("cryptography", "crypto"), ("PWN", "pwn"),
    ("inconnu", "misc"), (None, "misc"),
])
def test_normalisation_des_categories(raw, expected):
    assert normalize_category(raw) == expected


# --- Vérification du flag --------------------------------------------------

def test_verificateur_tolere_espaces_et_invisibles():
    v = FlagVerifier("csawctf{abc}")
    assert v.check("  csawctf{abc}\n")
    assert v.check("csawctf{abc}​")
    assert not v.check("csawctf{abd}")
    assert v.attempts == 3


def test_le_flag_ne_fuit_pas_par_repr():
    assert "abc" not in repr(FlagVerifier("csawctf{abc}"))


def test_detection_des_candidats():
    text = "rien flag{a} encore csawctf{b_c} et flag{a}"
    assert find_candidates(text) == ["flag{a}", "csawctf{b_c}"]


# --- Trace -----------------------------------------------------------------

def test_trace_integre_puis_falsifiee(tmp_path):
    path = tmp_path / "trace.jsonl"
    t = TraceWriter(path)
    t.log("start", {"a": 1})
    t.log("decision", {"b": 2})
    t.log("end", {"c": 3})
    assert verify_trace(path)[0]

    lines = path.read_text().splitlines()
    lines[1] = lines[1].replace('"b": 2', '"b": 99')
    path.write_text("\n".join(lines) + "\n")
    ok, message = verify_trace(path)
    assert not ok and "ligne 2" in message


def test_trace_detecte_une_ligne_supprimee(tmp_path):
    path = tmp_path / "trace.jsonl"
    t = TraceWriter(path)
    for i in range(3):
        t.log("decision", {"i": i})
    lines = path.read_text().splitlines()
    path.write_text(lines[0] + "\n" + lines[2] + "\n")
    assert not verify_trace(path)[0]


def test_trace_refuse_d_ecraser(tmp_path):
    path = tmp_path / "trace.jsonl"
    TraceWriter(path).log("start", {})
    with pytest.raises(FileExistsError):
        TraceWriter(path)


# --- Données non fiables ---------------------------------------------------

def test_encadrement_nettoie_et_tronque():
    out = wrap_untrusted("\x1b[31mrouge\x1b[0m\x00" + "a" * 50, "test", limit=20)
    assert "\x1b" not in out and "\x00" not in out
    assert "tronqués" in out
    assert out.startswith('<donnees_non_fiables source="test"')


def test_encadrement_identifiant_imprevisible():
    a, b = wrap_untrusted("x", "s"), wrap_untrusted("x", "s")
    assert a != b


# --- Bout en bout ----------------------------------------------------------

def test_run_resout_le_cas_en_clair_et_ignore_le_leurre(tmp_path):
    summary = run_challenge(FIXTURES / "demo-clair" / "challenge.json", tmp_path)
    assert summary["status"] == "resolu"
    assert summary["flag"] == "demo{socle_ok}"
    assert summary["attempts"] == 2  # le leurre est essayé puis rejeté

    trace = Path(summary["run_dir"]) / "trace.jsonl"
    assert verify_trace(trace)[0]
    events = [json.loads(line) for line in trace.read_text().splitlines()]
    assert [e["type"] for e in events][0] == "start"
    assert events[-1]["type"] == "end"
    checks = [e["payload"]["valid"] for e in events if e["type"] == "check_flag"]
    assert checks == [False, True]


def test_run_sans_llm_ne_resout_pas_le_cas_encode(tmp_path):
    summary = run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path)
    assert summary["status"] == "non_resolu"
    assert summary["attempts"] == 0
