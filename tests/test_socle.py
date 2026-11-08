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


# --- Base CSAW 2026 (format dataset.json + challenge.json) -------------------

def _base_csaw(tmp_path):
    """Mini-base au format CSAW26_LLMAC_DB, avec des fichiers de solution à côté."""
    root = tmp_path / "db"
    chal = root / "2026" / "CSAW-Quals" / "crypto" / "mini"
    (chal / "files").mkdir(parents=True)
    (chal / "solution").mkdir()
    (chal / "files" / "data.txt").write_text("rien ici")
    (chal / "README.md").write_text("Énoncé pour les joueurs.")
    (chal / "solution" / "solve.py").write_text("print('demo{secret_solution}')")
    (chal / "flag.txt").write_text("demo{secret_solution}")
    (chal / "challenge.json").write_text(json.dumps({
        "name": "Mini", "category": "crypto",
        "description": "Service : nc {box} {port}",
        "flag": "demo{secret_solution}",
        "files": ["README.md", "files/data.txt", "solution/solve.py", "flag.txt"],
        "compose": True, "box": "mini.chal.csaw.io", "internal_port": 1337, "proto": "nc",
    }))
    web = root / "2026" / "CSAW-Quals" / "web" / "site"
    web.mkdir(parents=True)
    (web / "challenge.json").write_text(json.dumps({
        "name": "Site", "category": "web", "description": "http://{box}:{port}/",
        "flag": "demo{w}", "files": [], "compose": True, "box": "site", "internal_port": 80,
        "proto": "http"}))
    (root / "dataset.json").write_text(json.dumps({
        "2026q-cry-mini": {"category": "crypto", "path": "2026/CSAW-Quals/crypto/mini"},
        "2026q-web-site": {"category": "web", "path": "2026/CSAW-Quals/web/site"},
    }))
    return root, chal


def test_csaw_solutions_jamais_copiees(tmp_path):
    root, chal = _base_csaw(tmp_path)
    challenge, verifier = load_challenge(chal / "challenge.json", tmp_path / "ws")
    names = sorted(f.name for f in challenge.files)
    assert names == ["README.md", "data.txt"]
    assert set(challenge.excluded) == {"solution/solve.py", "flag.txt"}
    copied = b"".join(p.read_bytes() for p in (tmp_path / "ws" / "files").iterdir())
    assert b"secret_solution" not in copied
    assert "secret_solution" not in json.dumps(challenge.to_view())
    assert verifier.check("demo{secret_solution}")


def test_csaw_serveur_et_description(tmp_path):
    _, chal = _base_csaw(tmp_path)
    challenge, _ = load_challenge(chal / "challenge.json", tmp_path / "ws")
    assert challenge.description == "Service : nc mini.chal.csaw.io 1337"
    assert challenge.server == "nc mini.chal.csaw.io:1337"
    assert challenge.needs_server


def test_csaw_index_et_run_all(tmp_path):
    from csaw_agent.__main__ import run_all
    from csaw_agent.challenge import discover

    root, _ = _base_csaw(tmp_path)
    refs = discover(root / "dataset.json")
    assert [(r.id, r.category, r.needs_server) for r in refs] == [
        ("2026q-cry-mini", "crypto", True), ("2026q-web-site", "web", True)]
    assert [r.id for r in discover(root)] == ["2026q-cry-mini", "2026q-web-site"]

    results = run_all(root, tmp_path / "runs", None, 5, skip_server=True)
    assert [r["status"] for r in results] == ["ignore_serveur", "ignore_serveur"]
    results = run_all(root, tmp_path / "runs", None, 5, categories=["crypto"])
    assert [(r["id"], r["status"]) for r in results] == [("2026q-cry-mini", "non_resolu")]
    bilan = json.loads((tmp_path / "runs" / "bilan.json").read_text())
    assert bilan[0]["id"] == "2026q-cry-mini"


def test_csaw_noms_en_double(tmp_path):
    chal = tmp_path / "c"
    (chal / "a").mkdir(parents=True)
    (chal / "b").mkdir()
    (chal / "a" / "x.bin").write_bytes(b"1")
    (chal / "b" / "x.bin").write_bytes(b"2")
    (chal / "challenge.json").write_text(json.dumps(
        {"name": "c", "files": ["a/x.bin", "b/x.bin"], "flag": "x{y}"}))
    challenge, _ = load_challenge(chal / "challenge.json", tmp_path / "ws")
    assert [f.name for f in challenge.files] == ["x.bin", "b_x.bin"]


def test_rapport_avec_separateurs_unicode(tmp_path):
    """Une sortie d'outil contenant \\x85, U+2028 ou \\x0b ne doit pas casser le rapport."""
    from csaw_agent.report import build_report
    trace = TraceWriter(tmp_path / "trace.jsonl")
    trace.log("start", {"challenge_json": "x"})
    trace.log("tool_result", {"tool": "strings", "output": "a\x85b c d\x0be\x1cf"})
    trace.log("end", {"status": "non_resolu"})
    assert verify_trace(trace.path)[0]
    assert "Rapport" in build_report(trace.path)
