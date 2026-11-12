import json
from pathlib import Path

from csaw_agent.__main__ import main
from csaw_agent.soumission import assemble
from csaw_agent.trace import TraceWriter


def _essai(root: Path, name: str, entries: list[tuple[str, str, str]]) -> Path:
    """Fabrique un dossier d'essai comme l'artefact « runs » : bilan.json + traces."""
    essai = root / name
    bilan = []
    for i, (cid, cat, status) in enumerate(entries):
        short = cid.split("-", 2)[2]
        run_dir = essai / short / f"2026111{i}T000000Z"
        run_dir.mkdir(parents=True)
        t = TraceWriter(run_dir / "trace.jsonl")
        t.log("start", {"challenge": cid, "essai": name})
        t.log("end", {"status": status})
        (run_dir / "rapport.md").write_text(f"# {cid} {status} {name}\n", encoding="utf-8")
        bilan.append({"id": cid, "category_db": cat, "status": status, "model": "m@x",
                      "llm_steps": 3, "run_dir": f"runs/{short}/2026111{i}T000000Z"})
    bilan.append({"id": "2026q-web-absent", "category_db": "web", "status": "ignore_serveur"})
    (essai / "bilan.json").write_text(json.dumps(bilan), encoding="utf-8")
    return essai


def test_retient_la_tentative_reussie_et_nomme_selon_la_convention(tmp_path):
    e1 = _essai(tmp_path, "111", [("2026q-rev-autobahn", "rev", "resolu"),
                                  ("2026q-web-juggler", "web", "non_resolu")])
    e2 = _essai(tmp_path, "222", [("2026q-rev-autobahn", "rev", "non_resolu"),
                                  ("2026q-web-juggler", "web", "resolu"),
                                  ("2026q-pwn-diamond_dogs", "pwn", "abandon")])
    out = tmp_path / "out"
    summary = assemble([e1, e2], out)

    names = sorted(p.name for p in (out / "transcripts").iterdir())
    assert names == [
        "pwn_diamond_dogs_unsolved.jsonl", "pwn_diamond_dogs_unsolved.md",
        "rev_autobahn_solved.jsonl", "rev_autobahn_solved.md",
        "web_juggler_solved.jsonl", "web_juggler_solved.md",
    ]
    # La réussite du 1er essai n'est pas écrasée par l'échec du 2e.
    assert "111" in (out / "transcripts" / "rev_autobahn_solved.md").read_text()
    assert summary["resolus"] == ["2026q-rev-autobahn", "2026q-web-juggler"]
    assert summary["tentatives"] == 5 and summary["traces_rejetees"] == []
    # Toutes les tentatives sont conservées en annexe, octet pour octet.
    assert (out / "ancillary" / "traces" / "222" / "2026q-rev-autobahn.jsonl").read_bytes() == \
        (e2 / "autobahn" / "20261110T000000Z" / "trace.jsonl").read_bytes()
    assert "| 111 | 2026q-rev-autobahn | rev | resolu |" in (out / "ancillary" / "essais.md").read_text()


def test_une_trace_alteree_n_est_jamais_publiee(tmp_path):
    e1 = _essai(tmp_path, "111", [("2026q-cry-polly", "crypto", "resolu")])
    trace = e1 / "polly" / "20261110T000000Z" / "trace.jsonl"
    trace.write_text(trace.read_text().replace("resolu", "RESOLU"), encoding="utf-8")
    out = tmp_path / "out"
    summary = assemble([e1], out)
    assert summary["traces_rejetees"] and summary["resolus"] == []
    assert list((out / "transcripts").iterdir()) == []
    assert main(["soumission", str(e1), "--out", str(tmp_path / "o2")]) == 1


def test_refuse_un_chemin_qui_sort_de_l_essai(tmp_path):
    e1 = _essai(tmp_path, "111", [("2026q-rev-autobahn", "rev", "resolu")])
    bilan = json.loads((e1 / "bilan.json").read_text())
    bilan[0]["run_dir"] = "runs/../../ailleurs"
    (e1 / "bilan.json").write_text(json.dumps(bilan))
    summary = assemble([e1], tmp_path / "out")
    assert summary["challenges"] == 0


def test_artefact_neste_bilan_dans_un_sous_dossier(tmp_path):
    """Essai avec --atelier au niveau racine : l'artefact a runs/ + atelier/, donc
    bilan.json et les traces sont sous runs/. L'assemblage doit quand même les trouver."""
    e = _essai(tmp_path, "999", [("2026q-rev-autobahn", "rev", "non_resolu")])
    # On simule le nesting : tout le contenu de l'essai passe sous runs/, plus atelier/.
    nested = tmp_path / "999n"
    (nested / "runs").mkdir(parents=True)
    for item in e.iterdir():
        item.rename(nested / "runs" / item.name)
    (nested / "atelier").mkdir()
    (nested / "atelier" / "index.json").write_text("{}", encoding="utf-8")

    out = tmp_path / "out"
    summary = assemble([nested], out)
    assert summary["tentatives"] == 1
    assert (out / "transcripts" / "rev_autobahn_unsolved.jsonl").is_file()
    # L'étiquette de l'essai reste l'ID du run (999n), pas « runs ».
    assert (out / "ancillary" / "traces" / "999n" / "2026q-rev-autobahn.jsonl").is_file()
