import json
from pathlib import Path

import pytest

from csaw_agent.ablation import (REFERENCE, VARIANTES, analyser_trace, analyser_traces,
                                 run_ablation, tableau_markdown, variante)
from csaw_agent.llm import ScriptedModel
from csaw_agent.run import run_challenge

FIXTURES = Path(__file__).parent / "fixtures"
EXPECTED = "demo{base64_decode}"


def act(action, categorie="crypto", **args):
    return json.dumps({"categorie": categorie, "pensee": "t", "action": action, "args": args})


def _events(run_dir):
    return [json.loads(l) for l in (Path(run_dir) / "trace.jsonl").read_text().splitlines()]


def test_matrice_des_variantes():
    assert [v.nom for v in VARIANTES] == [
        "A_reference", "B_sans_prescan", "C_sans_autoverif", "D_sans_memoire", "E_sans_outils",
        "F_sans_briefing", "G_sans_hypotheses"]
    assert REFERENCE.prescan and REFERENCE.auto_verif and REFERENCE.memoire and REFERENCE.outils
    assert REFERENCE.briefing and REFERENCE.hypotheses
    assert variante("B_sans_prescan").prescan is False
    assert variante("E_sans_outils").outils is False
    assert variante("F_sans_briefing").briefing is False
    assert variante("G_sans_hypotheses").hypotheses is False
    with pytest.raises(KeyError):
        variante("inconnue")


def test_sans_prescan_ne_trouve_plus_le_flag_en_clair(tmp_path):
    # Référence : le pré-scan déterministe résout demo-clair sans appeler le LLM.
    ref = run_challenge(FIXTURES / "demo-clair" / "challenge.json", tmp_path / "a", None)
    assert ref["status"] == "resolu" and ref["llm_steps"] == 0
    # Variante B : sans pré-scan et sans modèle, le flag en clair n'est plus trouvé.
    b = run_challenge(FIXTURES / "demo-clair" / "challenge.json", tmp_path / "b", None,
                      ablation=variante("B_sans_prescan"))
    assert b["status"] == "non_resolu"


def test_sans_autoverif_le_candidat_des_outils_n_est_plus_valide(tmp_path):
    # Référence : decode produit le flag, vérifié automatiquement (source auto:decode).
    ref = run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path / "a",
                        ScriptedModel([act("decode", ops="base64", file="message.txt")]))
    assert ref["status"] == "resolu"
    # Variante C : le même décodage ne déclenche plus rien ; le LLM abandonne.
    m = ScriptedModel([act("decode", ops="base64", file="message.txt"),
                       act("give_up", reason="x")])
    c = run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path / "b", m,
                      ablation=variante("C_sans_autoverif"))
    assert c["status"] == "abandon"
    # Mais check_flag explicite reste vérifié hors LLM : l'intégrité est préservée.
    m2 = ScriptedModel([act("check_flag", candidate=EXPECTED)])
    c2 = run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path / "c", m2,
                       ablation=variante("C_sans_autoverif"))
    assert c2["status"] == "resolu"


def test_sans_memoire_ne_bloque_pas_la_repetition(tmp_path):
    same = act("list_files")
    # Référence : la 2e action identique est bloquée par la garde anti-répétition.
    ref = run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path / "a",
                        ScriptedModel([same, same, act("give_up", reason="x")]), max_steps=5)
    ev = _events(ref["run_dir"])
    assert any(e["type"] == "decision" and e["payload"].get("repetition") for e in ev)
    n_ref = sum(1 for e in ev if e["type"] == "tool_result"
                and e["payload"].get("tool") == "list_files")
    assert n_ref == 1  # la 2e n'a pas été exécutée

    # Variante D : la répétition n'est plus bloquée, les deux list_files s'exécutent.
    d = run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path / "b",
                      ScriptedModel([same, same, act("give_up", reason="x")]), max_steps=5,
                      ablation=variante("D_sans_memoire"))
    evd = _events(d["run_dir"])
    assert not any(e["type"] == "decision" and e["payload"].get("repetition") for e in evd)
    n_d = sum(1 for e in evd if e["type"] == "tool_result"
              and e["payload"].get("tool") == "list_files")
    assert n_d == 2


def test_sans_outils_vide_la_boite(tmp_path):
    m = ScriptedModel([act("list_files"), act("give_up", reason="x")])
    e = run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path, m,
                      ablation=variante("E_sans_outils"))
    results = [x["payload"] for x in _events(e["run_dir"])
               if x["type"] == "tool_result" and x["payload"].get("tool") == "list_files"]
    assert results and results[0]["ok"] is False and "inconnu" in results[0]["output"]


def test_briefing_present_par_defaut_absent_en_variante_F(tmp_path):
    # Référence : le briefing de faits est journalisé dans la trace.
    ref = run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path / "a",
                        ScriptedModel([act("give_up", reason="x")]))
    ev = _events(ref["run_dir"])
    assert any(e["type"] == "ingestion" and "briefing" in e["payload"] for e in ev)
    # Variante F : aucun briefing.
    f = run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path / "b",
                      ScriptedModel([act("give_up", reason="x")]),
                      ablation=variante("F_sans_briefing"))
    evf = _events(f["run_dir"])
    assert not any(e["type"] == "ingestion" and "briefing" in e["payload"] for e in evf)


def test_hypothese_suivie_par_le_code(tmp_path):
    # Le modèle déclare une hypothèse, la réfute, puis abandonne : la trace garde l'état.
    actions = [act("hypothese", texte="le flag est en base64"),
               json.dumps({"categorie": "crypto", "pensee": "t", "action": "hypothese",
                           "args": {"id": "H1", "statut": "refutee"}}),
               act("give_up", reason="x")]
    e = run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path,
                      ScriptedModel(actions))
    ev = _events(e["run_dir"])
    hyps = [x["payload"] for x in ev if x["type"] == "decision" and "hypothese" in x["payload"]]
    assert len(hyps) == 2
    assert hyps[-1]["etat"][0]["statut"] == "refutee"


def test_variante_G_ne_propose_pas_l_action_hypothese(tmp_path):
    g = run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path,
                      ScriptedModel([act("give_up", reason="x")]),
                      ablation=variante("G_sans_hypotheses"))
    ev = _events(g["run_dir"])
    prompt = next(e for e in ev if e["type"] == "prompt")
    système = prompt["payload"]["messages"][0]["content"]
    assert "hypothese(" not in système


def test_analyse_retrospective_attribue_la_bonne_source(tmp_path):
    s1 = run_challenge(FIXTURES / "demo-clair" / "challenge.json", tmp_path / "clair", None)
    a1 = analyser_trace(Path(s1["run_dir"]) / "trace.jsonl")
    assert a1["source_flag"] == "prescan"
    assert a1["candidats_rejetes"] >= 1  # le leurre flag{faux_flag} a été écarté

    s2 = run_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path / "enc",
                       ScriptedModel([act("decode", ops="base64", file="message.txt")]))
    a2 = analyser_trace(Path(s2["run_dir"]) / "trace.jsonl")
    assert a2["source_flag"] == "auto:decode" and a2["etapes_llm"] == 1

    agg = analyser_traces([Path(s1["run_dir"]) / "trace.jsonl",
                           Path(s2["run_dir"]) / "trace.jsonl"])
    assert agg["resolues"] == 2
    assert agg["flags_par_source"] == {"prescan": 1, "auto:decode": 1}


def test_run_ablation_orchestre_et_resume(tmp_path):
    # Matrice complète sur demo-clair, sans modèle : seul le pré-scan peut résoudre.
    summary = run_ablation(FIXTURES, ["demo-clair"], tmp_path, None, 3)
    bilan = summary["bilan"]
    assert bilan["A_reference"]["resolus"] == 1
    assert bilan["B_sans_prescan"]["resolus"] == 0  # pré-scan retiré → plus de flag
    assert bilan["E_sans_outils"]["resolus"] == 1   # pré-scan suffit, outils non requis
    md = tableau_markdown(summary)
    assert "A_reference" in md and "B_sans_prescan" in md and "référence" in md
