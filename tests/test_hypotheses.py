from csaw_agent.hypotheses import HypothesisRegister


def test_declarer_et_statuer():
    r = HypothesisRegister()
    msg, hid = r.declarer("le binaire est packé UPX")
    assert hid == "H1" and "H1" in msg
    assert r.ouvertes()[0].texte.startswith("le binaire")
    assert r.statuer("H1", "refutee") == "H1 marquée refutee."
    assert r.ouvertes() == []


def test_refus_de_rouvrir_une_hypothese_refutee():
    r = HypothesisRegister()
    _, hid = r.declarer("la clé XOR fait un octet")
    r.statuer(hid, "refutee")
    # Reformulée presque à l'identique : le code la reconnaît et la refuse.
    msg, hid2 = r.declarer("La clé XOR fait un octet !")
    assert hid2 == "" and "réfutée" in msg


def test_doublon_ouvert_renvoie_le_meme_id():
    r = HypothesisRegister()
    _, hid = r.declarer("flag caché en stéganographie LSB")
    msg, hid2 = r.declarer("flag caché en stéganographie LSB")
    assert hid2 == hid and "ouverte" in msg


def test_statuer_id_inconnu_et_statut_invalide():
    r = HypothesisRegister()
    assert "inconnue" in r.statuer("H9", "confirmee")
    r.declarer("x")
    assert "statut attendu" in r.statuer("H1", "n_importe_quoi")


def test_bloc_prompt_et_relance():
    r = HypothesisRegister()
    r.declarer("piste A")
    _, hid = r.declarer("piste B")
    r.statuer(hid, "refutee")
    bloc = r.bloc_prompt()
    assert "H1" in bloc and "H2" in bloc and "✗" in bloc and "?" in bloc
    assert "H2" in r.relance()  # la relance cite la piste réfutée à éviter


def test_texte_vide_refuse():
    r = HypothesisRegister()
    msg, hid = r.declarer("   ")
    assert hid == "" and "attend" in msg
