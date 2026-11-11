import struct
from pathlib import Path

from csaw_agent.briefing import build_briefing, _entropy, _elf_faits
from csaw_agent.challenge import load_challenge

FIXTURES = Path(__file__).parent / "fixtures"


def test_entropie():
    assert _entropy(b"") == 0.0
    assert _entropy(b"\x00" * 100) == 0.0
    assert _entropy(bytes(range(256))) > 7.9  # uniforme → ~8 bits/octet


def test_elf_faits_lit_l_entete_sans_desassembler():
    # En-tête ELF64, x86-64, exécutable à adresse fixe (ET_EXEC=2).
    head = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9
    head += struct.pack("<HH", 2, 62)  # e_type=EXEC, e_machine=x86-64
    head += b"\x00" * 40
    head += b"\x00gets\x00gets\x00"  # symbole notable en clair
    faits = _elf_faits(head)
    assert any("x86-64" in f for f in faits)
    assert any("adresse fixe" in f for f in faits)
    assert any("gets" in f for f in faits)


def test_briefing_sur_fixture_encode_donne_faits_et_fiche(tmp_path):
    ch, _ = load_challenge(FIXTURES / "demo-encode" / "challenge.json", tmp_path)
    b = build_briefing(ch)
    # Un fait par fichier au minimum, avec la taille réelle.
    assert any("message.txt" in f and "octets" in f for f in b.faits)
    # Le texte final est non vide et annonce clairement qu'il ne contient pas de solution.
    txt = b.texte()
    assert "Faits établis" in txt
    assert "solutions" in txt or "pas des solutions" in txt


def test_briefing_ne_fuite_pas_le_flag(tmp_path):
    # demo-clair contient un flag en clair dans le fichier ; le briefing ne cite
    # que des faits de structure (taille, type, entropie), jamais le contenu.
    ch, verifier = load_challenge(FIXTURES / "demo-clair" / "challenge.json", tmp_path)
    b = build_briefing(ch)
    txt = b.texte().lower()
    assert "flag{" not in txt and "demo{" not in txt and "csaw{" not in txt


def test_briefing_sans_fichier(tmp_path):
    # Fabrique un challenge sans fichier pour vérifier le message dédié.
    import json
    d = tmp_path / "chal"
    d.mkdir()
    (d / "challenge.json").write_text(json.dumps(
        {"name": "x", "category": "misc", "description": "rien", "files": [], "flag": "demo{a}"}))
    ch, _ = load_challenge(d / "challenge.json", tmp_path / "ws")
    b = build_briefing(ch)
    assert any("aucun fichier" in f for f in b.faits)
