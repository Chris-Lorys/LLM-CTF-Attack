"""Routage multi-modèles par catégorie et résolution des clés par fournisseur."""

from __future__ import annotations

import pytest

from csaw_agent.llm import ModelRouter, _api_key, make_model, make_router


@pytest.fixture(autouse=True)
def _clean_keys(monkeypatch):
    for name in ("CSAW_API_KEY", "GEMINI_API_KEY", "OPENROUTER_API_KEY",
                 "CSAW_API_KEY_OPENROUTER", "GROQ_API_KEY"):
        monkeypatch.delenv(name, raising=False)


def test_cle_par_fournisseur(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "or")
    monkeypatch.setenv("GEMINI_API_KEY", "gm")
    assert _api_key("openrouter") == "or"
    assert _api_key("gemini") == "gm"
    assert _api_key("groq") is None  # aucune clé définie


def test_repli_sur_csaw_api_key(monkeypatch):
    # Un seul fournisseur : CSAW_API_KEY suffit encore (rétrocompatibilité).
    monkeypatch.setenv("CSAW_API_KEY", "unique")
    assert _api_key("gemini") == "unique"
    # Une clé propre au fournisseur l'emporte sur le repli.
    monkeypatch.setenv("CSAW_API_KEY_GEMINI", "propre")
    assert _api_key("gemini") == "propre"


def test_routeur_choisit_par_categorie(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "or")
    monkeypatch.setenv("GEMINI_API_KEY", "gm")
    router = make_router("crypto=openrouter:deepseek/deepseek-r1:free,"
                         "pwn=openrouter:moonshotai/kimi-k2.6:free,"
                         "default=gemini:gemini-2.5-flash")
    assert isinstance(router, ModelRouter)
    assert router.for_category("crypto").model == "deepseek/deepseek-r1:free"
    assert router.for_category("pwn").model == "moonshotai/kimi-k2.6:free"
    # Catégorie non routée : le modèle par défaut.
    assert router.for_category("web").model == "gemini-2.5-flash"
    assert router.for_category("crypto").api_key == "or"
    assert router.for_category("web").api_key == "gm"


def test_routage_invalide():
    with pytest.raises(ValueError):
        make_router("crypto=openrouter:x")  # pas de default
    with pytest.raises(ValueError):
        make_router("crypto,default=gemini:x")  # paire sans '='


def test_run_all_route_le_modele_par_categorie(tmp_path, monkeypatch):
    # Le challenge crypto doit recevoir le modèle crypto du routeur, pas le défaut.
    import json

    from csaw_agent.__main__ import run_all
    from csaw_agent.llm import ModelRouter, ScriptedModel

    chal = tmp_path / "cry"
    chal.mkdir()
    (chal / "challenge.json").write_text(json.dumps(
        {"name": "c", "category": "crypto", "flag": "x{y}", "description": "rien"}))

    crypto_model = ScriptedModel(['{"action": "give_up", "args": {"reason": "test"}}'])
    default_model = ScriptedModel(['{"action": "give_up", "args": {"reason": "test"}}'])
    router = ModelRouter({"crypto": crypto_model}, default_model)

    run_all(tmp_path, tmp_path / "runs", None, 2, router=router)
    # Seul le modèle crypto a été sollicité.
    assert crypto_model.received and not default_model.received
