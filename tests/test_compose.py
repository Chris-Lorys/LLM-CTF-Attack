"""Lanceur de conteneur pour les challenges à serveur (parties sans Docker)."""

from __future__ import annotations

import json

import pytest

from csaw_agent import compose
from csaw_agent.compose import ComposeError, _free_port, _load_yaml, _service_name, docker_available


def test_docker_available_rend_un_booleen():
    assert isinstance(docker_available(), bool)


def test_free_port_dans_la_plage():
    port = _free_port()
    assert 1024 < port < 65536


def test_service_name_prend_le_premier_service():
    assert _service_name({"services": {"vespers": {}, "db": {}}}) == "vespers"
    with pytest.raises(ComposeError):
        _service_name({"services": {}})


def test_load_yaml_lit_le_compose_json_de_la_base(tmp_path):
    # La base CSAW 2026 fournit ses docker-compose.yml en JSON (YAML valide).
    path = tmp_path / "docker-compose.yml"
    path.write_text(json.dumps({"services": {"challenge": {"expose": ["5000"]}}}))
    assert _load_yaml(path)["services"]["challenge"]["expose"] == ["5000"]


def test_run_one_ignore_un_serveur_sans_docker(tmp_path):
    # Sans Docker et avec --skip-server, un challenge à serveur est ignoré, pas lancé.
    from csaw_agent.__main__ import _run_one
    from csaw_agent.challenge import ChallengeRef

    (tmp_path / "challenge.json").write_text(json.dumps(
        {"name": "srv", "flag": "x{y}", "box": "h", "internal_port": 5000, "proto": "http",
         "compose": True}))
    ref = ChallengeRef("srv", tmp_path / "challenge.json", "web", True)
    out = _run_one(ref, tmp_path / "runs", None, 3, None, skip_server=True, docker=False)
    assert out["status"] == "ignore_serveur"


def _simuler_up_trop_long(monkeypatch):
    """Remplace compose._run : `up` dépasse son délai, le reste réussit."""
    import subprocess

    def fake_run(args, **kw):
        if "up" in args:
            raise subprocess.TimeoutExpired(cmd=args, timeout=kw.get("timeout", 1))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(compose, "_run", fake_run)


def test_challenge_server_convertit_un_build_trop_long_en_compose_error(tmp_path, monkeypatch):
    # Un `docker compose up --build` qui dépasse le délai lève TimeoutExpired :
    # le lanceur doit la convertir en ComposeError (sinon tout le lot plante).
    from csaw_agent.compose import challenge_server
    from csaw_agent.net import ServerTarget

    compose_path = tmp_path / "docker-compose.yml"
    compose_path.write_text(json.dumps({"services": {"chal": {"expose": ["5000"]}}}))
    _simuler_up_trop_long(monkeypatch)

    with pytest.raises(ComposeError):
        with challenge_server(compose_path, ServerTarget("http", "box", 5000), timeout=1):
            pass


def test_run_one_serveur_qui_ne_demarre_pas_ne_plante_pas_le_lot(tmp_path, monkeypatch):
    # Régression (essai du 2026-11-10) : un conteneur trop long à construire
    # faisait remonter une TimeoutExpired brute et arrêtait les 11 challenges
    # suivants. _run_one doit renvoyer « erreur_serveur » sans lever.
    from csaw_agent.__main__ import _run_one
    from csaw_agent.challenge import ChallengeRef

    (tmp_path / "challenge.json").write_text(json.dumps(
        {"name": "srv", "flag": "x{y}", "box": "h", "internal_port": 5000, "proto": "http",
         "compose": True}))
    (tmp_path / "docker-compose.yml").write_text(json.dumps(
        {"services": {"srv": {"expose": ["5000"]}}}))
    _simuler_up_trop_long(monkeypatch)

    ref = ChallengeRef("srv", tmp_path / "challenge.json", "web", True)
    out = _run_one(ref, tmp_path / "runs", None, 3, None, skip_server=False, docker=True)
    assert out["status"] == "erreur_serveur"
