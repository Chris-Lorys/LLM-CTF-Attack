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
