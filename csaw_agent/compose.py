"""Lanceur de conteneur pour les challenges à serveur (étape 3 du plan).

Les 12 challenges « à serveur » de la base CSAW 2026 fournissent un
`docker-compose.yml` : le service se rattache au réseau externe `ctfnet` sous
l'alias `box` et `expose` (sans publier) son port interne. Pour les jouer hors
de l'infrastructure officielle, on publie ce port sur localhost et on redirige
la cible réseau de l'agent vers cette adresse.

Docker n'existe ni sur Kaggle ni sur Colab : ce module n'est utilisé que là où
`docker` est présent (GitHub Actions, PC de Daren, Codespaces). Sans Docker, le
lanceur se déclare indisponible et les challenges à serveur sont sautés.

Le compose n'est jamais modifié sur disque : on passe un fichier de surcharge
(`-f`) qui publie le port, ce qui laisse la base de challenges intacte et en
lecture seule.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

from .net import ServerTarget

CTF_NETWORK = "ctfnet"


class ComposeError(RuntimeError):
    """Le conteneur du challenge n'a pas pu démarrer ou être joint."""


def docker_available() -> bool:
    """Vrai si la ligne de commande docker répond (daemon joignable)."""
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _service_name(compose: dict) -> str:
    services = compose.get("services") or {}
    if not services:
        raise ComposeError("docker-compose.yml sans service")
    # Le service du challenge est en général l'unique service, ou celui dont un
    # alias ctfnet correspond au box ; à défaut, le premier.
    return next(iter(services))


def _run(args: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, **kw)


@contextmanager
def challenge_server(compose_path: Path, target: ServerTarget, timeout: int = 180):
    """Démarre le service du challenge et rend un `ServerTarget` vers localhost.

    À la sortie du bloc, le conteneur est arrêté et supprimé, réseau compris.
    L'appelant garde la base de challenges intacte : on n'écrit qu'un fichier de
    surcharge temporaire, à côté du compose, pour publier le port.
    """
    compose_path = Path(compose_path).resolve()
    compose = json.loads(compose_path.read_text(encoding="utf-8")) \
        if compose_path.suffix == ".json" else _load_yaml(compose_path)
    service = _service_name(compose)
    host_port = _free_port()

    # Surcharge : publie le port interne sur localhost. Déposée dans un dossier
    # temporaire, jamais dans la base (lecture seule).
    override = compose_path.parent / f".override-{host_port}.yml"
    override.write_text(json.dumps({
        "services": {service: {"ports": [f"127.0.0.1:{host_port}:{target.port}"]}}
    }), encoding="utf-8")
    project = f"csaw{host_port}"
    base_cmd = ["docker", "compose", "-p", project,
                "-f", str(compose_path), "-f", str(override)]
    # Le réseau externe ctfnet doit exister avant le up.
    _run(["docker", "network", "create", CTF_NETWORK])
    try:
        up = _run(base_cmd + ["up", "-d", "--build"], timeout=timeout)
        if up.returncode != 0:
            raise ComposeError(f"échec du démarrage : {up.stderr[-800:]}")
        local = target.with_endpoint("127.0.0.1", host_port)
        _wait_ready(local, timeout=min(timeout, 90))
        yield local
    finally:
        _run(base_cmd + ["down", "-v", "--remove-orphans"], timeout=120)
        override.unlink(missing_ok=True)


def _wait_ready(target: ServerTarget, timeout: int) -> None:
    """Attend que le port réponde (le conteneur met un temps à écouter)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((target.host, target.port), timeout=3):
                return
        except OSError:
            time.sleep(1)
    raise ComposeError(f"le service n'écoute pas après {timeout} s sur {target.human()}")


def _load_yaml(path: Path) -> dict:
    """Charge un docker-compose.yml. PyYAML si présent, sinon un repli minimal.

    La base CSAW 2026 fournit ses compose en JSON (qui est du YAML valide), donc
    json.loads suffit le plus souvent ; PyYAML couvre les vrais fichiers YAML.
    """
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        import yaml  # dépendance facultative
    except ImportError as exc:
        raise ComposeError(f"{path.name} n'est pas du JSON et PyYAML est absent "
                           "(pip install pyyaml)") from exc
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ComposeError(f"{path.name} : contenu compose invalide")
    return data
