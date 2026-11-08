"""Tests du bac à sable du shell. Ils demandent root et un utilisateur dédié ;
sinon ils sont sautés (p. ex. sur un PC de développement)."""

import os
import pwd
import shutil
import subprocess

import pytest

from csaw_agent.sandbox import Sandbox, SandboxError
from csaw_agent.tools import Toolbox

USER = "ctfsandbox"


def _ready() -> bool:
    if os.geteuid() != 0 or not shutil.which("setpriv"):
        return False
    try:
        pwd.getpwnam(USER)
    except KeyError:
        subprocess.run(["useradd", "-M", "-s", "/bin/bash", USER], check=False)
    try:
        pwd.getpwnam(USER)
        return True
    except KeyError:
        return False


pytestmark = pytest.mark.skipif(not _ready(), reason="root et setpriv requis")


@pytest.fixture
def box(tmp_path):
    tmp_path.chmod(0o755)
    base = tmp_path / "base"
    (base / "solution").mkdir(parents=True)
    (base / "solution" / "solve.py").write_text("print('demo{fuite}')")
    files = tmp_path / "files"
    files.mkdir()
    (files / "data.txt").write_text("bonjour\n")
    (files / "data.txt").chmod(0o444)
    sandbox = Sandbox(USER, [base], timeout=5)
    return Toolbox(files, sandbox), base


def test_shell_lit_les_fichiers_du_challenge(box):
    toolbox, _ = box
    out = toolbox.call("shell", {"command": "cat data.txt"})
    assert "bonjour" in out


def test_shell_ne_lit_pas_la_base(box):
    toolbox, base = box
    out = toolbox.call("shell", {"command": f"cat {base}/solution/solve.py; ls {base}"})
    assert "demo{fuite}" not in out
    assert "Permission denied" in out


def test_shell_sans_reseau(box):
    toolbox, _ = box
    # Dans l'espace de noms réseau du bac à sable, seule l'interface lo existe.
    out = toolbox.call("shell", {"command": "tail -n +3 /proc/net/dev | cut -d: -f1"})
    interfaces = out.split("\n", 1)[1].split()
    assert interfaces == ["lo"]


def test_shell_delai(box):
    toolbox, _ = box
    out = toolbox.call("shell", {"command": "sleep 30", "timeout": 1})
    assert "délai" in out


def test_shell_fichier_cree_lisible_par_les_outils(box):
    toolbox, _ = box
    toolbox.call("shell", {"command": "echo cGxvcA== > b64.txt"})
    assert toolbox.call("decode", {"ops": "base64", "file": "b64.txt"}) == "plop"


def test_shell_garde_fou(box):
    toolbox, _ = box
    assert "refusé" in toolbox.call("shell", {"command": "git clone https://x/y"})


def test_mode_userns_ne_lit_pas_la_base(box):
    """Repli utilisé quand root ne peut pas créer d'espace de noms réseau."""
    toolbox, base = box
    toolbox.sandbox.net_mode = "userns"
    out = toolbox.call("shell", {"command": f"cat {base}/solution/solve.py; "
                                 "tail -n +3 /proc/net/dev | cut -d: -f1"})
    assert "demo{fuite}" not in out and "Permission denied" in out
    assert out.split("\n", 1)[1].split()[-1] == "lo"


def test_refuse_un_utilisateur_absent(tmp_path):
    with pytest.raises(SandboxError):
        Sandbox("utilisateur_qui_n_existe_pas", [])
