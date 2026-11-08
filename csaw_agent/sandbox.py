"""Bac à sable du shell (outil `shell`).

Le LLM choisit des commandes à partir de données non fiables (description et
fichiers du challenge) : une injection de prompt peut donc lui faire lancer
n'importe quoi. Le bac à sable borne ce que ces commandes peuvent atteindre,
au lieu de compter sur le LLM pour bien se tenir (chapitre 4).

Défenses, de la plus forte à la plus faible :

1. Utilisateur dédié sans privilèges (`setpriv`) : il ne peut pas lire le clone
   de la base CSAW, qui contient les solutions des organisateurs. Ce point est
   vérifié au démarrage : si un chemin protégé reste lisible, le shell refuse
   de démarrer.
2. Pas de réseau (`unshare -n`, ou `unshare -rn` lancé par l'utilisateur dédié) : rien ne peut être téléchargé, y compris les
   solutions publiées en ligne. Si l'isolation réseau est impossible sur la
   machine, le shell refuse de démarrer, sauf option explicite, et la trace
   le dit.
3. Délai maximal, groupe de processus tué à l'échéance, environnement vidé,
   sortie tronquée.
4. Garde-fou textuel : refus des commandes qui visent la base ou le réseau
   (git, curl, wget, pip...). Contournable, il ne sert qu'à signaler tôt.

Chaque commande et sa sortie sont écrites dans la trace par la boucle de l'agent.
"""

from __future__ import annotations

import os
import pwd
import re
import shutil
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path

DEFAULT_USER = "ctfsandbox"
MAX_TIMEOUT = 120
MAX_CAPTURE = 1 << 20

_DENY = re.compile(
    r"\b(git|curl|wget|pip3?|apt(-get)?|ssh|scp|ftp|sudo|su|docker)\b"
    r"|LLMAC|CSAW26|github\.com|writeup|write-up",
    re.IGNORECASE,
)


class SandboxError(RuntimeError):
    """Le bac à sable ne peut pas démarrer avec les garanties demandées."""


@dataclass
class ShellResult:
    command: str
    returncode: int | None
    output: str
    timed_out: bool


class Sandbox:
    def __init__(self, user: str = DEFAULT_USER, protected: list[Path] | None = None,
                 isolate_network: bool = True, timeout: int = 30):
        if os.geteuid() != 0:
            raise SandboxError("le shell en bac à sable doit être lancé en root "
                               "(pour basculer vers l'utilisateur dédié)")
        for tool in ("setpriv", "unshare", "bash"):
            if shutil.which(tool) is None:
                raise SandboxError(f"commande système manquante : {tool}")
        try:
            entry = pwd.getpwnam(user)
        except KeyError as exc:
            raise SandboxError(f"utilisateur {user!r} absent : useradd -M {user}") from exc
        if entry.pw_uid == 0:
            raise SandboxError("l'utilisateur du bac à sable ne doit pas être root")
        self.user, self.uid, self.gid = user, entry.pw_uid, entry.pw_gid
        self.timeout = timeout
        self.protected = [Path(p).resolve() for p in (protected or [])]
        # Deux façons de couper le réseau : espace de noms créé par root (le plus
        # courant), ou, si le conteneur l'interdit (pas de CAP_SYS_ADMIN), espace de
        # noms utilisateur créé par l'utilisateur du bac à sable lui-même.
        self.net_mode = None
        if isolate_network:
            if self._probe(["unshare", "-n", "true"]):
                self.net_mode = "root"
            elif self._probe(self._drop() + ["unshare", "-rn", "true"]):
                self.net_mode = "userns"
        self.network_isolated = self.net_mode is not None
        if isolate_network and not self.network_isolated:
            raise SandboxError("isolation réseau impossible (unshare -n) ; relancer avec "
                               "l'isolation réseau désactivée, en connaissance de cause")
        for path in self.protected:
            self._hide(path)

    # --- Préparation ----------------------------------------------------------

    @staticmethod
    def _probe(cmd: list[str]) -> bool:
        try:
            return subprocess.run(cmd, capture_output=True, timeout=10).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def _drop(self) -> list[str]:
        return ["setpriv", f"--reuid={self.uid}", f"--regid={self.gid}", "--clear-groups",
                "--no-new-privs", "--"]

    def _prefix(self) -> list[str]:
        if self.net_mode == "root":
            return ["unshare", "-n", "--"] + self._drop()
        if self.net_mode == "userns":
            return self._drop() + ["unshare", "-rn", "--"]
        return self._drop()

    def _hide(self, path: Path) -> None:
        """Rend `path` illisible pour l'utilisateur du bac à sable, puis le vérifie."""
        if not path.exists():
            return
        path.chmod(0o700 if path.is_dir() else 0o600)
        check = subprocess.run(self._prefix() + ["test", "-r", str(path)], capture_output=True)
        if check.returncode == 0:
            raise SandboxError(f"chemin protégé encore lisible par {self.user} : {path}")

    def attach(self, workdir: Path) -> None:
        """Donne au bac à sable un dossier de travail (les fichiers du challenge)."""
        workdir = Path(workdir).resolve()
        for protected in self.protected:
            if workdir == protected or protected in workdir.parents:
                raise SandboxError("le dossier de travail est dans un chemin protégé")
        os.chown(workdir, self.uid, self.gid)
        workdir.chmod(0o755)
        self.workdir = workdir

    def describe(self) -> dict:
        return {"user": self.user, "network_isolated": self.network_isolated,
                "network_mode": self.net_mode,
                "timeout": self.timeout, "protected": [str(p) for p in self.protected]}

    # --- Exécution --------------------------------------------------------------

    def run(self, command: str, timeout: int | None = None) -> ShellResult:
        if _DENY.search(command):
            return ShellResult(command, None, "refusé : commande réseau, gestionnaire de "
                               "paquets ou accès à la base de challenges", False)
        limit = max(1, min(timeout or self.timeout, MAX_TIMEOUT))
        env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
               "HOME": str(self.workdir), "LANG": "C.UTF-8", "TERM": "dumb"}
        proc = subprocess.Popen(
            self._prefix() + ["bash", "-c", command], cwd=self.workdir, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True)
        try:
            out, _ = proc.communicate(timeout=limit)
            timed_out = False
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            out, _ = proc.communicate()
            timed_out = True
        text = out[:MAX_CAPTURE].decode("utf-8", errors="replace")
        if timed_out:
            text += f"\n[délai de {limit} s dépassé : processus arrêté]"
        return ShellResult(command, proc.returncode, text, timed_out)
