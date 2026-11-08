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
2. Pas de réseau (`unshare -n`, ou `unshare -rn` lancé par l'utilisateur dédié, ou, si
   le conteneur interdit les espaces de noms comme sur Kaggle, filtre seccomp qui
   refuse la création de sockets réseau) : rien ne peut être téléchargé, y compris les
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

import ctypes
import os
import platform
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


# --- Filtre seccomp : interdit les sockets réseau sans aucun privilège -----------
#
# Programme BPF chargé par le processus enfant juste avant exec ; il s'hérite et
# ne peut plus être retiré. Il refuse (EACCES) socket() pour tout domaine autre
# qu'AF_UNIX, io_uring (qui sait aussi ouvrir des sockets) et l'ABI x32.

_AUDIT_ARCH_X86_64 = 0xC000003E
_RET_ALLOW, _RET_KILL, _RET_EACCES = 0x7FFF0000, 0x80000000, 0x00050000 | 13
_LD, _JEQ, _JGE, _RET = 0x20, 0x15, 0x35, 0x06
_SYS_SOCKET, _SYS_IO_URING_SETUP, _X32 = 41, 425, 0x40000000
_AF_UNIX = 1

_FILTER = [
    (_LD, 0, 0, 4),                         # 0 : architecture
    (_JEQ, 1, 0, _AUDIT_ARCH_X86_64),       # 1 : x86-64 → 3
    (_RET, 0, 0, _RET_KILL),                # 2 : autre architecture : tué
    (_LD, 0, 0, 0),                         # 3 : numéro d'appel système
    (_JGE, 6, 0, _X32),                     # 4 : ABI x32 → refus
    (_JEQ, 5, 0, _SYS_IO_URING_SETUP),      # 5 : io_uring → refus
    (_JEQ, 1, 0, _SYS_SOCKET),              # 6 : socket → 8
    (_RET, 0, 0, _RET_ALLOW),               # 7 : le reste est permis
    (_LD, 0, 0, 16),                        # 8 : premier argument (domaine)
    (_JEQ, 0, 1, _AF_UNIX),                 # 9 : AF_UNIX → 10, sinon → 11
    (_RET, 0, 0, _RET_ALLOW),               # 10
    (_RET, 0, 0, _RET_EACCES),              # 11 : socket réseau refusée
]


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8),
                ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(_SockFilter))]


def _install_seccomp() -> None:  # appelé dans l'enfant, entre fork et exec
    libc = ctypes.CDLL(None, use_errno=True)
    prog_array = (_SockFilter * len(_FILTER))(*[_SockFilter(*ins) for ins in _FILTER])
    prog = _SockFprog(len(_FILTER), prog_array)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS")
    if libc.prctl(22, 2, ctypes.byref(prog), 0, 0) != 0:  # PR_SET_SECCOMP, FILTER
        raise OSError(ctypes.get_errno(), "PR_SET_SECCOMP")


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
            elif self._seccomp_works():
                self.net_mode = "seccomp"
        self.network_isolated = self.net_mode is not None
        if isolate_network and not self.network_isolated:
            raise SandboxError("isolation réseau impossible (unshare -n, unshare -rn et "
                               "seccomp refusés) ; relancer avec --shell-avec-reseau, "
                               "en connaissance de cause")
        for path in self.protected:
            self._hide(path)

    # --- Préparation ----------------------------------------------------------

    @staticmethod
    def _probe(cmd: list[str]) -> bool:
        try:
            return subprocess.run(cmd, capture_output=True, timeout=10).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    @staticmethod
    def _seccomp_works() -> bool:
        """Vrai si le filtre se charge et bloque bien une socket réseau."""
        if platform.machine() != "x86_64" or shutil.which("python3") is None:
            return False
        code = ("import socket\ntry:\n socket.socket()\nexcept PermissionError:\n"
                " print('bloque')\nelse:\n print('ouvert')")
        try:
            out = subprocess.run(["python3", "-I", "-c", code], capture_output=True,
                                 timeout=10, preexec_fn=_install_seccomp)
        except (OSError, subprocess.SubprocessError):
            return False
        return out.stdout.strip() == b"bloque"

    def _preexec(self):
        return _install_seccomp if self.net_mode == "seccomp" else None

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
        check = subprocess.run(self._prefix() + ["test", "-r", str(path)], capture_output=True,
                               preexec_fn=self._preexec())
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
            start_new_session=True, preexec_fn=self._preexec())
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
