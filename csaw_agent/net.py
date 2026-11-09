"""Accès réseau borné au seul service du challenge (challenges à serveur).

Les 12 challenges « à serveur » de la base CSAW 2026 exposent un service (HTTP
ou TCP brut) décrit par `box` + `internal_port` + `proto`. L'agent doit pouvoir
le joindre, mais rien d'autre : le règlement interdit de télécharger des
solutions, et une injection de prompt pourrait pousser le modèle à sortir.

D'où une cible unique et figée. Les outils `http` et `connect` ne prennent
jamais d'hôte en argument : ils parlent au `ServerTarget` construit à
l'ingestion (ou redirigé par le lanceur de conteneur vers localhost:PORT). Le
shell en bac à sable, lui, reste sans réseau : seules ces deux portes typées
sortent, et elles ne mènent qu'au challenge.

Aucune dépendance externe : http.client et socket suffisent.
"""

from __future__ import annotations

import http.client
import socket
import ssl
from dataclasses import dataclass, field
from http.cookies import SimpleCookie

MAX_BODY = 1 << 20  # 1 Mo lu au plus par réponse
DEFAULT_TIMEOUT = 15


class NetworkError(RuntimeError):
    """Le service du challenge est injoignable ou a coupé la connexion."""


@dataclass
class ServerTarget:
    """L'unique service que l'agent a le droit de joindre."""

    proto: str          # "http", "https" ou "nc" (TCP brut)
    host: str
    port: int

    def with_endpoint(self, host: str, port: int) -> "ServerTarget":
        """Même service, mais joint à une autre adresse (conteneur local mappé)."""
        return ServerTarget(self.proto, host, port)

    def describe(self) -> dict:
        return {"proto": self.proto, "host": self.host, "port": self.port}

    def human(self) -> str:
        if self.proto in ("http", "https"):
            return f"{self.proto}://{self.host}:{self.port}/"
        return f"{self.host}:{self.port} (TCP)"


def _unescape(text: str) -> bytes:
    r"""Interprète \n \r \t \0 \xNN et \\ ; tout le reste est pris littéralement.

    Les services pwn/crypto attendent souvent des octets précis, que le modèle
    ne peut pas taper directement dans du JSON. On n'utilise pas
    `unicode_escape`, qui déforme les octets >= 0x80.
    """
    out = bytearray()
    i = 0
    simple = {"n": 10, "r": 13, "t": 9, "0": 0, "\\": 92, '"': 34, "'": 39}
    while i < len(text):
        ch = text[i]
        if ch != "\\" or i + 1 >= len(text):
            out.extend(ch.encode("utf-8"))
            i += 1
            continue
        nxt = text[i + 1]
        if nxt == "x" and i + 3 < len(text) + 1 and len(text[i + 2:i + 4]) == 2:
            try:
                out.append(int(text[i + 2:i + 4], 16))
                i += 4
                continue
            except ValueError:
                pass
        if nxt in simple:
            out.append(simple[nxt])
            i += 2
            continue
        out.append(92)  # antislash littéral suivi du caractère tel quel
        i += 1
    return bytes(out)


@dataclass
class NetworkClient:
    """Client réseau à cible unique, avec session (cookies HTTP, socket TCP persistante)."""

    target: ServerTarget
    timeout: float = DEFAULT_TIMEOUT
    _cookies: SimpleCookie = field(default_factory=SimpleCookie)
    _sock: socket.socket | None = None

    # --- HTTP ---------------------------------------------------------------

    def request(self, method: str, path: str, body: str = "",
                headers: dict | None = None, follow: bool = True) -> str:
        method = (method or "GET").upper()
        if not path.startswith("/"):
            path = "/" + path
        sent_headers = {k.lower(): v for k, v in (headers or {}).items()}
        hops = 0
        while True:
            status, resp_headers, data = self._one_request(method, path, body, sent_headers)
            self._store_cookies(resp_headers)
            if follow and status in (301, 302, 303, 307, 308) and "location" in resp_headers \
                    and hops < 5:
                location = resp_headers["location"]
                if location.startswith("http://") or location.startswith("https://"):
                    location = "/" + location.split("/", 3)[-1] if location.count("/") >= 3 else "/"
                path, method, body = location, ("GET" if status in (301, 302, 303) else method), ""
                hops += 1
                continue
            return self._format(status, resp_headers, data)

    def _connection(self) -> http.client.HTTPConnection:
        if self.target.proto == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return http.client.HTTPSConnection(self.target.host, self.target.port,
                                               timeout=self.timeout, context=ctx)
        return http.client.HTTPConnection(self.target.host, self.target.port, timeout=self.timeout)

    def _one_request(self, method, path, body, headers):
        conn = self._connection()
        all_headers = dict(headers)
        all_headers.setdefault("host", f"{self.target.host}:{self.target.port}")
        all_headers.setdefault("user-agent", "csaw-agent")
        all_headers.setdefault("accept", "*/*")
        all_headers.setdefault("connection", "close")
        cookie = self._cookie_header()
        if cookie and "cookie" not in all_headers:
            all_headers["cookie"] = cookie
        payload = body.encode("utf-8") if body else None
        if payload is not None and "content-type" not in all_headers:
            all_headers["content-type"] = "application/x-www-form-urlencoded"
        try:
            conn.request(method, path, body=payload, headers=all_headers)
            resp = conn.getresponse()
            raw = resp.read(MAX_BODY + 1)
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, resp_headers, raw
        except (OSError, http.client.HTTPException) as exc:
            raise NetworkError(f"échec de la requête HTTP vers {self.target.human()} : {exc}") from exc
        finally:
            conn.close()

    def _cookie_header(self) -> str:
        return "; ".join(f"{k}={m.value}" for k, m in self._cookies.items())

    def _store_cookies(self, headers: dict) -> None:
        raw = headers.get("set-cookie")
        if raw:
            self._cookies.load(raw)

    def _format(self, status: int, headers: dict, data: bytes) -> str:
        shown = [f"HTTP {status}"]
        for key in ("content-type", "location", "set-cookie", "www-authenticate"):
            if key in headers:
                shown.append(f"{key}: {headers[key]}")
        if len(data) > MAX_BODY:
            data = data[:MAX_BODY]
            truncated = "\n[... corps tronqué]"
        else:
            truncated = ""
        text = data.decode("utf-8", errors="replace")
        return "\n".join(shown) + "\n\n" + text + truncated

    # --- TCP brut (proto « nc ») --------------------------------------------

    def send(self, data: str, recv: bool = True, newline: bool = True,
             raw: bool = False) -> str:
        """Envoie `data` au service TCP et lit la réponse disponible.

        `raw=False` interprète \\n, \\xNN, etc. ; `newline` ajoute un saut de
        ligne final (la plupart des services lisent ligne par ligne).
        """
        payload = _unescape(data) if not raw else data.encode("utf-8", "surrogateescape")
        if newline and not payload.endswith(b"\n"):
            payload += b"\n"
        sock = self._tcp()
        try:
            if payload:
                sock.sendall(payload)
            return self._drain(sock) if recv else "(envoyé)"
        except (OSError, socket.timeout) as exc:
            self.close()
            raise NetworkError(f"échec TCP vers {self.target.human()} : {exc}") from exc

    def _tcp(self) -> socket.socket:
        if self._sock is not None:
            return self._sock
        try:
            self._sock = socket.create_connection((self.target.host, self.target.port),
                                                  timeout=self.timeout)
        except OSError as exc:
            raise NetworkError(f"connexion TCP impossible vers {self.target.human()} : {exc}") from exc
        return self._sock

    def _drain(self, sock: socket.socket) -> str:
        """Lit ce qui arrive jusqu'à un court silence (service interactif)."""
        sock.settimeout(self.timeout)
        chunks: list[bytes] = []
        total = 0
        try:
            first = sock.recv(65536)
            if not first:
                self.close()
                return "(connexion fermée par le service)"
            chunks.append(first)
            total += len(first)
            sock.settimeout(0.5)
            while total < MAX_BODY:
                more = sock.recv(65536)
                if not more:
                    break
                chunks.append(more)
                total += len(more)
        except socket.timeout:
            pass
        except OSError as exc:
            raise NetworkError(f"échec de lecture TCP : {exc}") from exc
        return b"".join(chunks).decode("utf-8", errors="replace") or "(aucune donnée reçue)"

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
