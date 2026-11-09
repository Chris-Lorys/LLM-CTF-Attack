"""Outils réseau bornés au service du challenge (challenges à serveur)."""

from __future__ import annotations

import http.server
import socket
import threading

import pytest

from csaw_agent.challenge import server_target
from csaw_agent.net import NetworkClient, NetworkError, ServerTarget, _unescape
from csaw_agent.tools import Toolbox, ToolError


def test_server_target_depuis_meta():
    t = server_target({"box": "polly.chal.csaw.io", "internal_port": 5000, "proto": "nc"})
    assert (t.proto, t.host, t.port) == ("nc", "polly.chal.csaw.io", 5000)
    t = server_target({"box": "web.chal", "internal_port": "80", "proto": "http"})
    assert t.proto == "http" and t.port == 80
    assert server_target({"category": "crypto"}) is None  # pas de serveur
    assert server_target({"box": "x", "internal_port": "abc"}) is None  # port non entier


def test_unescape_octets_precis():
    assert _unescape(r"A\x00\xffB") == b"A\x00\xffB"
    assert _unescape(r"ligne\n") == b"ligne\n"
    assert _unescape(r"100\%") == b"100\\%"  # échappement inconnu : antislash gardé


# --- HTTP sur un serveur local -------------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", "/cible")
            self.end_headers()
            return
        if self.path == "/cible":
            self.send_response(200)
            self.send_header("Set-Cookie", "sid=abc123")
            self.end_headers()
            self.wfile.write(b"page cible")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"cookie=" + self.headers.get("Cookie", "").encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"recu:" + body)

    def log_message(self, *args):
        pass


@pytest.fixture
def http_target():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield ServerTarget("http", "127.0.0.1", server.server_port)
    server.shutdown()


def test_http_suit_la_redirection_et_garde_le_cookie(http_target):
    net = NetworkClient(http_target, timeout=5)
    out = net.request("GET", "/redir")
    assert "HTTP 200" in out and "page cible" in out
    # Le cookie posé pendant la redirection est renvoyé à l'appel suivant.
    out2 = net.request("GET", "/echo")
    assert "sid=abc123" in out2


def test_http_post_transmet_le_corps(http_target):
    net = NetworkClient(http_target, timeout=5)
    out = net.request("POST", "/", body="payload=42")
    assert "recu:payload=42" in out


def test_outil_http_expose_seulement_pour_un_serveur_http(tmp_path, http_target):
    net = NetworkClient(http_target, timeout=5)
    box = Toolbox(tmp_path, net=net)
    assert "http" in box.tools and "connect" not in box.tools
    assert "HTTP 200" in box.call("http", {"path": "/", "method": "GET"})


# --- TCP brut ------------------------------------------------------------------

def _tcp_echo_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve():
        conn, _ = srv.accept()
        conn.sendall(b"salut\n")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(b"echo:" + data)
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv


def test_connect_dialogue_tcp(tmp_path):
    srv = _tcp_echo_server()
    net = NetworkClient(ServerTarget("nc", "127.0.0.1", srv.getsockname()[1]), timeout=3)
    box = Toolbox(tmp_path, net=net)
    assert "connect" in box.tools and "http" not in box.tools
    greeting = box.call("connect", {"data": "", "recv": True})  # juste lire la bannière
    assert "salut" in greeting
    reply = box.call("connect", {"data": "ping"})
    assert "echo:ping" in reply
    srv.close()


def test_connect_signale_une_erreur_reseau(tmp_path):
    # Port fermé : la connexion échoue et devient une ToolError lisible par le modèle.
    net = NetworkClient(ServerTarget("nc", "127.0.0.1", 1), timeout=1)
    box = Toolbox(tmp_path, net=net)
    with pytest.raises(ToolError):
        box.call("connect", {"data": "x"})
