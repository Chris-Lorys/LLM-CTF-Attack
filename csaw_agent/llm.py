"""Interface modèle unique.

Le reste de l'agent ne connaît que `ChatModel.complete(messages) -> str`.
Changer de modèle (Ollama local, modèle ouvert servi sur un GPU gratuit,
offre gratuite d'une API) revient à changer d'URL et de nom de modèle :
tous ces services parlent le protocole « chat completions » d'OpenAI.

Aucune dépendance externe : la requête HTTP passe par la bibliothèque standard.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol

# Message au format chat : {"role": "system" | "user" | "assistant", "content": "..."}
Message = dict


class LLMError(RuntimeError):
    """Le modèle est injoignable ou a renvoyé une réponse inexploitable."""


class ChatModel(Protocol):
    name: str

    def complete(self, messages: list[Message]) -> str: ...


# Préréglages : seule l'URL change. La clé d'API éventuelle est lue dans
# CSAW_API_KEY, jamais écrite dans le code ni dans la trace.
PRESETS = {
    "ollama": "http://localhost:11434/v1",
    "vllm": "http://localhost:8000/v1",
    "groq": "https://api.groq.com/openai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
    "cerebras": "https://api.cerebras.ai/v1",
    "deepseek": "https://api.deepseek.com/v1",
}

# Réglages propres aux offres gratuites des API : quotas par minute (on espace les
# appels) et modèles « qui réfléchissent » dont la réflexion consomme max_tokens.
PRESET_OPTIONS = {
    "gemini": {"min_interval": 7.0, "max_tokens": 8192},   # ~10 requêtes/min gratuites
    "groq": {"min_interval": 2.5},
    "openrouter": {"min_interval": 3.5, "max_tokens": 8192},  # deepseek-r1, kimi : raisonnement
    "cerebras": {"min_interval": 2.5, "max_tokens": 16384},  # qwen « réfléchit » : place pour le raisonnement + la réponse
    "deepseek": {"min_interval": 2.0, "max_tokens": 8192},
}

RETRY_STATUS = {429, 500, 502, 503, 504}


@dataclass
class OpenAICompatModel:
    """Tout service compatible « chat completions » : Ollama, vLLM, Groq, OpenRouter..."""

    model: str
    base_url: str = PRESETS["ollama"]
    api_key: str | None = None
    temperature: float = 0.2
    max_tokens: int = 2048  # 1024 coupait les scripts écrits par le modèle (essai 4)
    timeout: float = 300.0
    min_interval: float = 0.0   # secondes minimales entre deux appels (quota gratuit)
    retries: int = 6            # nouvelles tentatives sur 429 / 5xx, délai croissant
    _last_call: float = 0.0

    @property
    def name(self) -> str:
        return f"{self.model}@{self.base_url}"

    def complete(self, messages: list[Message]) -> str:
        body = json.dumps({
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }).encode()
        # On s'identifie honnêtement : le défaut d'urllib (« Python-urllib/… »)
        # est parfois refusé par les pare-feux des fournisseurs. On ne se fait pas
        # passer pour un navigateur ; on nomme simplement le client.
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "csaw-agent/1.0 (+https://github.com/Chris-Lorys/LLM-CTF-Attack)",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        url = self.base_url.rstrip("/") + "/chat/completions"
        for attempt in range(self.retries + 1):
            wait = self.min_interval - (time.monotonic() - self._last_call)
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.monotonic()
            request = urllib.request.Request(url, data=body, headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    data = json.load(response)
                break
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode(errors="replace")[:300]
                if exc.code in RETRY_STATUS and attempt < self.retries:
                    time.sleep(_retry_delay(exc.headers.get("Retry-After"), attempt))
                    continue
                raise LLMError(f"HTTP {exc.code} depuis {self.base_url} : {detail}") from exc
            except (urllib.error.URLError, TimeoutError) as exc:
                raise LLMError(f"modèle injoignable ({self.base_url}) : {exc}") from exc
        try:
            choice = data["choices"][0]
            message = choice["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"réponse inattendue : {str(data)[:300]}") from exc
        content = message.get("content")
        if content:
            return content
        # Un modèle « qui réfléchit » met sa réflexion dans un champ séparé
        # (`reasoning`) et peut laisser `content` vide s'il atteint max_tokens en
        # plein raisonnement (finish_reason="length"). On le dit clairement : la
        # solution est d'augmenter max_tokens, pas de renvoyer une erreur opaque.
        if choice.get("finish_reason") == "length":
            raise LLMError("réponse coupée par la limite de jetons "
                           "(max_tokens trop bas pour ce modèle qui réfléchit)")
        return content or ""


def _retry_delay(retry_after: str | None, attempt: int) -> float:
    """Délai avant une nouvelle tentative : celui demandé par le serveur, sinon croissant."""
    try:
        return min(float(retry_after), 120.0)
    except (TypeError, ValueError):
        return min(5.0 * 2 ** attempt, 120.0)


class ScriptedModel:
    """Modèle factice qui rejoue des réponses écrites d'avance (tests, démo hors ligne)."""

    name = "scripted"

    def __init__(self, replies: list[str]):
        self._replies = list(replies)
        self.received: list[list[Message]] = []

    def complete(self, messages: list[Message]) -> str:
        self.received.append([dict(m) for m in messages])
        if not self._replies:
            raise LLMError("plus de réponses scriptées")
        return self._replies.pop(0)


def _api_key(preset: str) -> str | None:
    """Clé du fournisseur, pour pouvoir router entre plusieurs API à la fois.

    Cherche, dans l'ordre : CSAW_API_KEY_<PRESET>, <PRESET>_API_KEY (p. ex.
    GEMINI_API_KEY, OPENROUTER_API_KEY, les noms que donnent les fournisseurs),
    puis CSAW_API_KEY (repli pour un seul fournisseur). Jamais écrite dans la trace.
    """
    up = preset.upper()
    for name in (f"CSAW_API_KEY_{up}", f"{up}_API_KEY", "CSAW_API_KEY"):
        value = os.environ.get(name)
        if value and value.strip():
            # Une clé collée dans un secret garde souvent un saut de ligne ou des
            # espaces : collés dans l'en-tête Authorization, ils la rendent invalide
            # (400 « Please pass a valid API key »).
            return value.strip()
    return None


def make_model(spec: str, base_url: str | None = None) -> ChatModel:
    """Construit un modèle à partir de `preset:modele`, p. ex. `ollama:qwen2.5:3b`.

    Sans préréglage reconnu, `spec` est le nom du modèle et `base_url` est requis
    (ou vaut l'URL d'Ollama par défaut).
    """
    preset, _, model = spec.partition(":")
    options = {}
    if preset in PRESETS and model:
        url = base_url or PRESETS[preset]
        options = PRESET_OPTIONS.get(preset, {})
    else:
        preset, model, url = "", spec, base_url or PRESETS["ollama"]
    return OpenAICompatModel(model=model, base_url=url, api_key=_api_key(preset), **options)


@dataclass
class ModelRouter:
    """Choisit un modèle selon la catégorie du challenge (routage multi-modèles).

    Idée (document de stratégie) : un modèle fort en raisonnement pour la crypto
    et le reverse, un modèle fort en code pour le pwn, un modèle rapide par
    défaut. Chaque modèle est joignable en une ligne car tous parlent le même
    protocole ; router ne coûte donc rien et tient dans les quotas gratuits.
    """

    routes: dict[str, ChatModel]
    default: ChatModel

    def for_category(self, category: str) -> ChatModel:
        return self.routes.get(category, self.default)

    @property
    def name(self) -> str:
        parts = [f"{cat}={m.name}" for cat, m in self.routes.items()]
        return "routeur(" + ", ".join(parts + [f"default={self.default.name}"]) + ")"

    def describe(self) -> dict:
        return {"default": self.default.name,
                "routes": {cat: m.name for cat, m in self.routes.items()}}


def make_router(spec: str, base_url: str | None = None) -> ModelRouter:
    """Construit un routeur depuis `cat=preset:modele,...,default=preset:modele`.

    Exemple : `crypto=openrouter:deepseek/deepseek-r1:free,
    pwn=openrouter:moonshotai/kimi-k2.6:free,default=gemini:gemini-3.8-flash`.
    La clé `default` est obligatoire.
    """
    routes: dict[str, ChatModel] = {}
    default = None
    for pair in spec.split(","):
        pair = pair.strip()
        if not pair:
            continue
        key, sep, model_spec = pair.partition("=")
        if not sep or not model_spec.strip():
            raise ValueError(f"routage invalide : {pair!r} (attendu catégorie=preset:modele)")
        key = key.strip()
        if key == "default":
            default = make_model(model_spec.strip(), base_url)
        else:
            routes[key] = make_model(model_spec.strip(), base_url)
    if default is None:
        raise ValueError("le routage doit comporter une entrée default=...")
    return ModelRouter(routes, default)
