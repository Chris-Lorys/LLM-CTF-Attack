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
}

# Réglages propres aux offres gratuites des API : quotas par minute (on espace les
# appels) et modèles « qui réfléchissent » dont la réflexion consomme max_tokens.
PRESET_OPTIONS = {
    "gemini": {"min_interval": 7.0, "max_tokens": 8192},   # ~10 requêtes/min gratuites
    "groq": {"min_interval": 2.5},
    "openrouter": {"min_interval": 3.5},
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
        headers = {"Content-Type": "application/json"}
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
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"réponse inattendue : {str(data)[:300]}") from exc


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
        model, url = spec, base_url or PRESETS["ollama"]
    return OpenAICompatModel(model=model, base_url=url, api_key=os.environ.get("CSAW_API_KEY"),
                             **options)
