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
}


@dataclass
class OpenAICompatModel:
    """Tout service compatible « chat completions » : Ollama, vLLM, Groq, OpenRouter..."""

    model: str
    base_url: str = PRESETS["ollama"]
    api_key: str | None = None
    temperature: float = 0.2
    max_tokens: int = 1024
    timeout: float = 300.0

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
        request = urllib.request.Request(
            self.base_url.rstrip("/") + "/chat/completions", data=body, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.load(response)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:300]
            raise LLMError(f"HTTP {exc.code} depuis {self.base_url} : {detail}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise LLMError(f"modèle injoignable ({self.base_url}) : {exc}") from exc
        try:
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"réponse inattendue : {str(data)[:300]}") from exc


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
    if preset in PRESETS and model:
        url = base_url or PRESETS[preset]
    else:
        model, url = spec, base_url or PRESETS["ollama"]
    return OpenAICompatModel(model=model, base_url=url, api_key=os.environ.get("CSAW_API_KEY"))
