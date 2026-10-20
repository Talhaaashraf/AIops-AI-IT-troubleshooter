"""Pluggable LLM providers for the AIops technician and troubleshooting agent.

LLM_PROVIDER=ollama (default, free, runs locally) or LLM_PROVIDER=groq.

All providers speak one normalized message format:
  {"role": "system" | "user", "content": str}
  {"role": "assistant", "content": str, "tool_calls": [{"id", "name", "arguments": dict}]}
  {"role": "tool", "tool_call_id": str, "name": str, "content": str}
and `chat()` returns {"content": str, "tool_calls": [{"id", "name", "arguments": dict}]}.
"""

import os

from dotenv import load_dotenv

from .base import LLMDisconnectedError, LLMModelError, LLMTimeoutError, LLMUnavailableError

load_dotenv()

_provider = None


def provider_name():
    return os.getenv("LLM_PROVIDER", "ollama").strip().lower() or "ollama"


def get_provider():
    global _provider
    name = provider_name()
    if _provider is None or _provider.name != name:
        if name == "groq":
            from .groq_provider import GroqProvider
            _provider = GroqProvider()
        elif name == "ollama":
            from .ollama_provider import OllamaProvider
            _provider = OllamaProvider()
        else:
            raise LLMUnavailableError(f"Unknown LLM_PROVIDER '{name}' (use ollama or groq)")
    return _provider


__all__ = ["LLMDisconnectedError", "LLMModelError", "LLMTimeoutError", "LLMUnavailableError", "get_provider", "provider_name"]
