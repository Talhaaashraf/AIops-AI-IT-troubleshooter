"""Groq cloud provider (optional fallback; needs GROQ_API_KEY)."""

import json
import logging
import os

from .base import LLMModelError, LLMUnavailableError, clean_content

logger = logging.getLogger(__name__)


class GroqProvider:
    name = "groq"

    def __init__(self):
        self.model = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")

    def status(self):
        available = bool(os.getenv("GROQ_API_KEY", "").strip())
        return {"available": available, "provider": self.name, "model": self.model, "message": "Groq ready" if available else "Set GROQ_API_KEY in .env (or switch to LLM_PROVIDER=ollama)"}

    def is_available(self):
        return self.status()["available"]

    def _client(self):
        key = os.getenv("GROQ_API_KEY", "").strip()
        if not key:
            raise LLMUnavailableError("AI technician unavailable: GROQ_API_KEY is not configured")
        try:
            from groq import Groq
            return Groq(api_key=key)
        except Exception as error:
            raise LLMUnavailableError(f"AI technician unavailable: {error}") from error

    @staticmethod
    def _to_openai(messages):
        converted = []
        for message in messages:
            if message["role"] == "assistant" and message.get("tool_calls"):
                converted.append({
                    "role": "assistant",
                    "content": message.get("content") or "",
                    "tool_calls": [{"id": call["id"], "type": "function", "function": {"name": call["name"], "arguments": json.dumps(call.get("arguments") or {})}} for call in message["tool_calls"]],
                })
            elif message["role"] == "tool":
                converted.append({"role": "tool", "tool_call_id": message.get("tool_call_id", ""), "content": message["content"]})
            else:
                converted.append({"role": message["role"], "content": message.get("content") or ""})
        return converted

    def warm_up(self):
        return self.is_available()

    def chat(self, messages, tools=None, json_mode=False, temperature=0.2, max_tokens=None, timeout=None, think=None, on_delta=None):  # noqa: ARG002 - same signature as Ollama
        kwargs = {"model": self.model, "messages": self._to_openai(messages), "temperature": temperature}
        if max_tokens:
            kwargs["max_tokens"] = int(max_tokens)
        if tools:
            kwargs["tools"] = tools
        elif json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        try:
            if timeout:
                kwargs["timeout"] = timeout
            response = self._client().chat.completions.create(**kwargs)
        except LLMUnavailableError:
            raise
        except Exception as error:
            status_code = getattr(error, "status_code", None)
            if type(error).__name__ == "NotFoundError" or (status_code is not None and 400 <= status_code < 500):
                logger.exception("Groq rejected model %s", self.model)
                raise LLMModelError("AI model unavailable, please check GROQ_MODEL in .env") from error
            logger.exception("Groq request failed for model %s", self.model)
            raise LLMUnavailableError("AI technician is temporarily unavailable") from error
        message = response.choices[0].message
        calls = []
        for call in message.tool_calls or []:
            try:
                arguments = json.loads(call.function.arguments or "{}")
            except ValueError:
                arguments = {}
            calls.append({"id": call.id, "name": call.function.name, "arguments": arguments})
        return {"content": clean_content(message.content), "tool_calls": calls}
