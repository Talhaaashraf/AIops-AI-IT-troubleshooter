"""Groq cloud provider (optional fallback; needs GROQ_API_KEY or GROQ_API_KEYS).

Several keys can be listed, comma-separated, in GROQ_API_KEYS (GROQ_API_KEY still works and comes first). When a
key is rate limited (429) or rejected (401), it rests for a while and the call moves on to the next key.
"""

import json
import logging
import os
import threading
import time

from .base import LLMModelError, LLMUnavailableError, clean_content

logger = logging.getLogger(__name__)


RATE_LIMIT_REST_SECONDS = 60
INVALID_KEY_REST_SECONDS = 3600


def groq_keys():
    """Configured keys in order: GROQ_API_KEY first, then GROQ_API_KEYS (comma-separated), without duplicates."""
    keys = []
    for value in [os.getenv("GROQ_API_KEY", "")] + os.getenv("GROQ_API_KEYS", "").split(","):
        value = value.strip()
        if value and value not in keys:
            keys.append(value)
    return keys


class GroqProvider:
    name = "groq"

    def __init__(self):
        self.model = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
        self._resting = {}  # key -> time it may be used again (in memory only, never logged)
        self._lock = threading.Lock()

    def status(self):
        keys = groq_keys()
        now = time.time()
        with self._lock:
            ready = sum(1 for key in keys if self._resting.get(key, 0) <= now)
        available = bool(keys)
        message = (f"Groq ready ({ready} of {len(keys)} key(s) ready)" if available
                   else "Set GROQ_API_KEY or GROQ_API_KEYS in .env (or switch to LLM_PROVIDER=ollama)")
        return {"available": available, "provider": self.name, "model": self.model, "keys": len(keys), "keys_ready": ready, "message": message}

    def is_available(self):
        return self.status()["available"]

    def _client(self, key):
        try:
            from groq import Groq
            return Groq(api_key=key)
        except Exception as error:
            raise LLMUnavailableError(f"AI technician unavailable: {error}") from error

    def _ready_keys(self):
        keys = groq_keys()
        if not keys:
            raise LLMUnavailableError("AI technician unavailable: GROQ_API_KEY or GROQ_API_KEYS is not configured")
        now = time.time()
        with self._lock:
            ready = [key for key in keys if self._resting.get(key, 0) <= now]
        if not ready:
            raise LLMUnavailableError("Every Groq key is resting after a rate limit or rejection; try again shortly")
        return ready

    def _rest(self, key, seconds):
        with self._lock:
            self._resting[key] = time.time() + seconds

    @staticmethod
    def _retry_after(error):
        try:
            return max(1, min(3600, int(error.response.headers.get("retry-after"))))
        except (AttributeError, TypeError, ValueError):
            return RATE_LIMIT_REST_SECONDS

    def _create(self, kwargs):
        """One completion, moving to the next key when a key is rate limited (429) or rejected (401)."""
        last = None
        for key in self._ready_keys():
            try:
                return self._client(key).chat.completions.create(**kwargs)
            except LLMUnavailableError:
                raise
            except Exception as error:
                status_code = getattr(error, "status_code", None)
                if status_code == 429:
                    self._rest(key, self._retry_after(error))
                elif status_code == 401:
                    self._rest(key, INVALID_KEY_REST_SECONDS)
                else:
                    raise
                logger.warning("Groq key %s of %s returned %s; trying the next key", groq_keys().index(key) + 1, len(groq_keys()), status_code)
                last = status_code
        raise LLMUnavailableError("Every Groq key is rate limited; try again shortly" if last == 429
                                  else "Groq rejected every key: check GROQ_API_KEY / GROQ_API_KEYS in .env")

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

    def chat(self, messages, tools=None, json_mode=False, temperature=None, max_tokens=None, timeout=None, think=None, on_delta=None):  # noqa: ARG002 - same signature as Ollama
        kwargs = {"model": self.model, "messages": self._to_openai(messages), "temperature": 0.2 if temperature is None else temperature}
        if max_tokens:
            kwargs["max_tokens"] = int(max_tokens)
        if tools:
            kwargs["tools"] = tools
        elif json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        try:
            if timeout:
                kwargs["timeout"] = timeout
            response = self._create(kwargs)
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
        usage = getattr(response, "usage", None)
        return {"content": clean_content(message.content), "tool_calls": calls, "thinking": "", "model": self.model, "thought": False,
                "usage": {"prompt_tokens": getattr(usage, "prompt_tokens", None), "output_tokens": getattr(usage, "completion_tokens", None)}, "schema": False}
