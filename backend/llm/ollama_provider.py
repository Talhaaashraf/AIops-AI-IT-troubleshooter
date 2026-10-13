"""Ollama provider: a free, local model as the troubleshooting agent's brain."""

import json
import logging
import os
import threading
import time
import uuid

import httpx

from .base import LLMModelError, LLMUnavailableError, clean_content

logger = logging.getLogger(__name__)
STATUS_CACHE_SECONDS = 15


class OllamaProvider:
    name = "ollama"

    def __init__(self):
        self.host = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
        self.base_model = os.getenv("OLLAMA_MODEL", "qwen2.5:3b").strip()
        # The self-improving model (built from learned cases) replaces the base model once it exists.
        self.learned_model = os.getenv("LEARNED_MODEL_NAME", "sentinel-tech").strip()
        self.use_learned = os.getenv("LEARNING_USE_MODEL", "true").strip().lower() in ("1", "true", "yes")
        self.num_ctx = int(os.getenv("OLLAMA_NUM_CTX", "8192"))
        self.timeout = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "600"))
        # How long Ollama keeps the model in RAM after a call; lower it on memory-starved laptops.
        self.keep_alive = os.getenv("OLLAMA_KEEP_ALIVE", "10m")
        # A laptop CPU can only run one generation at a time without both crawling.
        self._lock = threading.Semaphore(int(os.getenv("OLLAMA_MAX_PARALLEL", "1")))
        self._status = None
        self._status_at = 0

    # -- status -------------------------------------------------------------

    def status(self):
        now = time.time()
        if self._status and now - self._status_at < STATUS_CACHE_SECONDS:
            return self._status
        try:
            response = httpx.get(f"{self.host}/api/tags", timeout=3)
            response.raise_for_status()
            names = {item.get("name", "") for item in response.json().get("models", [])}
            installed = lambda model: model in names or f"{model}:latest" in names
            learned = self.use_learned and installed(self.learned_model)
            model = self.learned_model if learned else self.base_model
            pulled = installed(model)
            message = ("Ollama ready" + (" (self-improved model)" if learned else "")) if pulled else f"Ollama is running but model {self.base_model} is not pulled. Run: ollama pull {self.base_model}"
            self._status = {"available": pulled, "provider": self.name, "model": model, "base_model": self.base_model, "learned_model_active": learned, "host": self.host, "message": message, "installed_models": sorted(names)}
        except (httpx.HTTPError, ValueError):
            self._status = {"available": False, "provider": self.name, "model": self.base_model, "base_model": self.base_model, "learned_model_active": False, "host": self.host, "message": f"Ollama is not reachable at {self.host}. Install it from https://ollama.com and run: ollama pull {self.base_model}"}
        self._status_at = now
        return self._status

    def is_available(self):
        return self.status()["available"]

    @property
    def model(self):
        return self.status().get("model") or self.base_model

    def refresh(self):
        self._status = None

    def warm_up(self):
        """Load the model into RAM ahead of the first request (an empty generate only loads it).
        Called at startup and at the start of each diagnosis, so loading overlaps evidence collection."""
        if not self.is_available():
            return False
        try:
            httpx.post(f"{self.host}/api/generate", json={"model": self.model, "keep_alive": self.keep_alive, "options": {"num_ctx": self.num_ctx}}, timeout=self.timeout).raise_for_status()
            return True
        except httpx.HTTPError as error:
            logger.warning("Ollama warm-up failed: %s", error)
            return False

    # -- chat ---------------------------------------------------------------

    @staticmethod
    def _to_ollama(messages):
        converted = []
        for message in messages:
            role = message["role"]
            if role == "assistant" and message.get("tool_calls"):
                converted.append({
                    "role": "assistant",
                    "content": message.get("content") or "",
                    "tool_calls": [{"function": {"name": call["name"], "arguments": call.get("arguments") or {}}} for call in message["tool_calls"]],
                })
            elif role == "tool":
                converted.append({"role": "tool", "content": message["content"], "tool_name": message.get("name", "")})
            else:
                converted.append({"role": role, "content": message.get("content") or ""})
        return converted

    def chat(self, messages, tools=None, json_mode=False, temperature=0.2, max_tokens=None):
        options = {"temperature": temperature, "num_ctx": self.num_ctx}
        if max_tokens:
            # Generation is the slowest part on a CPU; a cap keeps the worst case bounded.
            options["num_predict"] = int(max_tokens)
        body = {
            "model": self.model,
            "messages": self._to_ollama(messages),
            "stream": False,
            "options": options,
            "keep_alive": self.keep_alive,
        }
        if tools:
            body["tools"] = tools
        elif json_mode:
            body["format"] = "json"
        with self._lock:
            try:
                response = httpx.post(f"{self.host}/api/chat", json=body, timeout=self.timeout)
            except httpx.TimeoutException as error:
                raise LLMUnavailableError(f"Ollama did not answer within {int(self.timeout)}s (model may be too large for this machine)") from error
            except httpx.HTTPError as error:
                self._status = None
                raise LLMUnavailableError(f"Ollama is not reachable at {self.host}: {error}") from error
        if response.status_code == 404:
            raise LLMModelError(f"Model {self.model} is not available in Ollama. Run: ollama pull {self.model}")
        if response.status_code >= 400:
            detail = response.text[:300]
            logger.error("Ollama rejected request: %s", detail)
            raise LLMModelError(f"Ollama rejected the request: {detail}")
        payload = response.json()
        logger.info(
            "Ollama %s: prompt %s tok in %.1fs, output %s tok in %.1fs (load %.1fs)",
            self.model, payload.get("prompt_eval_count"), (payload.get("prompt_eval_duration") or 0) / 1e9,
            payload.get("eval_count"), (payload.get("eval_duration") or 0) / 1e9, (payload.get("load_duration") or 0) / 1e9,
        )
        message = payload.get("message", {})
        calls = []
        for call in message.get("tool_calls") or []:
            function = call.get("function", {})
            arguments = function.get("arguments") or {}
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except ValueError:
                    arguments = {}
            calls.append({"id": call.get("id") or uuid.uuid4().hex[:12], "name": function.get("name", ""), "arguments": arguments})
        return {"content": clean_content(message.get("content")), "tool_calls": calls}
