"""Ollama provider: a free, local model as the troubleshooting agent's brain."""

import json
import logging
import os
import threading
import time
import uuid

import httpx

from .base import LLMModelError, LLMUnavailableError, clean_content
from .catalog import selected_model

logger = logging.getLogger(__name__)
STATUS_CACHE_SECONDS = 15


class OllamaProvider:
    name = "ollama"

    def __init__(self):
        self.host = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
        self.base_model = selected_model()
        # The self-improving model (built from learned cases) replaces the base model once it exists.
        self.learned_model = os.getenv("LEARNED_MODEL_NAME", "aiops-brain").strip()
        self.use_learned = os.getenv("LEARNING_USE_MODEL", "true").strip().lower() in ("1", "true", "yes")
        self.num_ctx = int(os.getenv("OLLAMA_NUM_CTX", "8192"))
        self.timeout = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "600"))
        # How long Ollama keeps the model in RAM after a call; lower it on memory-starved laptops.
        self.keep_alive = os.getenv("OLLAMA_KEEP_ALIVE", "10m")
        # A laptop CPU can only run one generation at a time without both crawling.
        self._lock = threading.Semaphore(int(os.getenv("OLLAMA_MAX_PARALLEL", "1")))
        # Thinking models (qwen3, qwen3.5, ...) can spend minutes reasoning on a CPU before
        # answering; off by default, since the agent already gathers evidence step by step.
        self.think = os.getenv("OLLAMA_THINK", "false").strip().lower() in ("1", "true", "yes")
        self._capabilities = {}
        self.last_load_error = None
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
            learned = self.use_learned and installed(self.learned_model) and self._learned_base() in (None, self.base_model)
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

    @staticmethod
    def _learned_base():
        """The base model the self-improved model was built on (None for builds that predate the record)."""
        from ..learning.model_builder import version_info  # lazy: the learning package is optional here
        return version_info().get("base_model")

    def use_model(self, name):
        """Switch the base model at runtime. The previous model is unloaded so its RAM is free for the new one."""
        previous = self.model
        self.base_model = name
        self.last_load_error = None
        self._status = None
        if previous != self.model:
            try:
                httpx.post(f"{self.host}/api/generate", json={"model": previous, "keep_alive": 0}, timeout=30)
            except httpx.HTTPError as error:
                logger.warning("Could not unload %s: %s", previous, error)

    def warm_up(self):
        """Load the model into RAM ahead of the first request (an empty generate only loads it).
        Called at startup and at the start of each diagnosis, so loading overlaps evidence collection."""
        if not self.is_available():
            return False
        try:
            response = httpx.post(f"{self.host}/api/generate", json={"model": self.model, "keep_alive": self.keep_alive, "options": {"num_ctx": self.num_ctx}}, timeout=self.timeout)
            if response.status_code >= 400:
                # Ollama explains load failures (e.g. not enough memory) in the body; keep it for the dashboard.
                self.last_load_error = f"{self.model} could not be loaded: {response.text[:300]}"
                logger.warning("Ollama warm-up failed: %s", self.last_load_error)
                return False
            self.last_load_error = None
            return True
        except httpx.HTTPError as error:
            self.last_load_error = f"{self.model} could not be loaded: {error}"
            logger.warning("Ollama warm-up failed: %s", error)
            return False

    def supports_thinking(self, model):
        """Ollama rejects `think` for models without the capability, so only send it when it applies."""
        if model not in self._capabilities:
            try:
                response = httpx.post(f"{self.host}/api/show", json={"model": model}, timeout=10)
                response.raise_for_status()
                self._capabilities[model] = set(response.json().get("capabilities") or [])
            except (httpx.HTTPError, ValueError):
                return False  # not cached: retried on the next call
        return "thinking" in self._capabilities[model]

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

    def chat(self, messages, tools=None, json_mode=False, temperature=0.2, max_tokens=None, timeout=None, think=None, on_delta=None):
        """One chat call. `think` overrides OLLAMA_THINK for this call (thinking models only); with `on_delta`
        the reply is streamed and on_delta(kind, text) is called with "thinking" and "content" pieces as they arrive."""
        options = {"temperature": temperature, "num_ctx": self.num_ctx}
        if max_tokens:
            # Generation is the slowest part on a CPU; a cap keeps the worst case bounded.
            # Thinking tokens count toward it too, so thinking calls pass a larger cap.
            options["num_predict"] = int(max_tokens)
        model = self.model
        body = {
            "model": model,
            "messages": self._to_ollama(messages),
            "stream": bool(on_delta),
            "options": options,
            "keep_alive": self.keep_alive,
        }
        if tools:
            body["tools"] = tools
        elif json_mode:
            body["format"] = "json"
        thinking = False
        if self.supports_thinking(model):
            thinking = self.think if think is None else bool(think)
            body["think"] = thinking
        deadline = timeout or self.timeout
        with self._lock:
            try:
                if on_delta:
                    status_code, error_text, payload = self._stream(body, deadline, on_delta)
                else:
                    response = httpx.post(f"{self.host}/api/chat", json=body, timeout=deadline)
                    status_code, error_text = response.status_code, response.text[:300]
                    payload = response.json() if status_code < 400 else {}
            except httpx.TimeoutException as error:
                raise LLMUnavailableError(f"Ollama did not answer within {int(deadline)}s (model may be too large for this machine)") from error
            except httpx.HTTPError as error:
                self._status = None
                raise LLMUnavailableError(f"Ollama is not reachable at {self.host}: {error}") from error
        if status_code == 404:
            raise LLMModelError(f"Model {model} is not available in Ollama. Run: ollama pull {model}")
        if status_code >= 400:
            logger.error("Ollama rejected request: %s", error_text)
            raise LLMModelError(f"Ollama rejected the request: {error_text}")
        logger.info(
            "Ollama %s%s: prompt %s tok in %.1fs, output %s tok in %.1fs (load %.1fs)",
            model, " (thinking)" if thinking else "", payload.get("prompt_eval_count"), (payload.get("prompt_eval_duration") or 0) / 1e9,
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
        return {"content": clean_content(message.get("content")), "tool_calls": calls, "thinking": (message.get("thinking") or "").strip(), "model": model, "thought": thinking}

    def _stream(self, body, deadline, on_delta):
        """Stream /api/chat, enforcing an overall deadline (a read timeout alone never trips while tokens flow)."""
        started = time.monotonic()
        message = {"content": "", "thinking": "", "tool_calls": []}
        final = {}
        with httpx.stream("POST", f"{self.host}/api/chat", json=body, timeout=httpx.Timeout(deadline, connect=10)) as response:
            if response.status_code >= 400:
                response.read()
                return response.status_code, response.text[:300], {}
            for line in response.iter_lines():
                if time.monotonic() - started > deadline:
                    if message["thinking"]:
                        # Out of time while reasoning: return what was thought, so the caller can write it up.
                        logger.warning("Ollama stream hit the %ss deadline; returning the partial reasoning", deadline)
                        return 200, "", {"message": message, "done_reason": "deadline"}
                    raise httpx.ReadTimeout(f"no complete answer within {deadline}s")
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                except ValueError:
                    logger.debug("Skipping a malformed stream line: %r", line[:120])
                    continue
                if chunk.get("error"):
                    return 500, str(chunk["error"])[:300], {}
                delta = chunk.get("message") or {}
                for kind in ("thinking", "content"):
                    if delta.get(kind):
                        message[kind] += delta[kind]
                        try:
                            on_delta(kind, delta[kind])
                        except Exception:  # a broken listener must not kill the answer
                            logger.debug("on_delta failed", exc_info=True)
                message["tool_calls"].extend(delta.get("tool_calls") or [])
                if chunk.get("done"):
                    final = chunk
        return 200, "", {**final, "message": message}
