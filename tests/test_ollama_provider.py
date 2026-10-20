import json

import pytest

from backend import settings_store
from backend.llm import catalog, ollama_provider


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(settings_store, "DB_PATH", tmp_path / "test.db")
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = ""

    def json(self):
        return self._payload

    def raise_for_status(self):
        pass


def _provider(monkeypatch, capabilities):
    sent = []

    def fake_post(url, json=None, timeout=None):
        if url.endswith("/api/show"):
            return FakeResponse({"capabilities": capabilities})
        sent.append(json)
        return FakeResponse({"message": {"content": "<think>hmm</think>{\"ok\": true}"}})

    monkeypatch.setattr(ollama_provider.httpx, "post", fake_post)
    provider = ollama_provider.OllamaProvider()
    provider._status = {"model": provider.base_model}
    provider._status_at = float("inf")
    return provider, sent


def test_thinking_model_gets_think_false_by_default(monkeypatch):
    monkeypatch.delenv("OLLAMA_THINK", raising=False)
    provider, sent = _provider(monkeypatch, ["completion", "tools", "thinking"])

    result = provider.chat([{"role": "user", "content": "hi"}], json_mode=True)

    assert sent[0]["think"] is False
    assert result["content"] == '{"ok": true}'


def test_non_thinking_model_never_gets_think(monkeypatch):
    provider, sent = _provider(monkeypatch, ["completion", "tools"])

    provider.chat([{"role": "user", "content": "hi"}])

    assert "think" not in sent[0]


def test_saved_model_choice_wins_over_env(monkeypatch):
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:3b")
    assert catalog.selected_model() == "qwen2.5:3b"
    catalog.save_selected_model("qwen3:4b")
    assert catalog.selected_model() == "qwen3:4b"
    assert ollama_provider.OllamaProvider().base_model == "qwen3:4b"


def test_switching_model_unloads_the_previous_one(monkeypatch):
    provider, sent = _provider(monkeypatch, ["completion", "tools"])
    provider.last_load_error = "qwen3:4b could not be loaded: out of memory"
    monkeypatch.setattr(provider, "status", lambda: {"model": provider.base_model})

    provider.use_model("qwen3:8b")

    assert sent == [{"model": "qwen3:4b", "keep_alive": 0}]
    assert provider.base_model == "qwen3:8b" and provider.last_load_error is None


def test_model_mojibake_is_repaired():
    from backend.llm.base import clean_content

    assert clean_content("<think>x</think>CPU at 85.1\u00c2\u00b0C \u00e2\u20ac\u201c it\u00e2\u20ac\u2122s hot") == "CPU at 85.1\u00b0C - it's hot"


def test_sampling_follows_qwens_advice_unless_a_temperature_is_given(monkeypatch):
    monkeypatch.delenv("OLLAMA_SAMPLING", raising=False)
    provider, sent = _provider(monkeypatch, ["completion", "thinking"])
    provider.chat([{"role": "user", "content": "hi"}], think=True)
    provider.chat([{"role": "user", "content": "hi"}], think=False)
    provider.chat([{"role": "user", "content": "hi"}], think=False, temperature=0.1)
    assert [(body["options"]["temperature"], body["options"].get("top_p")) for body in sent] == [(0.6, 0.95), (0.7, 0.8), (0.1, 0.8)]
    assert all(body["options"]["top_k"] == 20 for body in sent)


def test_a_json_schema_is_sent_and_plain_json_is_used_where_ollama_refuses_it(monkeypatch):
    schema = {"type": "object", "properties": {"cause": {"enum": ["F1", "none"]}}, "required": ["cause"]}
    sent = []

    def fake_post(url, json=None, timeout=None):
        if url.endswith("/api/show"):
            return FakeResponse({"capabilities": ["completion"]})
        sent.append(dict(json))
        if isinstance(json.get("format"), dict):
            response = FakeResponse({}, status_code=400)
            response.text = '{"error":"invalid JSON schema in format"}'
            return response
        return FakeResponse({"message": {"content": '{"cause": "F1"}'}})

    monkeypatch.setattr(ollama_provider.httpx, "post", fake_post)
    provider = ollama_provider.OllamaProvider()
    provider._status, provider._status_at = {"model": provider.base_model}, float("inf")

    first = provider.chat([{"role": "user", "content": "hi"}], json_mode=schema)
    second = provider.chat([{"role": "user", "content": "hi"}], json_mode=schema)

    assert [body["format"] for body in sent] == [schema, "json", "json"]  # refused once, then remembered
    assert first["content"] == second["content"] == '{"cause": "F1"}' and first["schema"] is False


def test_thinking_stops_at_its_budget_and_the_reasoning_so_far_is_returned(monkeypatch):
    lines = [json.dumps({"message": {"thinking": "x" * 40}}) for _ in range(10)] + [json.dumps({"message": {"content": "{}"}}), json.dumps({"done": True})]

    class FakeStream:
        status_code = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def iter_lines(self):
            return iter(lines)

    monkeypatch.setattr(ollama_provider.httpx, "stream", lambda *args, **kwargs: FakeStream())
    provider = ollama_provider.OllamaProvider()
    status, _error, payload = provider._stream({"model": "x"}, 600, lambda kind, text: None, max_thinking_chars=100)
    assert status == 200 and payload["done_reason"] == "thinking_budget" and len(payload["message"]["thinking"]) == 120 and payload["message"]["content"] == ""


def test_timeouts_and_dropped_connections_are_told_apart(monkeypatch):
    from backend.llm import LLMDisconnectedError, LLMTimeoutError

    provider, _sent = _provider(monkeypatch, ["completion"])
    for error, expected in ((ollama_provider.httpx.ReadTimeout("slow"), LLMTimeoutError), (ollama_provider.httpx.RemoteProtocolError("Server disconnected"), LLMDisconnectedError)):
        def raising(url, json=None, timeout=None, error=error):
            if url.endswith("/api/show"):
                return FakeResponse({"capabilities": []})
            raise error

        monkeypatch.setattr(ollama_provider.httpx, "post", raising)
        with pytest.raises(expected):
            provider.chat([{"role": "user", "content": "hi"}])
