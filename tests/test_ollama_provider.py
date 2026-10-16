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
    provider.last_load_error = "qwen3:8b could not be loaded: out of memory"
    monkeypatch.setattr(provider, "status", lambda: {"model": provider.base_model})

    provider.use_model("qwen3:4b")

    assert sent == [{"model": "qwen3:8b", "keep_alive": 0}]
    assert provider.base_model == "qwen3:4b" and provider.last_load_error is None


def test_model_mojibake_is_repaired():
    from backend.llm.base import clean_content

    assert clean_content("<think>x</think>CPU at 85.1\u00c2\u00b0C \u00e2\u20ac\u201c it\u00e2\u20ac\u2122s hot") == "CPU at 85.1\u00b0C - it's hot"
