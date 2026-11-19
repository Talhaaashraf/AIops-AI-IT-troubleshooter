"""Several Groq keys: a rate-limited or rejected key rests and the next one answers."""
import types

import pytest

from backend.llm import LLMUnavailableError
from backend.llm.groq_provider import GroqProvider, groq_keys


class Failure(Exception):
    def __init__(self, status_code, retry_after=None):
        super().__init__(f"HTTP {status_code}")
        self.status_code = status_code
        self.response = types.SimpleNamespace(headers={"retry-after": retry_after} if retry_after else {})


def answer(text="ok"):
    message = types.SimpleNamespace(content=text, tool_calls=None)
    return types.SimpleNamespace(choices=[types.SimpleNamespace(message=message)], usage=None)


@pytest.fixture
def groq(monkeypatch):
    """A fake Groq API: `results` maps a key to an exception to raise (otherwise it answers)."""
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("GROQ_API_KEYS", raising=False)
    provider, used, results = GroqProvider(), [], {}

    def client(key):
        def create(**kwargs):
            used.append(key)
            if key in results:
                raise results[key]
            return answer(f"from {key}")
        return types.SimpleNamespace(chat=types.SimpleNamespace(completions=types.SimpleNamespace(create=create)))

    monkeypatch.setattr(provider, "_client", client)
    return provider, used, results


def test_keys_come_from_both_settings_without_duplicates(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk_one")
    monkeypatch.setenv("GROQ_API_KEYS", "gsk_two, gsk_one ,,gsk_three")
    assert groq_keys() == ["gsk_one", "gsk_two", "gsk_three"]


def test_a_rate_limited_key_rests_and_the_next_answers(groq, monkeypatch):
    provider, used, results = groq
    monkeypatch.setenv("GROQ_API_KEYS", "gsk_a,gsk_b")
    results["gsk_a"] = Failure(429, "30")
    assert provider.chat([{"role": "user", "content": "hi"}])["content"] == "from gsk_b"
    assert used == ["gsk_a", "gsk_b"]
    used.clear()
    provider.chat([{"role": "user", "content": "hi"}])
    assert used == ["gsk_b"]  # the resting key is not tried again yet
    status = provider.status()
    assert status["keys"] == 2 and status["keys_ready"] == 1 and "gsk_" not in status["message"]


def test_an_invalid_key_is_skipped(groq, monkeypatch):
    provider, used, results = groq
    monkeypatch.setenv("GROQ_API_KEYS", "gsk_bad,gsk_good")
    results["gsk_bad"] = Failure(401)
    assert provider.chat([{"role": "user", "content": "hi"}])["content"] == "from gsk_good"


def test_every_key_limited_says_so(groq, monkeypatch):
    provider, used, results = groq
    monkeypatch.setenv("GROQ_API_KEYS", "gsk_a,gsk_b")
    results.update(gsk_a=Failure(429), gsk_b=Failure(429))
    with pytest.raises(LLMUnavailableError, match="rate limited"):
        provider.chat([{"role": "user", "content": "hi"}])
    with pytest.raises(LLMUnavailableError, match="resting"):
        provider.chat([{"role": "user", "content": "hi"}])
    assert used == ["gsk_a", "gsk_b"]


def test_no_key_is_reported_clearly(groq):
    provider, _used, _results = groq
    assert provider.status()["available"] is False
    with pytest.raises(LLMUnavailableError, match="GROQ_API_KEYS"):
        provider.chat([{"role": "user", "content": "hi"}])
