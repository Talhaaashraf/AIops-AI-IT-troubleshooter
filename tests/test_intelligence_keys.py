"""Several API keys per threat-intelligence provider: the next key takes over when one is rate limited, out of
budget or invalid, while uploads and their polling stay on the primary key the approval was given for."""
import json

import httpx
import pytest
from fastapi import HTTPException

from backend import intelligence as intel, intelligence_secrets as vault, security_store as store

SHA = "a" * 64
KEY1, KEY2, KEY3 = "1" * 64, "2" * 64, "3" * 64
REPORT = {"data": {"id": SHA, "attributes": {"last_analysis_stats": {"malicious": 0}}}}


def enable(*extra_keys, **policy):
    intel.configure("virustotal", dict(api_key=KEY1, enabled=True, business_authorized=True,
                                       use_basis="Synthetic permission for mocked tests only", upload_authorized=True, **policy))
    for key in extra_keys:
        intel.configure("virustotal", {"add_api_key": key})


@pytest.fixture
def provider(monkeypatch):
    """A mocked VirusTotal: `answers` maps a key to the HTTP status it gets (200 by default)."""
    client, seen, answers = httpx.Client, [], {}

    def handle(req):
        key = req.headers.get("x-apikey")
        seen.append(key)
        code = answers.get(key, 200)
        return httpx.Response(code, json=REPORT if code == 200 else {}, headers={"Retry-After": "600"} if code == 429 else {})

    monkeypatch.setattr(intel.httpx, "Client", lambda **kwargs: client(transport=httpx.MockTransport(handle), **kwargs))
    return seen, answers


def test_keys_are_added_listed_without_key_material_and_removed():
    enable(KEY2)
    generation = intel.policy("virustotal")["generation"]
    data = intel.status("virustotal")
    assert [item["slot"] for item in data["keys"]] == [1, 2] and data["keys"][0]["primary"] and not data["keys"][1]["primary"]
    text = json.dumps(data)
    assert KEY1 not in text and KEY2 not in text and "1111" not in text
    # Adding or removing an extra key is not a new account: approvals and cached work stay valid.
    intel.configure("virustotal", {"add_api_key": KEY3})
    intel.configure("virustotal", {"remove_key": 2})
    assert [item["key"] for item in vault.get_all("virustotal")] == [KEY1, KEY3]
    assert intel.policy("virustotal")["generation"] == generation


def test_a_new_primary_is_a_new_account():
    enable(KEY2)
    before = intel.policy("virustotal")
    intel.configure("virustotal", {"remove_key": 1})  # KEY2 becomes the primary
    after = intel.policy("virustotal")
    assert vault.get("virustotal") == KEY2
    assert after["key_generation"] != before["key_generation"] and after["generation"] != before["generation"]
    # Entering the same primary again is not a change.
    intel.configure("virustotal", {"api_key": KEY2})
    assert intel.policy("virustotal")["generation"] == after["generation"]


@pytest.mark.parametrize("payload, message", [
    ({"add_api_key": KEY1}, "already saved"),
    ({"add_api_key": "short"}, "Invalid API key format"),
    ({"remove_key": 3}, "number of a saved key"),
    ({"api_keys": [KEY2, KEY2]}, "listed twice"),
    ({"api_keys": ["4" * 64] * 2 + ["5" * 64, "6" * 64, "7" * 64, "8" * 64]}, "at most"),
])
def test_bad_key_edits_are_refused(payload, message):
    enable()
    with pytest.raises(HTTPException, match=message):
        intel.configure("virustotal", payload)
    assert [item["key"] for item in vault.get_all("virustotal")] == [KEY1]


def test_at_most_five_keys():
    enable(KEY2, KEY3, "4" * 64, "5" * 64)
    with pytest.raises(HTTPException, match="At most 5"):
        intel.configure("virustotal", {"add_api_key": "6" * 64})


def test_a_rate_limited_key_hands_over_to_the_next(provider):
    seen, answers = provider
    enable(KEY2)
    answers[KEY1] = 429
    assert intel.request("virustotal", "GET", "/files/" + SHA) == REPORT
    assert seen == [KEY1, KEY2]
    keys = intel.status("virustotal")["keys"]
    assert keys[0]["wait_seconds"] > 500 and keys[1]["wait_seconds"] == 0
    seen.clear()
    intel.request("virustotal", "GET", "/files/" + SHA)
    assert seen == [KEY2]  # the backing-off key is skipped without a request


def test_an_invalid_key_hands_over_but_a_lone_key_reports_its_own_error(provider):
    seen, answers = provider
    enable(KEY2)
    answers[KEY1] = 401
    assert intel.request("virustotal", "GET", "/files/" + SHA) == REPORT and seen == [KEY1, KEY2]
    answers[KEY2] = 401
    with pytest.raises(HTTPException) as error:
        intel.request("virustotal", "GET", "/users/me")
    assert error.value.status_code == 401


def test_every_key_rate_limited_reports_429(provider):
    seen, answers = provider
    enable(KEY2)
    answers.update({KEY1: 429, KEY2: 429})
    with pytest.raises(HTTPException) as error:
        intel.request("virustotal", "GET", "/files/" + SHA)
    assert error.value.status_code == 429 and seen == [KEY1, KEY2]


def test_each_key_has_its_own_budget(provider):
    seen, _answers = provider
    enable(KEY2, per_minute=1)
    intel.request("virustotal", "GET", "/files/" + SHA)
    intel.request("virustotal", "GET", "/files/" + SHA)
    assert seen == [KEY1, KEY2]  # the second request used the second key's budget
    with pytest.raises(HTTPException) as error:
        intel.request("virustotal", "GET", "/files/" + SHA)
    assert error.value.status_code == 429 and "every saved key" in error.value.detail and len(seen) == 2
    assert intel.status("virustotal")["usage"]["minute"] == 2


def test_uploads_and_polls_never_switch_accounts(provider):
    seen, answers = provider
    enable(KEY2)
    answers[KEY1] = 429
    generation = intel.policy("virustotal")["generation"]
    with pytest.raises(HTTPException) as error:
        intel.request("virustotal", "POST", "/files", expect={"generation": generation, "upload": True})
    assert error.value.status_code == 429 and seen == [KEY1]  # not retried with the second account's key
    seen.clear()
    with pytest.raises(HTTPException) as error:
        intel.request("virustotal", "GET", "/analyses/x", expect={"key_generation": intel.policy("virustotal")["key_generation"]})
    assert error.value.status_code == 429 and seen == []  # the primary is backing off: no request at all


def test_a_key_saved_before_lists_existed_still_works(provider):
    seen, _answers = provider
    enable()
    rules = intel.policy("virustotal")
    vault._memory["virustotal"] = vault.cipher().encrypt(KEY1.encode()).decode()  # the old format: one plain key
    assert vault.get_all("virustotal", rules["key_generation"]) == [{"id": rules["key_generation"], "key": KEY1}]
    intel.request("virustotal", "GET", "/files/" + SHA)
    assert seen == [KEY1]
    intel.configure("virustotal", {"add_api_key": KEY2})
    assert intel.policy("virustotal")["generation"] == rules["generation"]  # the old key kept its identity
    assert [item["key"] for item in vault.get_all("virustotal")] == [KEY1, KEY2]


def test_keys_persist_encrypted_with_the_master_key(monkeypatch):
    from cryptography.fernet import Fernet

    monkeypatch.setenv("SENTINEL_INTELLIGENCE_MASTER_KEY", Fernet.generate_key().decode())
    enable(KEY2)
    with store.connect() as db:
        ciphertext = db.execute("SELECT ciphertext FROM intelligence_credentials").fetchone()[0]
    assert KEY1 not in ciphertext and KEY2 not in ciphertext
    monkeypatch.setattr(vault, "_cipher", None)  # a restart
    assert [item["key"] for item in vault.get_all("virustotal")] == [KEY1, KEY2]
