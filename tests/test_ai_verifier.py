"""Gemini second opinion: off by default, masked, advice only; plus the local-vs-VirusTotal/Hybrid Analysis cross-check.
All HTTP is mocked; no real key or provider is used."""
import asyncio
import json
import time

import httpx
import pytest
from fastapi import HTTPException

from backend import ai_verifier, chat_agent, intelligence as intel, intelligence_jobs as jobs, security_samples as samples
from backend import security_store as store
from backend.agent_brain import planner, session_store
from backend.agent_brain.executor import Target

K1, K2 = "g" * 39 + "1", "g" * 39 + "2"
SHA = "a" * 64
VERDICT = {"verdict": "disagree", "confidence": 0.8, "reason": "The evidence shows DNS works; the cause is the proxy.", "concerns": ["proxy not checked"]}


def enable(**extra):
    return intel.configure("gemini", {"api_key": K1, "enabled": True, "business_authorized": True,
                                      "use_basis": "Synthetic permission for mocked tests only", **extra})


def gemini_reply(payload=VERDICT, status=200):
    return {"status": status, "json": {"candidates": [{"content": {"parts": [{"text": json.dumps(payload)}]}}]}}


@pytest.fixture
def transport(monkeypatch):
    client, calls, replies = httpx.Client, [], []

    def handle(req):
        calls.append(req)
        reply = replies.pop(0) if len(replies) > 1 else replies[0]
        return httpx.Response(reply["status"], json=reply.get("json"), headers=reply.get("headers", {}))

    monkeypatch.setattr(intel.httpx, "Client", lambda **kwargs: client(transport=httpx.MockTransport(handle), **kwargs))
    return calls, replies


def test_it_is_off_until_enabled_and_then_sends_nothing(transport):
    calls, replies = transport
    replies.append(gemini_reply())
    assert ai_verifier.verify("chat", "q", {}, {"a": 1}) is None
    intel.configure("gemini", {"api_key": K1})  # a key alone is not permission
    assert ai_verifier.verify("chat", "q", {}, {"a": 1}) is None and calls == []


def test_settings_validate_the_model_and_refuse_file_submission():
    status = enable()
    assert status["enabled"] and status["policy"]["model"] == intel.DEFAULT_GEMINI_MODEL and K1 not in json.dumps(status)
    assert intel.configure("gemini", {"model": "gemini-3-flash"})["policy"]["model"] == "gemini-3-flash"
    for bad in ("gpt-4o", "gemini-x/../../keys", "../models"):
        with pytest.raises(HTTPException) as error:
            intel.configure("gemini", {"model": bad})
        assert error.value.status_code == 400
    with pytest.raises(HTTPException):
        intel.configure("gemini", {"upload_authorized": True})


def test_gemini_is_never_a_file_reputation_provider():
    enable()
    for call in (lambda: intel.get_file("gemini", SHA), lambda: jobs.enqueue("gemini", SHA), lambda: samples.stage("gemini", b"x")):
        with pytest.raises(HTTPException) as error:
            call()
        assert error.value.status_code == 404


def test_a_verdict_is_returned_and_names_are_masked(transport):
    calls, replies = transport
    replies.append(gemini_reply())
    enable(model="gemini-3-flash")
    evidence = {"host": "FINANCE-PC-07", "ip": "192.168.1.44", "mac": "AA:BB:CC:DD:EE:FF", "mail": "ali@corp.example",
                "path": "C:\\Users\\ali.khan\\Downloads\\x.exe", "linux": "/home/ali/x"}
    result = ai_verifier.verify("diagnosis", "internet down on FINANCE-PC-07", evidence, {"root_cause": "DNS"}, ("FINANCE-PC-07",))
    assert result["state"] == "done" and result["verdict"] == "disagree" and result["concerns"] == ["proxy not checked"]
    assert result["model"] == "gemini-3-flash" and "never changes anything" in result["note"]
    sent = calls[0]
    assert str(sent.url) == "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash:generateContent"
    assert sent.headers["x-goog-api-key"] == K1 and K1 not in str(sent.url)
    body = sent.content.decode()
    for secret in ("FINANCE-PC-07", "192.168.1.44", "AA:BB:CC:DD:EE:FF", "ali@corp.example", "ali.khan", "/home/ali"):
        assert secret not in body
    assert "<device>" in body and "<ip>" in body and "responseSchema" in body


def test_a_bad_answer_or_provider_error_never_breaks_the_local_answer(transport):
    calls, replies = transport
    enable()
    replies.append(gemini_reply({"verdict": "maybe", "reason": "?"}))
    assert ai_verifier.verify("chat", "q", {}, {})["state"] == "unavailable"
    replies[:] = [{"status": 500, "json": {}}]
    assert ai_verifier.verify("chat", "q", {}, {})["state"] == "unavailable"
    replies[:] = [{"status": 404, "json": {}}]
    assert "model" in ai_verifier.verify("chat", "q", {}, {})["reason"]


def test_a_rate_limited_key_hands_over_to_the_next(transport):
    calls, replies = transport
    enable()
    intel.configure("gemini", {"add_api_key": K2})
    replies[:] = [{"status": 429, "json": {}, "headers": {"Retry-After": "30"}}, gemini_reply()]
    assert ai_verifier.verify("chat", "q", {}, {})["verdict"] == "disagree"
    assert [req.headers["x-goog-api-key"] for req in calls] == [K1, K2]


def test_connection_test_reports_the_model(transport):
    calls, replies = transport
    replies.append(gemini_reply({"verdict": "agree", "confidence": 1, "reason": "ok"}))
    enable()
    result = intel.test_connection("gemini")
    assert result["state"] == "completed" and intel.DEFAULT_GEMINI_MODEL in result["result"]["detail"]


def test_local_verdict_cross_check_with_virustotal_and_hybrid_analysis():
    flagged, clean, unknown = {"classification": "malicious"}, {"classification": "no_detections_reported"}, {"classification": "unknown"}
    assert ai_verifier.agreement("malicious", [flagged, unknown])["state"] == "match"
    assert ai_verifier.agreement("clean", [flagged])["state"] == "mismatch"
    assert ai_verifier.agreement("suspicious", [clean])["state"] == "mismatch"
    assert ai_verifier.agreement("clean", [clean])["state"] == "match"
    assert ai_verifier.agreement("clean", [unknown])["state"] == "no_evidence"  # unknown is never proof of safety
    assert ai_verifier.agreement("unknown", [flagged])["state"] == "no_evidence"


def test_hash_explanation_flags_a_mismatch(monkeypatch):
    from backend import ai_technician, workers
    store.state_set("report:virustotal:" + SHA, {"expires": time.time() + 100, "report": {"classification": "malicious", "stats": {"malicious": 9}}})
    monkeypatch.setattr(ai_technician, "is_ai_available", lambda: True)
    monkeypatch.setattr(ai_technician, "_schema_completion", lambda *a, **k: json.dumps({"verdict": "clean", "summary": "Looks fine", "evidence_refs": ["virustotal"], "next_steps": []}))

    async def run_now(func, *args):
        return func(*args)
    monkeypatch.setattr(workers, "run_ai", run_now)
    result = asyncio.run(intel.explain_hash(SHA))
    assert result["local_verdict"] == "clean" and result["agreement"]["state"] == "mismatch"
    assert result["second_opinion"] is None  # Gemini is off in this test


def test_chat_answer_carries_the_second_opinion_but_the_fix_card_is_unchanged(monkeypatch, tmp_path):
    monkeypatch.setattr(session_store, "DB_PATH", tmp_path / "t.db")
    monkeypatch.setattr(chat_agent, "turns", {})
    seen = []

    async def brain(messages, tools=None, **kwargs):
        if tools:
            return {"content": "done", "tool_calls": []}
        return {"content": json.dumps({"plain_explanation": "Restart the spooler", "fix": {"tool_id": "restart_service", "args": {"name": "Spooler"}}})}

    def verify(kind, question, evidence, answer, names=(), specialist=None):
        seen.append((kind, names, specialist))
        return {"state": "done", "verdict": "disagree", "provider": "gemini", "model": "m", "reason": "r", "confidence": 0.5, "concerns": []}

    monkeypatch.setattr(chat_agent, "_chat", brain)
    monkeypatch.setattr(ai_verifier, "enabled", lambda: True)
    monkeypatch.setattr(ai_verifier, "verify", verify)
    target = Target("dev1", "Windows", "FINANCE-PC", "offline")
    turn = chat_agent.create_turn("printer not printing", target, None, {"source": "agent"}, [], False)
    asyncio.run(chat_agent.run_turn(turn))
    view = chat_agent.public(turn)
    assert view["second_opinion"]["verdict"] == "disagree" and seen == [("chat", ("FINANCE-PC", "dev1"), "hardware")]
    assert view["state"] == "done"


def test_diagnosis_second_opinion_is_added_after_the_report(monkeypatch):
    published, saved = [], []
    monkeypatch.setattr(ai_verifier, "enabled", lambda: True)
    monkeypatch.setattr(ai_verifier, "verify", lambda *a, **k: {"state": "done", "verdict": "agree", "provider": "gemini", "model": "m", "reason": "fits", "confidence": 0.9, "concerns": []})
    monkeypatch.setattr(planner.session_store, "update_session", lambda session_id, **fields: saved.append(fields))
    monkeypatch.setattr(planner.events, "publish", lambda session_id, event: published.append(event))
    report = {"ai": {"model": "aiops-brain"}, "root_cause": "Disk full", "proposed_fixes": [{"tool_id": "clear_temp_files", "title": "Clear temp files"}]}
    asyncio.run(planner._second_opinion("s1", Target("dev1", "Windows", "pc", "online"), "slow pc", report, [], [], None))
    assert report["second_opinion"]["verdict"] == "agree" and saved and published[-1]["type"] == "report"

    rules_only = {"root_cause": "Disk full"}  # a rule-based (instant) diagnosis has no AI answer to check
    asyncio.run(planner._second_opinion("s2", Target("dev1", "Windows", "pc", "online"), "slow pc", rules_only, [], [], None))
    assert "second_opinion" not in rules_only


def test_agreement_score_per_specialist_shows_the_weakest_area(transport):
    calls, replies = transport
    enable()
    assert intel.policy("gemini")["per_minute"] == 5 and intel.policy("gemini")["per_day"] == 20  # the free tier's reported caps
    intel.configure("gemini", {"per_minute": 100})
    plan = [("network", "agree")] * 3 + [("network", "partly")] + [("hardware", "disagree")] * 2 + [("hardware", "agree")]
    for specialist, verdict in plan:
        replies[:] = [gemini_reply({**VERDICT, "verdict": verdict})]
        ai_verifier.verify("diagnosis", "q", {}, {}, specialist=specialist)
    replies[:] = [{"status": 500, "json": {}}]
    ai_verifier.verify("chat", "q", {}, {}, specialist="os")
    stats = ai_verifier.agreement_stats()
    rows = {row["id"]: row for row in stats["by_specialist"]}
    assert rows["network"]["agreement_rate"] == 0.88 and rows["hardware"]["agreement_rate"] == 0.33
    assert rows["os"]["judged"] == 0 and rows["os"]["unavailable"] == 1 and rows["os"]["agreement_rate"] is None
    assert stats["weakest"] == "hardware" and stats["overall"]["judged"] == 7 and stats["enabled"]
    with store.connect() as db:  # labels only: never the question, evidence or answers
        assert db.execute("SELECT COUNT(*) FROM second_opinions").fetchone()[0] == 8
        assert {len(row) for row in db.execute("SELECT * FROM second_opinions")} == {6}


def test_learning_stats_include_the_agreement_score(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    from backend import main
    from backend.learning import store as learning_store
    monkeypatch.setattr(learning_store, "DB_PATH", tmp_path / "learn.db")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "check-pass-123")
    client = TestClient(main.app)
    client.post("/login", data={"password": "check-pass-123"}, follow_redirects=False)
    data = client.get("/api/learning/stats").json()["second_opinion"]
    assert data["overall"]["judged"] == 0 and data["weakest"] is None and data["enabled"] is False
