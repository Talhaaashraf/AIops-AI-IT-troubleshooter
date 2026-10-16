import json

from backend import ai_technician


def _big_report():
    events = [{"time": "2026-10-13T19:42:13", "level": "Error", "source": f"Source{i % 6}", "id": 4096 + i % 6, "message": "Something failed " * 30} for i in range(50)]
    return {
        "system": {"os_name": "Windows", "os_release": "11", "hostname": "laptop"},
        "cpu": {"total_usage_percent": 82.3, "logical_cores": 12, "current_frequency_mhz": 1300, "max_frequency_mhz": 1300, "per_core_usage_percent": [50.0] * 12},
        "memory": {"ram": {"total": "15.64 GB", "available": "1.37 GB", "usage_percent": 91.2}, "swap": {"total": "18.54 GB", "usage_percent": 31.1}},
        "disk": [{"mountpoint": "C:\\", "usage_percent": 75.8, "free": "57.02 GB"}],
        "battery": {"percent": 100, "charging": True},
        "top_processes": {"top_by_cpu": [{"name": "vmmemWSL", "cpu_percent": 549.0}] * 8, "top_by_memory": [{"name": "chrome.exe", "memory_percent": 12.0}] * 8},
        "security": {
            "firewall": {"available": True, "enabled": True, "detail": "3/3 firewall profiles active"},
            "antivirus": {"available": True, "enabled": False, "detail": "Real-time protection off"},
            "listening_ports": {"available": True, "ports": [{"port": p} for p in range(45)]},
        },
        "event_logs": {"available": True, "lookback_hours": 24, "events": events, "critical_count": 1, "error_count": 18, "warning_count": 28},
    }


def test_compact_report_is_small_and_keeps_the_signal():
    alerts = [{"category": "Memory", "severity": "high", "description": f"RAM usage is {90 + i}%"} for i in range(20)]
    raw_size = len(json.dumps({"diagnostics": _big_report(), "recent_alerts": alerts}))
    digest = ai_technician.compact_report(_big_report(), alerts)
    text = json.dumps(digest)

    assert len(text) < raw_size / 4 and len(text) < 4000
    assert "91.2% used" in digest["ram"] and digest["top_cpu"][0] == "vmmemWSL 549.0%"
    assert digest["security"]["antivirus"] == "Real-time protection off" and "listening_ports" not in digest["security"]
    assert len(digest["event_logs"]["most_frequent"]) == 6 and digest["event_logs"]["most_frequent"][0].startswith("Source0 #4096 x9")
    assert digest["recent_alerts"] == ["high Memory x20: RAM usage is 90%"]


def test_list_fields_returned_as_one_string_are_split_into_items():
    raw = json.dumps({"summary": "s", "severity": "Medium", "steps": "1. Close apps.\n2. Free up disk space.\n", "suggested_actions": "Call IT"})
    result = ai_technician._parse_diagnosis(raw)

    assert result["steps"] == ["Close apps.", "Free up disk space."]
    assert result["suggested_actions"] == ["Call IT"] and result["severity"] == "medium"

    objects = ai_technician._parse_diagnosis(json.dumps({"steps": [{"summary": "Restart", "details": "Close apps first"}, "Free disk space"]}))
    assert objects["steps"] == ["Restart: Close apps first", "Free disk space"]


def test_diagnose_sends_digest_with_a_length_cap(monkeypatch):
    calls = []

    class FakeProvider:
        def chat(self, messages, tools=None, json_mode=False, temperature=0.2, max_tokens=None, timeout=None, think=None, on_delta=None):
            calls.append({"messages": messages, "max_tokens": max_tokens})
            return {"content": json.dumps({"summary": "RAM is nearly full", "root_cause": "vmmemWSL", "severity": "high", "steps": ["Close WSL"]})}

    monkeypatch.setattr(ai_technician, "get_provider", lambda: FakeProvider())
    result = ai_technician.diagnose(_big_report(), [])

    assert result["summary"] == "RAM is nearly full"
    assert calls[0]["max_tokens"] == ai_technician.REPORT_MAX_TOKENS
    prompt = json.loads(calls[0]["messages"][1]["content"])
    assert len(calls[0]["messages"][1]["content"]) < 4000
    # The model explains the rule-detected issues instead of judging raw numbers itself.
    assert any("RAM usage is 91.2%" in line for line in prompt["detected_issues"])


def test_reply_cut_off_by_the_token_cap_keeps_its_complete_parts():
    cut = '{"summary": "PC is slow", "issues": [{"title": "RAM", "explanation": "Chrome", "fix_steps": ["Close tabs"]}, {"title": "Di'
    result = ai_technician._parse_diagnosis(cut)
    assert result["summary"] == "PC is slow"
    assert result["issues"][0] == {"title": "RAM", "explanation": "Chrome", "fix_steps": ["Close tabs"]}


def test_empty_event_log_is_answered_without_the_ai(monkeypatch):
    monkeypatch.setattr(ai_technician, "get_provider", lambda: (_ for _ in ()).throw(AssertionError("AI must not be called")))
    result = ai_technician.diagnose_logs({"available": False, "detail": "journalctl not available", "events": []})
    assert "journalctl not available" in result["summary"] and result["severity"] == "low"
