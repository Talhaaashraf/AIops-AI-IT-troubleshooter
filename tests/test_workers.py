import asyncio
import threading
import time

import psutil

from backend import collectors, workers
from backend.agent_brain import planner


def test_queued_ai_calls_wait_without_threads_and_the_monitor_still_answers(monkeypatch):
    """Diagnoses waiting for the model must not hold threads: the dashboard's snapshot has to answer meanwhile."""
    release = threading.Event()
    inside, peak = [], []

    class BlockingProvider:
        name = "fake"

        def chat(self, messages, **kwargs):
            inside.append(1)
            peak.append(len(inside))
            release.wait(5)
            inside.pop()
            return {"content": "{}", "tool_calls": [], "thinking": "", "model": "fake", "thought": False}

    monkeypatch.setattr(planner, "get_provider", lambda: BlockingProvider())

    async def scenario():
        calls = [asyncio.create_task(planner._chat([{"role": "user", "content": "hi"}])) for _ in range(3)]
        await asyncio.sleep(0.2)
        started = time.monotonic()
        assert await workers.run_monitor(lambda: "ok") == "ok"
        waited = time.monotonic() - started
        release.set()
        await asyncio.gather(*calls)
        return waited

    assert asyncio.run(scenario()) < 1
    assert max(peak) == 1  # one generation at a time; the others waited as coroutines


def test_the_server_report_survives_a_missing_cpu_frequency_and_a_broken_section(monkeypatch):
    def unsupported():
        raise NotImplementedError("no cpufreq on this VM")

    def broken():
        raise OSError("interfaces unreadable")

    monkeypatch.setattr(psutil, "cpu_freq", unsupported)
    monkeypatch.setattr(collectors, "get_network_info", broken)
    report = collectors.collect_report()
    assert report["cpu"]["current_frequency_mhz"] is None
    assert report["network"] == {}
    assert report["memory"]["ram"]["usage_percent"] >= 0
