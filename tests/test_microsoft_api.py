"""Server endpoints for Microsoft product removal: id validation, the job it starts, and the agent-risk guard."""

import asyncio

import pytest
from fastapi import HTTPException

from backend import main, software_store
from backend.agent_brain import session_store
from backend.agent_brain.executor import Target


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    for module in (software_store, session_store):
        monkeypatch.setattr(module, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(main, "resolve_target", lambda device_id: Target("dev1", "Windows", "laptop") if device_id == "dev1" else None)
    monkeypatch.delenv("SENTINEL_IN_DOCKER", raising=False)
    main.software_jobs.clear()


def _run(coro):
    return asyncio.run(coro)


def test_scan_and_remove_start_jobs_with_the_right_tool_and_risk(monkeypatch):
    calls = []

    async def fake_execute(target, tool_id, args, max_risk, session_id=None):
        calls.append((tool_id, args, max_risk))
        return {"ok": True, "summary": f"{tool_id} done", "data": {"products": []} if tool_id == "microsoft_products" else {}}

    monkeypatch.setattr(main, "execute", fake_execute)

    async def finished(job):
        for _ in range(200):
            if main.software_jobs[job["job_id"]]["state"] != "running":
                return job
            await asyncio.sleep(0.01)
        return job

    async def scenario():
        scan = await main.scan_device_microsoft("dev1")
        assert (await main.scan_device_microsoft("dev1"))["job_id"] == scan["job_id"]  # one scan at a time
        await finished(scan)
        remove = await finished(await main.remove_device_microsoft("dev1", {"id": "office|2016", "name": "Microsoft Office Standard 2016"}))
        fix = await finished(await main.fix_device_installer("dev1"))  # a change only starts once the last one is done
        return scan, remove, fix

    scan, remove, fix = _run(scenario())
    by_tool = {tool_id: (args, risk) for tool_id, args, risk in calls}
    assert by_tool["microsoft_products"] == ({}, "read")
    assert by_tool["remove_microsoft"] == ({"id": "office|2016"}, "high")
    assert by_tool["fix_install_blocker"] == ({}, "medium")
    assert main.software_jobs[remove["job_id"]]["action"] == "ms-remove"


def test_remove_needs_a_valid_product_id():
    for bad in ("", "office|../etc", "rm -rf", "office|2016; echo", "weird|x"):
        with pytest.raises(HTTPException) as refused:
            _run(main.remove_device_microsoft("dev1", {"id": bad}))
        assert refused.value.status_code == 400
    # These shapes are accepted (a real agent still re-checks the id against its own listing).
    for good in ("office|M365", "appx|Microsoft.BingNews_1.0.0.0_x64__8wekyb3d8bbwe", "HKLM64|{guid}", "winget|Microsoft.Teams"):
        assert main.MS_ID_PATTERN.match(good)


def test_an_unknown_device_is_404():
    with pytest.raises(HTTPException) as missing:
        _run(main.scan_device_microsoft("ghost"))
    assert missing.value.status_code == 404


def test_the_container_itself_cannot_be_targeted_in_docker(monkeypatch):
    monkeypatch.setenv("SENTINEL_IN_DOCKER", "1")
    monkeypatch.setattr(main, "resolve_target", lambda device_id: Target(main.LOCAL_DEVICE_ID, "Linux", "AIops container"))
    with pytest.raises(HTTPException) as refused:
        _run(main.scan_device_microsoft("local"))
    assert refused.value.status_code == 400
