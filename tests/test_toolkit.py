from agent.toolkit import describe_tools, get_tool, run_tool, tool_schemas
from agent.toolkit.registry import validate_args


def test_unknown_tool_is_refused():
    result = run_tool("rm_rf_everything", {}, max_risk="high")
    assert result["ok"] is False
    assert "Unknown or disallowed" in result["summary"]


def test_fix_tools_need_explicit_risk_permission():
    result = run_tool("flush_dns", {}, max_risk="read")
    assert result["ok"] is False
    assert "not permitted" in result["summary"]


def test_arguments_are_validated():
    item = get_tool("kill_process")
    for bad in ({"pid": "abc", "expected_name": "x"}, {"pid": 1, "expected_name": "x"}, {"pid": 100}, {"pid": 100, "expected_name": "x", "extra": 1}):
        try:
            validate_args(item, bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted bad args {bad}")
    assert validate_args(item, {"pid": "1234", "expected_name": "chrome.exe"}) == {"pid": 1234, "expected_name": "chrome.exe"}


def test_restart_service_rejects_names_outside_allow_list():
    result = run_tool("restart_service", {"name": "evil; shutdown"}, max_risk="high")
    assert result["ok"] is False
    assert "allow-list" in result["summary"]


def test_ping_rejects_option_injection():
    result = run_tool("ping_host", {"host": "-t 127.0.0.1"})
    assert result["ok"] is False


def test_llm_only_sees_read_only_tools_by_default():
    schemas = tool_schemas("Windows")
    assert schemas and all(get_tool(schema["function"]["name"]).risk == "read" for schema in schemas)


def test_os_specific_tools_are_filtered():
    linux_ids = {tool["id"] for tool in describe_tools("Linux")}
    assert "repair_system_files" not in linux_ids
    assert "flush_dns" in linux_ids


def test_system_overview_runs():
    result = run_tool("system_overview")
    assert result["ok"] is True
    assert "CPU" in result["summary"]


def test_test_tcp_port_detects_open_and_closed(tmp_path):
    import socket
    # An open port: a real listening socket on localhost.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        opened = run_tool("test_tcp_port", {"host": "127.0.0.1", "port": port})
        assert opened["ok"] is True and opened["data"]["open"] is True
    finally:
        listener.close()
    # The same port is closed once the listener is gone.
    closed = run_tool("test_tcp_port", {"host": "127.0.0.1", "port": port})
    assert closed["ok"] is True and closed["data"]["open"] is False


def test_test_tcp_port_validates_input():
    assert run_tool("test_tcp_port", {"host": "-t 127.0.0.1", "port": 80})["ok"] is False  # host injection
    # Port out of range is rejected by the schema.
    assert run_tool("test_tcp_port", {"host": "127.0.0.1", "port": 70000})["ok"] is False


def test_driver_inventory_is_read_only_and_runs():
    item = get_tool("driver_inventory")
    assert item is not None and item.risk == "read"
    result = run_tool("driver_inventory")
    assert "ok" in result and isinstance(result.get("summary", ""), str)
