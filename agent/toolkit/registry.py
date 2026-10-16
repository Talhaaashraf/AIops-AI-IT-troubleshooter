"""Allow-listed tool registry shared by the server and the remote agent.

Every diagnostic or fix the AI can trigger is a registered Tool with a fixed
id, a typed parameter schema, a risk level, and the operating systems it
supports. Nothing outside this registry can be executed, and arguments are
validated against the schema before the tool function is called.
"""

import time
from dataclasses import dataclass, field

from .common import os_name

RISK_LEVELS = ("read", "low", "medium", "high")
ALL_OS = frozenset({"Windows", "Linux", "Darwin"})

_TOOLS = {}


@dataclass(frozen=True)
class Tool:
    id: str
    description: str
    risk: str
    fn: object
    params: dict = field(default_factory=dict)
    required: tuple = ()
    os: frozenset = ALL_OS
    timeout: int = 90
    # False keeps a tool out of the AI's function list (huge outputs, or actions only a person should start).
    ai_visible: bool = True


def tool(tool_id, description, risk="read", params=None, required=(), os=ALL_OS, timeout=90, ai_visible=True):
    if risk not in RISK_LEVELS:
        raise ValueError(f"Unknown risk level {risk}")

    def decorator(fn):
        _TOOLS[tool_id] = Tool(tool_id, description, risk, fn, params or {}, tuple(required), frozenset(os), timeout, ai_visible)
        return fn

    return decorator


def risk_rank(risk):
    return RISK_LEVELS.index(risk) if risk in RISK_LEVELS else len(RISK_LEVELS)


def get_tool(tool_id):
    return _TOOLS.get(tool_id)


def list_tools(target_os=None, max_risk="high", min_risk="read"):
    target_os = target_os or os_name()
    return [
        item for item in _TOOLS.values()
        if target_os in item.os and risk_rank(min_risk) <= risk_rank(item.risk) <= risk_rank(max_risk)
    ]


def describe_tools(target_os=None, max_risk="high", min_risk="read"):
    return [
        {"id": item.id, "description": item.description, "risk": item.risk, "params": item.params, "required": list(item.required), "timeout": item.timeout}
        for item in list_tools(target_os, max_risk, min_risk)
    ]


def tool_schemas(target_os=None, max_risk="read", min_risk="read"):
    """Function-calling schemas in the OpenAI/Ollama `tools` format."""
    return [
        {
            "type": "function",
            "function": {
                "name": item.id,
                "description": item.description,
                "parameters": {"type": "object", "properties": item.params, "required": list(item.required)},
            },
        }
        for item in list_tools(target_os, max_risk, min_risk)
        if item.ai_visible
    ]


def validate_args(item, args):
    """Return cleaned args or raise ValueError. Unknown keys are rejected."""
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise ValueError("Tool arguments must be an object")
    unknown = set(args) - set(item.params)
    if unknown:
        raise ValueError(f"Unknown argument(s): {', '.join(sorted(unknown))}")
    cleaned = {}
    for name, spec in item.params.items():
        if name not in args or args[name] is None or args[name] == "":
            if name in item.required:
                raise ValueError(f"Missing required argument: {name}")
            continue
        value = args[name]
        kind = spec.get("type")
        if kind == "integer":
            if isinstance(value, bool):
                raise ValueError(f"{name} must be an integer")
            try:
                value = int(value)
            except (TypeError, ValueError) as error:
                raise ValueError(f"{name} must be an integer") from error
            if "minimum" in spec and value < spec["minimum"]:
                raise ValueError(f"{name} must be >= {spec['minimum']}")
            if "maximum" in spec and value > spec["maximum"]:
                raise ValueError(f"{name} must be <= {spec['maximum']}")
        elif kind == "boolean":
            if isinstance(value, str) and value.lower() in ("true", "false"):
                value = value.lower() == "true"
            if not isinstance(value, bool):
                raise ValueError(f"{name} must be true or false")
        elif kind == "string":
            if not isinstance(value, (str, int, float)) or isinstance(value, bool):
                raise ValueError(f"{name} must be a string")
            value = str(value).strip()
            if len(value) > spec.get("maxLength", 200):
                raise ValueError(f"{name} is too long")
        if "enum" in spec and value not in spec["enum"]:
            raise ValueError(f"{name} must be one of: {', '.join(map(str, spec['enum']))}")
        cleaned[name] = value
    return cleaned


def run_tool(tool_id, args=None, max_risk="read", target_os=None):
    """Execute one registered tool and always return a result dict (never raises)."""
    started = time.perf_counter()
    item = get_tool(tool_id)
    base = {"tool_id": tool_id, "ok": False, "data": None}
    if item is None:
        return {**base, "summary": f"Unknown or disallowed tool: {tool_id}"}
    target_os = target_os or os_name()
    if target_os not in item.os:
        return {**base, "risk": item.risk, "summary": f"{tool_id} is not supported on {target_os}"}
    if risk_rank(item.risk) > risk_rank(max_risk):
        return {**base, "risk": item.risk, "summary": f"{tool_id} is a {item.risk}-risk action and was not permitted (limit: {max_risk})"}
    try:
        cleaned = validate_args(item, args)
    except ValueError as error:
        return {**base, "risk": item.risk, "summary": f"Invalid arguments: {error}"}
    try:
        result = item.fn(**cleaned) or {}
    except Exception as error:  # a broken tool must never crash the agent loop
        result = {"ok": False, "summary": f"{tool_id} failed: {type(error).__name__}: {error}"}
    return {
        "tool_id": tool_id,
        "risk": item.risk,
        "args": cleaned,
        "ok": bool(result.get("ok", True)),
        "summary": str(result.get("summary", "")),
        "data": result.get("data"),
        "changed": result.get("changed"),
        "rollback_hint": result.get("rollback_hint"),
        "duration_ms": round((time.perf_counter() - started) * 1000),
    }
