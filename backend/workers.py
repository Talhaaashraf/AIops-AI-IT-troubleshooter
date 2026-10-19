"""Thread pools for blocking work, kept apart so slow AI calls cannot starve the rest of the server.

asyncio.to_thread uses one shared pool of min(32, CPUs + 4) threads: about 6 on a 2-vCPU server. An AI
call holds its thread for minutes (and used to wait inside it for the one-generation-at-a-time lock), so a
few queued diagnoses blocked every other to_thread call, including the live monitor: the dashboard then
stayed on "Waiting for telemetry". AI work now runs on its own pool and waits for its turn as a coroutine
(ai_gate), and the monitor has a pool of its own.
"""

import asyncio
import functools
import os
import weakref
from concurrent.futures import ThreadPoolExecutor


def _int_env(name, default):
    try:
        return max(1, int(os.getenv(name, str(default))))
    except ValueError:
        return default


AI_EXECUTOR = ThreadPoolExecutor(_int_env("AI_WORKER_THREADS", 4), thread_name_prefix="aiops-ai")
MONITOR_EXECUTOR = ThreadPoolExecutor(2, thread_name_prefix="aiops-monitor")
# One gate per event loop: an asyncio.Semaphore belongs to the loop it was first used on (tests run many loops).
_gates = weakref.WeakKeyDictionary()


async def run_ai(function, *args, **kwargs):
    """Run blocking LLM or model-building work on the AI pool."""
    return await asyncio.get_running_loop().run_in_executor(AI_EXECUTOR, functools.partial(function, *args, **kwargs))


async def run_monitor(function, *args, **kwargs):
    """Run the dashboard's quick system snapshot on its own pool, so it never queues behind other work."""
    return await asyncio.get_running_loop().run_in_executor(MONITOR_EXECUTOR, functools.partial(function, *args, **kwargs))


def ai_gate():
    """Admits OLLAMA_MAX_PARALLEL AI generations at a time; the rest wait here without holding a thread."""
    loop = asyncio.get_running_loop()
    gate = _gates.get(loop)
    if gate is None:
        gate = _gates[loop] = asyncio.Semaphore(_int_env("OLLAMA_MAX_PARALLEL", 1))
    return gate
