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
from concurrent.futures import ThreadPoolExecutor


def int_env(name, default):
    try:
        return max(1, int(os.getenv(name, str(default))))
    except ValueError:
        return default


AI_EXECUTOR = ThreadPoolExecutor(int_env("AI_WORKER_THREADS", 4), thread_name_prefix="aiops-ai")
MONITOR_EXECUTOR = ThreadPoolExecutor(2, thread_name_prefix="aiops-monitor")
# One semaphore per event loop: an asyncio.Semaphore belongs to the loop it was first used on (tests run many
# loops). Plain dicts, pruned of closed loops: not every loop type (uvloop's, in the image) is sure to allow
# weak references.
_gates = {}
_slots = {}


async def run_ai(function, *args, **kwargs):
    """Run blocking LLM or model-building work on the AI pool."""
    return await asyncio.get_running_loop().run_in_executor(AI_EXECUTOR, functools.partial(function, *args, **kwargs))


async def run_monitor(function, *args, **kwargs):
    """Run the dashboard's quick system snapshot on its own pool, so it never queues behind other work."""
    return await asyncio.get_running_loop().run_in_executor(MONITOR_EXECUTOR, functools.partial(function, *args, **kwargs))


def _loop_semaphore(store, env, default):
    loop = asyncio.get_running_loop()
    semaphore = store.get(loop)
    if semaphore is None:
        for closed in [item for item in store if item.is_closed()]:
            del store[closed]
        semaphore = store[loop] = asyncio.Semaphore(int_env(env, default))
    return semaphore


def ai_gate():
    """Admits OLLAMA_MAX_PARALLEL AI generations at a time; the rest wait here without holding a thread."""
    return _loop_semaphore(_gates, "OLLAMA_MAX_PARALLEL", 1)


def diagnosis_limit():
    return int_env("MAX_CONCURRENT_DIAGNOSES", 2)


def diagnosis_slots():
    """Admits MAX_CONCURRENT_DIAGNOSES diagnoses at a time, whoever started them (What's the issue?, onboarding,
    the Performance tab); the rest wait in line as "queued". On a CPU the AI writes one report at a time
    anyway, so more parallel diagnoses would only make each of them slower."""
    return _loop_semaphore(_slots, "MAX_CONCURRENT_DIAGNOSES", 2)
