"""In-process wake-ups for the agent task channel.

Without these, both sides of the channel poll SQLite once a second: the agent's
long-poll waiting for work and the planner waiting for a result. A signal wakes
the waiter immediately instead; the database stays the source of truth, and the
waits keep a short timeout so a missed signal only costs a few seconds.

All functions must be called from the event loop thread.
"""

import asyncio
import contextlib

_waiters = {}


def device_key(device_id):
    return f"device:{device_id}"


def task_key(task_id):
    return f"task:{task_id}"


@contextlib.contextmanager
def listen(key):
    """Register before checking the database, so a signal sent in between is not lost."""
    event = asyncio.Event()
    _waiters.setdefault(key, set()).add(event)
    try:
        yield event
    finally:
        events = _waiters.get(key)
        if events:
            events.discard(event)
            if not events:
                _waiters.pop(key, None)


async def wait(event, timeout):
    try:
        await asyncio.wait_for(event.wait(), timeout)
        return True
    except asyncio.TimeoutError:
        return False


def notify(key):
    for event in list(_waiters.get(key, ())):
        event.set()
