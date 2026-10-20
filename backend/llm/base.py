"""Shared provider errors and helpers."""

import json
import re

THINK_BLOCK = re.compile(r"<think>.*?</think>", re.DOTALL)


class LLMUnavailableError(RuntimeError):
    """The provider cannot be reached or is not configured."""


class LLMModelError(LLMUnavailableError):
    """The provider is reachable but rejected the configured model or request."""


class LLMTimeoutError(LLMUnavailableError):
    """The model did not finish within the deadline (too slow on this machine right now)."""


class LLMDisconnectedError(LLMUnavailableError):
    """The connection dropped mid-answer (e.g. the model runner restarted under memory pressure)."""


def loads_lenient(raw):
    """json.loads, or the longest complete prefix of a reply cut off by the token limit
    (closing whatever brackets were still open), so a long answer is not thrown away."""
    text = (raw or "").strip()
    if text.startswith("```"):
        text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        return json.loads(text)
    except ValueError:
        pass
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object in the reply")
    text = text[start:]
    stack, in_string, escaped, cuts = [], False, False, []
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[":
            stack.append("}" if char == "{" else "]")
        elif char in "}]":
            if stack:
                stack.pop()
            cuts.append((index + 1, "".join(reversed(stack))))
        elif char == ",":
            cuts.append((index, "".join(reversed(stack))))
    for cut, closers in reversed(cuts):
        try:
            return json.loads(text[:cut] + closers)
        except ValueError:
            continue
    raise ValueError("no parsable JSON in the reply")


# UTF-8 punctuation that was decoded as Windows-1252 somewhere in a model's training data;
# small models reproduce it (e.g. "85.1Â°C"), so repair the common cases.
MOJIBAKE = {"Â°": "°", "â€™": "'", "â€˜": "'", "â€œ": '"', "â€": '"',
            "â€“": "-", "â€”": "-", "â€¦": "...", "Â ": " "}


def clean_content(text):
    """Drop reasoning blocks some local models emit before the answer, and repair mojibake."""
    text = THINK_BLOCK.sub("", text or "").strip()
    for broken, fixed in MOJIBAKE.items():
        text = text.replace(broken, fixed)
    return text
