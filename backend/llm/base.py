"""Shared provider errors and helpers."""

import re

THINK_BLOCK = re.compile(r"<think>.*?</think>", re.DOTALL)


class LLMUnavailableError(RuntimeError):
    """The provider cannot be reached or is not configured."""


class LLMModelError(LLMUnavailableError):
    """The provider is reachable but rejected the configured model or request."""


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
