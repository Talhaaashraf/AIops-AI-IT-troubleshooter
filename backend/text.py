"""Tiny text helpers shared by playbook matching and the learned-case memory.

A very small stemmer: enough to make "hangs", "freezing" and "websites" match "hang", "freeze" and "website",
without a language library.
"""

import re

WORD = re.compile(r"[a-z0-9]+(?:[-'][a-z0-9]+)*")
VOWELS = set("aeiou")


def stem(word):
    word = word.lower()
    for suffix, keep in (("ing", 3), ("ed", 3), ("es", 3), ("s", 3)):
        if word.endswith(suffix) and len(word) - len(suffix) >= keep and not (suffix == "s" and word.endswith("ss")):
            word = word[: -len(suffix)]
            # stopped -> stop, lagging -> lag (but keep "press", "install")
            if suffix in ("ing", "ed") and len(word) >= 3 and word[-1] == word[-2] and word[-1] not in VOWELS | {"s", "l"}:
                word = word[:-1]
            break
    if word.endswith("e") and len(word) > 4:
        word = word[:-1]
    return word


def words(text):
    """Lower-case word tokens (keeping wi-fi and won't whole)."""
    return WORD.findall((text or "").lower())


def stems(text):
    return [stem(word) for word in words(text)]
