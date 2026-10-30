"""Selective, budgeted knowledge retrieval (spec §34-35).

NEVER inject the whole knowledge base. `retrieve()` picks at most one domain card for the current
issue (keyed off the matched playbook, else the issue's keywords), renders it compactly, and trims it
to a character budget so the CPU model's prompt stays short. `investigate_tool_hint()` renders, for the
same domain, which read-only checks answer which questions — so the model selects a tool to test a
hypothesis, not because it exists.

Everything here is pure and deterministic (no I/O, no model): easy to test and safe to call on every
diagnosis. When nothing matches, it returns "" and the prompt is unchanged.
"""

import json
import os
import re

from ...text import stems
from . import tool_knowledge
from .bugchecks import BUGCHECKS
from .domains import DOMAINS, DOMAINS_BY_ID
from .error_codes import ERROR_CODES
from .event_ids import EVENT_IDS
from .investigation_map import where
from .playbook_extras import GENERIC_QUESTIONS, extras_for


def _budget(name, default):
    try:
        return max(0, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def domain_budget(mode="deep"):
    # Fast mode keeps the prompt tighter; deep mode has more room to reason.
    return _budget("KNOWLEDGE_BUDGET_CHARS", 1200 if mode == "deep" else 700)


# Playbook ids whose domain card has a different id.
PLAYBOOK_DOMAIN_ALIAS = {"performance": "slow_pc"}


def match_domain(issue, playbook=None, found_keys=()):
    """The one most relevant domain card, or None. The matched playbook wins; otherwise the issue's
    words are scored against each card's keywords (whole stemmed words, so 'mic' is not 'Microsoft')."""
    if playbook:
        card_id = playbook.get("id") if playbook.get("id") in DOMAINS_BY_ID else PLAYBOOK_DOMAIN_ALIAS.get(playbook.get("id"))
        if card_id in DOMAINS_BY_ID:
            return DOMAINS_BY_ID[card_id]
    tokens = set(stems(issue))
    best, best_score = None, 0
    for card in DOMAINS:
        score = sum(1 for keyword in card["keywords"] if set(stems(keyword)) <= tokens and set(stems(keyword)))
        if score > best_score:
            best, best_score = card, score
    return best


def render_domain(card):
    """A compact, senior-engineer guidance block for one domain card."""
    lines = [f"DOMAIN: {card['title']}",
             "Where to look: " + "; ".join(where(card["where"])) + ".",
             "Approach: " + card["approach"],
             "Likely causes: " + "; ".join(card["causes"]) + ".",
             "Confirm fixed: " + card["confirm"]]
    return "\n".join(lines)


def _trim(text, budget):
    """Keep whole lines up to the budget; never cut mid-line."""
    if len(text) <= budget:
        return text
    kept = []
    used = 0
    for line in text.splitlines():
        extra = len(line) + (1 if kept else 0)  # the newline only counts between kept lines
        if used + extra > budget:
            break
        kept.append(line)
        used += extra
    return "\n".join(kept)


def retrieve(issue, playbook=None, found_keys=(), os_type=None, mode="deep"):
    """The domain-knowledge block for the diagnosis prompt, or "" when nothing matches."""
    card = match_domain(issue, playbook, found_keys)
    if not card:
        return ""
    return _trim(render_domain(card), domain_budget(mode))


def investigate_tool_hint(issue, playbook=None, found_keys=(), os_type=None):
    """For the matched domain: which check answers which question, plus its decision points, so the model
    picks the next check to TEST a hypothesis (spec §6-7, §27). Budget-capped; "" when no domain matches."""
    card = match_domain(issue, playbook, found_keys)
    if not card:
        return ""
    lines = tool_knowledge.hint_lines(card["tools"])
    for point in extras_for(card["id"]).get("decision_points", []):
        lines.append(f"- decision: {point}")
    return _trim("\n".join(lines), _budget("KNOWLEDGE_TOOL_HINT_CHARS", 700))


def clarifying_questions(issue, playbook=None, found_keys=(), limit=3):
    """Targeted questions to narrow an unclear problem (spec §28-29): the matched domain's, else generic.
    Each has a diagnostic purpose; used when the checks did not pin a cause."""
    card = match_domain(issue, playbook, found_keys)
    questions = extras_for(card["id"]).get("questions") if card else None
    return list(questions or GENERIC_QUESTIONS)[:limit]


def escalation_reasons(issue, playbook=None, found_keys=()):
    """Domain-specific conditions that warrant escalation (spec §40), for the matched domain."""
    card = match_domain(issue, playbook, found_keys)
    return list(extras_for(card["id"]).get("escalate_when", [])) if card else []


# ---------------------------------------------------------------------------
# Error-code / Event-ID / BSOD engines (spec §12, §25, §26): retrieve only the codes that are
# actually present in the issue text or the evidence, and teach HOW to investigate each.
# ---------------------------------------------------------------------------

_CODE_SOURCES = (("ERROR CODE", ERROR_CODES), ("EVENT", EVENT_IDS), ("BSOD", BUGCHECKS))


def _corpus(issue, evidence):
    """The text to scan for codes: the issue plus each check's summary and a capped dump of its data."""
    parts = [str(issue or "")]
    for _tool_id, _args, result in evidence or []:
        if not isinstance(result, dict):
            continue
        parts.append(str(result.get("summary") or ""))
        data = result.get("data")
        if data is not None:
            parts.append(json.dumps(data, default=str)[:2000])
    return "\n".join(parts)


def detect_codes(issue, evidence=()):
    """[(kind, entry)] for every known code/Event-ID/bugcheck whose trigger matches. Deterministic."""
    corpus = _corpus(issue, evidence)
    hits = []
    for kind, entries in _CODE_SOURCES:
        for entry in entries:
            if any(re.search(pattern, corpus, re.I) for pattern in entry["triggers"]):
                hits.append((kind, entry))
    return hits


def _render_code(kind, entry):
    if kind == "BSOD":
        return f"- {entry['label']}: {entry['meaning']} Correlate: {entry['correlate']}"
    return f"- {entry['label']}: {entry['meaning']} Investigate: {entry['investigate']} Do not conclude: {entry['do_not']}"


def retrieve_codes(issue, evidence=(), max_entries=4):
    """A compact block for the codes/Event-IDs/bugchecks present, or "" when none are. Budget-capped."""
    hits = detect_codes(issue, evidence)[:max_entries]
    if not hits:
        return ""
    body = "\n".join(_render_code(kind, entry) for kind, entry in hits)
    return _trim(body, _budget("KNOWLEDGE_CODES_CHARS", 1000))
