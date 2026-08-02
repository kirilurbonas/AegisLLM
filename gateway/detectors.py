"""Detectors for the guardrail pipeline.

A deliberate note on what these are worth, because overclaiming here is how
security theatre gets built:

**Pattern-based prompt-injection detection is a weak control.** It catches known
phrasings and casual attempts; it does not catch a determined adversary, who can
paraphrase, encode, translate, or split an instruction across turns. Anyone
selling a regex list as "prompt injection protection" is selling a filter, not a
defence.

It is included because defence in depth is still worth having and because the
red-team suite in Pillar 4 needs something to measure movement against. The
controls that actually bound the damage are architectural, and they live
elsewhere in this platform: the model has no tools, no network egress, and no
credentials, so a successful injection has nothing to reach for. That is
LLM06 (Excessive Agency) being handled by design rather than by detection.

PII detection is a different case: patterns work well for *structured*
identifiers (card numbers, emails, national IDs) because those have checkable
shapes. Names and addresses are not reliably detectable this way and are not
claimed to be.
"""

from __future__ import annotations

import dataclasses
import re


@dataclasses.dataclass(frozen=True)
class Finding:
    """One detector hit."""

    detector: str
    category: str
    detail: str
    # Where in the text, so the output guardrail can redact rather than reject.
    span: tuple[int, int] | None = None


# --------------------------------------------------------------------------
# Prompt injection / jailbreak heuristics
# --------------------------------------------------------------------------

# Each pattern targets a *published* jailbreak shape. Kept small and readable on
# purpose: a huge unexplained regex list is impossible to review and gives a
# false sense of coverage.
INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", "instruction-override"),
    (r"disregard\s+(all\s+)?(previous|prior|the\s+above)", "instruction-override"),
    (r"forget\s+(everything|all)\s+(you|above)", "instruction-override"),
    (r"you\s+are\s+now\s+(a|an|in)\b", "persona-hijack"),
    (r"\bpretend\s+(to\s+be|you\s+are)\b", "persona-hijack"),
    (r"\b(dan|do\s+anything\s+now)\s+mode\b", "persona-hijack"),
    (r"\bdeveloper\s+mode\b", "persona-hijack"),
    (r"(reveal|show|print|repeat|output)\s+(me\s+)?(your|the)\s+(system\s+)?prompt",
     "system-prompt-extraction"),
    (r"what\s+(are|were)\s+your\s+(original\s+)?instructions", "system-prompt-extraction"),
    (r"repeat\s+(everything\s+)?above", "system-prompt-extraction"),
    (r"</?(system|assistant|user)>", "role-injection"),
    (r"\[\s*(system|inst)\s*\]", "role-injection"),
    (r"<\|im_(start|end)\|>", "role-injection"),
    (r"###\s*(system|instruction)", "role-injection"),
]

_INJECTION = [(re.compile(p, re.IGNORECASE), category) for p, category in INJECTION_PATTERNS]


def detect_injection(text: str) -> list[Finding]:
    findings = []
    for pattern, category in _INJECTION:
        match = pattern.search(text)
        if match:
            findings.append(
                Finding(
                    detector="prompt-injection",
                    category=category,
                    detail=f"matched {pattern.pattern!r}",
                    span=match.span(),
                )
            )
    return findings


# --------------------------------------------------------------------------
# PII and secrets
# --------------------------------------------------------------------------

PII_PATTERNS: list[tuple[str, str]] = [
    (r"\b[\w.%-]+@[\w.-]+\.[A-Za-z]{2,}\b", "email"),
    # Card-shaped digit runs; validated with Luhn below to cut false positives.
    (r"\b(?:\d[ -]*?){13,19}\b", "payment-card"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "us-ssn"),
    (r"\b(?:\+?\d{1,3}[ -]?)?(?:\(\d{3}\)|\d{3})[ -]?\d{3}[ -]?\d{4}\b", "phone"),
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "ip-address"),
]

SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"\bgh[pousr]_[A-Za-z0-9]{16,}\b", "github-token"),
    (r"\bAKIA[0-9A-Z]{16}\b", "aws-access-key"),
    (r"\bsk-[A-Za-z0-9]{20,}\b", "openai-key"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private-key"),
    (r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "jwt"),
]

_PII = [(re.compile(p), category) for p, category in PII_PATTERNS]
_SECRETS = [(re.compile(p), category) for p, category in SECRET_PATTERNS]


def _luhn_ok(digits: str) -> bool:
    """Luhn checksum — what separates a card number from any 16-digit string."""
    total, parity = 0, len(digits) % 2
    for index, char in enumerate(digits):
        value = int(char)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def detect_pii(text: str) -> list[Finding]:
    findings = []
    for pattern, category in _PII:
        for match in pattern.finditer(text):
            if category == "payment-card":
                digits = re.sub(r"\D", "", match.group())
                # Without this check every order number and long ID is "a credit
                # card", the redactor mangles legitimate output, and users learn
                # to route around the guardrail.
                if not (13 <= len(digits) <= 19 and _luhn_ok(digits)):
                    continue
            findings.append(
                Finding(
                    detector="pii",
                    category=category,
                    detail=category,
                    span=match.span(),
                )
            )
    return findings


def detect_secrets(text: str) -> list[Finding]:
    findings = []
    for pattern, category in _SECRETS:
        for match in pattern.finditer(text):
            findings.append(
                Finding(
                    detector="secret",
                    category=category,
                    detail=category,
                    span=match.span(),
                )
            )
    return findings


def redact(text: str, findings: list[Finding]) -> str:
    """Replace each finding's span with a category marker.

    Applied right-to-left so earlier spans keep their offsets. Overlapping
    findings are skipped rather than double-redacted, which would corrupt the
    surrounding text.
    """
    spans = sorted(
        (f for f in findings if f.span is not None),
        key=lambda f: f.span[0],
        reverse=True,
    )
    result = text
    last_start = len(text) + 1
    for finding in spans:
        start, end = finding.span
        if end > last_start:
            continue
        result = f"{result[:start]}[REDACTED:{finding.category}]{result[end:]}"
        last_start = start
    return result
