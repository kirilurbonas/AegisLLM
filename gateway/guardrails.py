"""The guardrail pipeline: the only path between a caller and the model.

Two asymmetric decisions, deliberately:

* **Input is rejected.** If a prompt looks like an injection attempt, the request
  is refused outright. There is no safe way to "clean" an adversarial prompt --
  a sanitiser that removes `ignore previous instructions` just teaches the
  attacker to write it differently, while telling the operator the problem was
  handled.

* **Output is redacted, then rejected only if redaction is not enough.** Model
  output is not adversarial in the same way; a leaked email address in an
  otherwise useful response should be masked, not thrown away. Secrets are the
  exception -- a leaked credential means something has already gone wrong
  upstream, so that response is refused entirely and logged loudly.

Every decision is recorded, because Pillar 5 needs an audit trail and Pillar 4
needs something to measure. A guardrail that blocks silently cannot be tuned.
"""

from __future__ import annotations

import dataclasses
import enum
import time

from . import detectors
from .detectors import Finding


class Decision(str, enum.Enum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"


@dataclasses.dataclass
class GuardrailResult:
    decision: Decision
    text: str
    findings: list[Finding]
    stage: str
    elapsed_ms: float

    @property
    def blocked(self) -> bool:
        return self.decision is Decision.BLOCK

    def summary(self) -> dict:
        """Audit-log shape. Deliberately excludes the prompt itself.

        Logging the full text of every blocked prompt would turn the audit log
        into a store of exactly the sensitive data the PII guardrail exists to
        keep out of logs. Categories and counts are what an operator needs.
        """
        return {
            "stage": self.stage,
            "decision": self.decision.value,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "findings": sorted({f"{f.detector}:{f.category}" for f in self.findings}),
            "finding_count": len(self.findings),
        }


@dataclasses.dataclass(frozen=True)
class GuardrailConfig:
    max_input_chars: int = 4_000
    # LLM10: an unbounded prompt is a cheap way to burn someone else's compute.
    max_output_tokens: int = 256
    block_pii_on_input: bool = False
    """PII in a *prompt* is usually the user's own data, knowingly supplied. It
    is redacted before reaching the model rather than refused, so the service
    stays usable; set True for a stricter deployment."""


class InputGuardrail:
    """OWASP LLM01 (Prompt Injection) and LLM10 (Unbounded Consumption)."""

    def __init__(self, config: GuardrailConfig) -> None:
        self.config = config

    def __call__(self, text: str) -> GuardrailResult:
        started = time.perf_counter()
        findings: list[Finding] = []
        decision = Decision.ALLOW
        result_text = text

        if len(text) > self.config.max_input_chars:
            findings.append(
                Finding(
                    detector="limits",
                    category="input-too-long",
                    detail=f"{len(text)} > {self.config.max_input_chars} chars",
                )
            )
            decision = Decision.BLOCK

        injection = detectors.detect_injection(text)
        if injection:
            findings += injection
            decision = Decision.BLOCK

        secrets = detectors.detect_secrets(text)
        if secrets:
            # A credential in a prompt should never reach the model, be logged,
            # or be echoed back. Refuse and let the caller notice.
            findings += secrets
            decision = Decision.BLOCK

        pii = detectors.detect_pii(text)
        if pii:
            findings += pii
            if self.config.block_pii_on_input:
                decision = Decision.BLOCK
            elif decision is Decision.ALLOW:
                result_text = detectors.redact(text, pii)
                decision = Decision.REDACT

        return GuardrailResult(
            decision=decision,
            text=result_text,
            findings=findings,
            stage="input",
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )


class OutputGuardrail:
    """OWASP LLM02 (Sensitive Information Disclosure) and LLM07 (System Prompt
    Leakage)."""

    def __init__(self, config: GuardrailConfig, system_prompt: str = "") -> None:
        self.config = config
        # Kept to check for verbatim leakage. Only a distinctive fragment is
        # compared, so an incidental word overlap is not a false positive.
        self._canary = system_prompt.strip()[:60]

    def __call__(self, text: str) -> GuardrailResult:
        started = time.perf_counter()
        findings: list[Finding] = []
        decision = Decision.ALLOW
        result_text = text

        secrets = detectors.detect_secrets(text)
        if secrets:
            findings += secrets
            decision = Decision.BLOCK

        if self._canary and self._canary in text:
            findings.append(
                Finding(
                    detector="system-prompt-leak",
                    category="verbatim-system-prompt",
                    detail="response contained the system prompt",
                )
            )
            decision = Decision.BLOCK

        pii = detectors.detect_pii(text)
        if pii:
            findings += pii
            if decision is Decision.ALLOW:
                result_text = detectors.redact(text, pii)
                decision = Decision.REDACT

        if decision is Decision.BLOCK:
            # Never return partially-redacted text alongside a block: the point
            # of blocking is that nothing derived from this response is safe.
            result_text = ""

        return GuardrailResult(
            decision=decision,
            text=result_text,
            findings=findings,
            stage="output",
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )
