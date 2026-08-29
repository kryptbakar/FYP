"""LLM access for the synthesis node.

Two implementations behind one interface:

  OllamaClient — the real thing, constrained by the SynthesisOutput JSON schema.
  FakeLLM      — deterministic, no model, no network. CI runs the whole graph on this,
                 so the orchestrator's control flow is testable without 2 GB of weights
                 and 90 seconds of CPU inference per case.

The repair loop is deliberately bounded at ONE attempt. A model that cannot produce
valid JSON twice will not produce it on the fifth try either, and each retry costs ~90s
on this hardware. When it fails we abstain — `INSUFFICIENT_EVIDENCE` is a legitimate,
scored outcome, and a wrong-but-confident verdict is far worse than a refusal.
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Protocol

import httpx
from pydantic import ValidationError

from .models import Disposition, Severity, SynthesisOutput

log = logging.getLogger("orchestrator.llm")


class LLM(Protocol):
    name: str

    def complete(self, system: str, user: str) -> str: ...


class LLMUnavailable(RuntimeError):
    """The model could not be reached at all (as opposed to answering badly)."""


class OllamaClient:
    """Ollama chat client with a circuit breaker.

    The breaker exists because of the shape of the failure, not for its own sake. If
    Ollama is down, every investigation spends the FULL timeout — 240 s by default —
    discovering that, one after another, because the worker is serial. Ten queued
    investigations become forty minutes of waiting to produce ten identical failures,
    and the queue looks busy rather than broken the whole time.

    After `breaker_threshold` consecutive unreachable-errors the breaker opens and calls
    fail immediately for `breaker_cooldown_s`. One trial call is then allowed through; if
    it succeeds the breaker closes.

    Deliberately narrow: only failures to REACH the model trip it. A model that answers
    with unparseable output is answering, and that path is handled by the single bounded
    repair in `synthesize()` — tripping on it would disable the LLM over a bad generation.
    """

    def __init__(self, url: str, model: str, timeout_s: int = 240,
                 breaker_threshold: int = 3, breaker_cooldown_s: int = 120) -> None:
        self.url = url.rstrip("/")
        self.name = model
        self.timeout_s = timeout_s
        self.breaker_threshold = breaker_threshold
        self.breaker_cooldown_s = breaker_cooldown_s
        self._consecutive_failures = 0
        self._opened_at: float | None = None

    def _breaker_is_open(self) -> bool:
        if self._opened_at is None:
            return False
        if time.monotonic() - self._opened_at >= self.breaker_cooldown_s:
            # Half-open: let exactly one call through to test the water. It either closes
            # the breaker or re-opens it, so a dead Ollama costs one timeout per cooldown
            # rather than one per investigation.
            self._opened_at = None
            log.info("llm circuit breaker half-open; trying one call")
            return False
        return True

    def _record_success(self) -> None:
        if self._consecutive_failures:
            log.info("llm reachable again; circuit breaker reset")
        self._consecutive_failures = 0
        self._opened_at = None

    def _record_failure(self) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= self.breaker_threshold and self._opened_at is None:
            self._opened_at = time.monotonic()
            log.warning(
                "llm unreachable %d times in a row; circuit breaker open for %ds - "
                "investigations will abstain immediately instead of waiting %ds each",
                self._consecutive_failures, self.breaker_cooldown_s, self.timeout_s,
            )

    def complete(self, system: str, user: str) -> str:
        if self._breaker_is_open():
            raise LLMUnavailable(
                f"circuit breaker open after {self._consecutive_failures} consecutive "
                f"failures; not calling {self.url}"
            )
        payload = {
            "model": self.name,
            "stream": False,
            # Hand Ollama the actual JSON Schema rather than the string "json".
            # "json" only asks for *some* JSON; the schema constrains generation to the
            # shape we are about to validate, which is what makes one repair attempt
            # enough instead of a retry loop.
            "format": SynthesisOutput.model_json_schema(),
            "options": {"temperature": 0},   # deterministic: the same case must not drift
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        try:
            with httpx.Client(timeout=self.timeout_s) as c:
                r = c.post(f"{self.url}/api/chat", json=payload)
                r.raise_for_status()
                content = (r.json().get("message") or {}).get("content", "")
        except Exception as e:  # noqa: BLE001 - surfaced to the caller as a typed failure
            self._record_failure()
            raise LLMUnavailable(f"{type(e).__name__}: {e}") from e
        self._record_success()
        return content


class FakeLLM:
    """Deterministic stand-in. Derives a defensible verdict from the prompt text alone.

    Not a mock that returns a fixed blob: it reads the severity/KEV signals the real
    prompt carries, so graph tests exercise genuinely different branches (escalate vs
    monitor) without a model.
    """

    name = "fake-llm"

    def __init__(self, force_invalid: bool = False) -> None:
        # Lets a test drive the malformed-output path, which is the one that must
        # degrade to an abstention rather than crash or invent a verdict.
        self.force_invalid = force_invalid
        self.calls = 0

    def complete(self, system: str, user: str) -> str:
        self.calls += 1
        if self.force_invalid:
            return "I think this looks quite bad, honestly."   # not JSON at all
        hot = ("KEV" in user) or ("CRITICAL" in user.upper())
        # Match a real citation id at the start of an evidence line. Each branch owns a
        # prefix (F/X/A/T/I/C/H), so this must accept any letter — an earlier version
        # hard-coded `E` and cited an id that did not exist, which the validator correctly
        # rejected. Anchored and colon-terminated so it cannot match the "EVIDENCE:"
        # header, which is the other way this has already gone wrong.
        cites = re.findall(r"^([A-Z]\d+):", user, flags=re.MULTILINE)
        cid = cites[0] if cites else "F1"
        return json.dumps({
            "recommended_severity": (Severity.HIGH if hot else Severity.LOW).value,
            "recommended_disposition": (Disposition.ESCALATE if hot else Disposition.MONITOR).value,
            "summary": "Escalate: known-exploited and reachable." if hot
                       else "Monitor: no exploitation signal.",
            "rationale_claims": [{"text": "Derived from the supplied evidence.",
                                  "citation_ids": [cid]}],
            "recommended_next_steps": ["Patch the affected package."] if hot else [],
            "missing_evidence": [],
        })


def build(settings) -> LLM:
    if settings.fake_llm:
        log.info("using FakeLLM (ORCH_FAKE_LLM=true)")
        return FakeLLM()
    return OllamaClient(settings.ollama_url, settings.ollama_model, settings.llm_timeout_s)


REPAIR = (
    "Your previous reply was not valid against the required schema ({err}). "
    "Reply again with ONLY the JSON object, no prose, no code fence."
)


def synthesize(llm: LLM, system: str, user: str) -> tuple[SynthesisOutput | None, str | None]:
    """Call the model and validate. Returns (output, error). One repair attempt.

    Never raises on a bad answer — a malformed reply is a normal operating condition for
    a 3B model, and the caller turns `None` into an abstained report.
    """
    try:
        raw = llm.complete(system, user)
    except LLMUnavailable as e:
        return None, f"model unavailable: {e}"

    try:
        return SynthesisOutput.model_validate_json(raw), None
    except ValidationError as first:
        log.warning("synthesis output invalid; one repair attempt")
        try:
            raw2 = llm.complete(system, user + "\n\n" + REPAIR.format(err=str(first)[:200]))
            return SynthesisOutput.model_validate_json(raw2), None
        except LLMUnavailable as e:
            return None, f"model unavailable during repair: {e}"
        except ValidationError as second:
            return None, f"invalid output after repair: {str(second)[:300]}"
