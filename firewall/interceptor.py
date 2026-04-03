from __future__ import annotations

import logging
import os
import threading
from uuid import uuid4

from firewall.redactor import Redactor
from firewall.sentinel import Sentinel
from firewall.audit_chain import AuditChain

logger = logging.getLogger("aegis")


class Interceptor:
    def __init__(self, sentinel: Sentinel, redactor: Redactor, audit_chain: AuditChain) -> None:
        self.sentinel = sentinel
        self.redactor = redactor
        self.audit_chain = audit_chain
        is_test_mode = os.getenv("TEST_MODE", "").lower() == "true" or bool(os.getenv("PYTEST_CURRENT_TEST"))
        self._async_commit = (os.getenv("AUDIT_CHAIN_ASYNC_COMMIT", "true").lower() == "true") and (not is_test_mode)

    def _commit_event(self, **kwargs) -> None:
        is_test_mode = os.getenv("TEST_MODE", "").lower() == "true" or bool(os.getenv("PYTEST_CURRENT_TEST"))
        if (not self._async_commit) or is_test_mode:
            self.audit_chain.commit(**kwargs)
            return

        def _runner() -> None:
            try:
                self.audit_chain.commit(**kwargs)
            except Exception:
                logger.exception("Async audit chain commit failed")

        threading.Thread(target=_runner, name="audit-chain-commit", daemon=True).start()

    def ingress(self, prompt: str, session_id: str) -> dict:
        trace_id = str(uuid4())
        scan = self.sentinel.scan(prompt)
        if scan["is_threat"]:
            self._commit_event(
                session_id=session_id,
                event_type="INGRESS_BLOCK",
                threat_type=scan["threat_type"],
                layer_used=scan.get("layer_used", "HEURISTIC"),
                confidence=scan["confidence"],
                trace_id=trace_id,
            )
            return {
                "trace_id": trace_id,
                "verdict": "BLOCKED",
                "sanitized_prompt": "",
                "threat_type": scan["threat_type"],
                "layer_used": scan.get("layer_used", "HEURISTIC"),
                "confidence": scan["confidence"],
            }

        prompt_redacted = self.redactor.redact(prompt)
        verdict = "CLEAN"

        return {
            "trace_id": trace_id,
            "verdict": verdict,
            "sanitized_prompt": prompt_redacted["redacted_text"],
            "threat_type": scan["threat_type"],
            "layer_used": scan.get("layer_used", "HEURISTIC"),
            "confidence": scan["confidence"],
        }

    def egress(self, trace_id: str, session_id: str, payload: str) -> dict:
        result = self.redactor.redact(payload)
        verdict = "SUSPICIOUS" if result["redactions"] else "CLEAN"
        if verdict == "SUSPICIOUS":
            self._commit_event(
                session_id=session_id,
                event_type="EGRESS_REDACT",
                threat_type="EGRESS_PII",
                layer_used="NER+REGEX",
                confidence=1.0,
                encrypted_fields=result.get("encrypted_fields", []),
                redacted_fields=[r for r in result["redactions"]
                                 if r not in result.get("encrypted_fields", [])],
                trace_id=trace_id,
            )
        return {
            "trace_id": trace_id,
            "verdict": verdict,
            "sanitized_payload": result["redacted_text"],
            "redactions": result["redactions"],
            "encrypted_fields": result.get("encrypted_fields", []),
        }
