from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from config import settings


logger = logging.getLogger("aegis")


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _resolve_db_path(path_from_config: str) -> Path:
    db_path = Path(path_from_config)
    if db_path.is_absolute():
        return db_path
    return _project_root() / db_path


def _compute_block_hash(
    block_index: int,
    trace_id: str,
    session_id: str,
    event_type: str,
    threat_type: str,
    timestamp_utc: str,
    prev_hash: str,
    encrypted_fields: list[str],
    redacted_fields: list[str],
    layer_used: str,
    confidence: float,
) -> str:
    payload = {
        "block_index": block_index,
        "trace_id": trace_id,
        "session_id": session_id,
        "event_type": event_type,
        "threat_type": threat_type,
        "timestamp_utc": timestamp_utc,
        "prev_hash": prev_hash,
        "encrypted_fields": encrypted_fields,
        "redacted_fields": redacted_fields,
        "layer_used": layer_used,
        "confidence": confidence,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class AuditEntry:
    block_index: int
    trace_id: str
    session_id: str
    event_type: str
    threat_type: str
    timestamp_utc: str
    prev_hash: str
    block_hash: str
    encrypted_fields: list[str] = field(default_factory=list)
    redacted_fields: list[str] = field(default_factory=list)
    layer_used: str = ""
    confidence: float = 0.0
    backend: str = "local_blockchain"


class AuditChain:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        db_path = os.getenv("AUDIT_CHAIN_DB_PATH", settings.audit_chain_db_path)
        self._db_path = _resolve_db_path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._last_error = ""
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_blocks (
                        block_index INTEGER PRIMARY KEY,
                        trace_id TEXT NOT NULL,
                        session_id TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        threat_type TEXT NOT NULL,
                        timestamp_utc TEXT NOT NULL,
                        prev_hash TEXT NOT NULL,
                        block_hash TEXT NOT NULL,
                        encrypted_fields TEXT NOT NULL,
                        redacted_fields TEXT NOT NULL,
                        layer_used TEXT NOT NULL,
                        confidence REAL NOT NULL
                    )
                    """
                )

                row = conn.execute("SELECT COUNT(*) AS total FROM audit_blocks").fetchone()
                total = int(row["total"]) if row else 0
                if total == 0:
                    genesis_ts = datetime.now(timezone.utc).isoformat()
                    genesis_hash = _compute_block_hash(
                        block_index=0,
                        trace_id="GENESIS",
                        session_id="system",
                        event_type="GENESIS",
                        threat_type="none",
                        timestamp_utc=genesis_ts,
                        prev_hash="0" * 64,
                        encrypted_fields=[],
                        redacted_fields=[],
                        layer_used="system",
                        confidence=1.0,
                    )
                    conn.execute(
                        """
                        INSERT INTO audit_blocks (
                            block_index, trace_id, session_id, event_type, threat_type,
                            timestamp_utc, prev_hash, block_hash, encrypted_fields,
                            redacted_fields, layer_used, confidence
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            0,
                            "GENESIS",
                            "system",
                            "GENESIS",
                            "none",
                            genesis_ts,
                            "0" * 64,
                            genesis_hash,
                            "[]",
                            "[]",
                            "system",
                            1.0,
                        ),
                    )

    def _row_to_entry(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "block_index": int(row["block_index"]),
            "trace_id": row["trace_id"],
            "session_id": row["session_id"],
            "event_type": row["event_type"],
            "threat_type": row["threat_type"],
            "timestamp_utc": row["timestamp_utc"],
            "prev_hash": row["prev_hash"],
            "block_hash": row["block_hash"],
            "encrypted_fields": json.loads(row["encrypted_fields"] or "[]"),
            "redacted_fields": json.loads(row["redacted_fields"] or "[]"),
            "layer_used": row["layer_used"],
            "confidence": float(row["confidence"]),
            "backend": "local_blockchain",
        }

    def commit(
        self,
        session_id: str,
        event_type: str,
        threat_type: str,
        layer_used: str = "",
        confidence: float = 0.0,
        encrypted_fields: list[str] | None = None,
        redacted_fields: list[str] | None = None,
        trace_id: str | None = None,
    ) -> AuditEntry:
        if trace_id is None:
            trace_id = str(uuid.uuid4())
        encrypted_fields = encrypted_fields or []
        redacted_fields = redacted_fields or []
        timestamp_utc = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._connect() as conn:
                last = conn.execute(
                    "SELECT block_index, block_hash FROM audit_blocks ORDER BY block_index DESC LIMIT 1"
                ).fetchone()
                prev_index = int(last["block_index"]) if last else 0
                prev_hash = str(last["block_hash"]) if last else ("0" * 64)
                block_index = prev_index + 1

                block_hash = _compute_block_hash(
                    block_index=block_index,
                    trace_id=trace_id,
                    session_id=session_id,
                    event_type=event_type,
                    threat_type=threat_type,
                    timestamp_utc=timestamp_utc,
                    prev_hash=prev_hash,
                    encrypted_fields=encrypted_fields,
                    redacted_fields=redacted_fields,
                    layer_used=layer_used,
                    confidence=confidence,
                )

                conn.execute(
                    """
                    INSERT INTO audit_blocks (
                        block_index, trace_id, session_id, event_type, threat_type,
                        timestamp_utc, prev_hash, block_hash, encrypted_fields,
                        redacted_fields, layer_used, confidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        block_index,
                        trace_id,
                        session_id,
                        event_type,
                        threat_type,
                        timestamp_utc,
                        prev_hash,
                        block_hash,
                        json.dumps(encrypted_fields),
                        json.dumps(redacted_fields),
                        layer_used,
                        float(confidence),
                    ),
                )

        entry = AuditEntry(
            block_index=block_index,
            trace_id=trace_id,
            session_id=session_id,
            event_type=event_type,
            threat_type=threat_type,
            timestamp_utc=timestamp_utc,
            prev_hash=prev_hash,
            block_hash=block_hash,
            encrypted_fields=encrypted_fields,
            redacted_fields=redacted_fields,
            layer_used=layer_used,
            confidence=confidence,
        )
        logger.info("Audit chain committed block=%s trace=%s", block_index, trace_id)
        return entry

    def get_all(self) -> list[dict[str, Any]]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM audit_blocks
                    WHERE event_type != 'GENESIS'
                    ORDER BY block_index DESC
                    """
                ).fetchall()
        return [self._row_to_entry(row) for row in rows]

    def get_by_session(self, session_id: str) -> list[dict[str, Any]]:
        return [entry for entry in self.get_all() if entry.get("session_id") == session_id]

    def get_by_trace(self, trace_id: str) -> Optional[dict[str, Any]]:
        for entry in self.get_all():
            if entry.get("trace_id") == trace_id:
                return entry
        return None

    def get_by_event_type(self, event_type: str) -> list[dict[str, Any]]:
        return [entry for entry in self.get_all() if entry.get("event_type") == event_type]

    def stats(self) -> dict[str, Any]:
        all_entries = self.get_all()
        threat_breakdown: dict[str, int] = {}
        sessions: set[str] = set()
        ingress_blocks = 0
        egress_redacts = 0

        for entry in all_entries:
            sessions.add(entry["session_id"])
            threat_type = entry["threat_type"]
            threat_breakdown[threat_type] = threat_breakdown.get(threat_type, 0) + 1
            if entry["event_type"] in {"BLOCK", "INGRESS_BLOCK"}:
                ingress_blocks += 1
            elif entry["event_type"] in {"REDACT", "EGRESS_REDACT"}:
                egress_redacts += 1

        return {
            "total": len(all_entries),
            "total_events": len(all_entries),
            "ingress_blocks": ingress_blocks,
            "egress_redacts": egress_redacts,
            "unique_sessions": len(sessions),
            "threat_type_breakdown": threat_breakdown,
            "storage": "local-blockchain",
        }

    def connectivity(self) -> dict[str, Any]:
        writable = os.access(self._db_path.parent, os.W_OK)
        return {
            "status": "online" if writable else "degraded",
            "backend": "local_blockchain",
            "db_path": str(self._db_path),
            "writable": writable,
            "error": self._last_error or "",
        }

    def _verify_entry(self, entry: dict[str, Any]) -> bool:
        stored_hash = (
            entry.get("block_hash")
            or entry.get("audit_hash")
            or entry.get("hash")
            or ""
        )
        derived_hash = _compute_block_hash(
            block_index=int(entry.get("block_index", 0)),
            trace_id=str(entry["trace_id"]),
            session_id=str(entry["session_id"]),
            event_type=str(entry["event_type"]),
            threat_type=str(entry["threat_type"]),
            timestamp_utc=str(entry["timestamp_utc"]),
            prev_hash=str(entry.get("prev_hash", "")),
            encrypted_fields=list(entry.get("encrypted_fields", [])),
            redacted_fields=list(entry.get("redacted_fields", [])),
            layer_used=str(entry.get("layer_used", "")),
            confidence=float(entry.get("confidence", 0.0)),
        )
        return derived_hash == stored_hash

    def verify(self, entry_or_trace_id: dict[str, Any] | str) -> dict[str, Any] | bool:
        if isinstance(entry_or_trace_id, dict):
            return self._verify_entry(entry_or_trace_id)

        trace_id = entry_or_trace_id
        entry = self.get_by_trace(trace_id)
        if entry is None:
            return {"error": "not found"}

        derived_hash = _compute_block_hash(
            block_index=int(entry["block_index"]),
            trace_id=entry["trace_id"],
            session_id=entry["session_id"],
            event_type=entry["event_type"],
            threat_type=entry["threat_type"],
            timestamp_utc=entry["timestamp_utc"],
            prev_hash=entry["prev_hash"],
            encrypted_fields=entry.get("encrypted_fields", []),
            redacted_fields=entry.get("redacted_fields", []),
            layer_used=entry.get("layer_used", ""),
            confidence=float(entry.get("confidence", 0.0)),
        )

        return {
            "trace_id": trace_id,
            "valid": derived_hash == entry["block_hash"],
            "stored_hash": entry["block_hash"],
            "derived_hash": derived_hash,
            "tampered": derived_hash != entry["block_hash"],
            "block_index": entry["block_index"],
        }

    def verify_all(self) -> dict[str, Any]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM audit_blocks
                    ORDER BY block_index ASC
                    """
                ).fetchall()

        if not rows:
            return {"total": 0, "valid": 0, "tampered": 0, "tampered_trace_ids": []}

        valid_count = 0
        tampered_count = 0
        tampered_trace_ids: list[str] = []
        previous_hash = "0" * 64

        for row in rows:
            entry = self._row_to_entry(row)
            expected_hash = _compute_block_hash(
                block_index=entry["block_index"],
                trace_id=entry["trace_id"],
                session_id=entry["session_id"],
                event_type=entry["event_type"],
                threat_type=entry["threat_type"],
                timestamp_utc=entry["timestamp_utc"],
                prev_hash=entry["prev_hash"],
                encrypted_fields=entry.get("encrypted_fields", []),
                redacted_fields=entry.get("redacted_fields", []),
                layer_used=entry.get("layer_used", ""),
                confidence=float(entry.get("confidence", 0.0)),
            )

            is_valid = expected_hash == entry["block_hash"] and entry["prev_hash"] == previous_hash

            if entry["event_type"] == "GENESIS":
                previous_hash = entry["block_hash"]
                continue

            if is_valid:
                valid_count += 1
            else:
                tampered_count += 1
                tampered_trace_ids.append(entry["trace_id"])

            previous_hash = entry["block_hash"]

        return {
            "total": valid_count + tampered_count,
            "valid": valid_count,
            "tampered": tampered_count,
            "tampered_trace_ids": tampered_trace_ids,
        }


audit_chain = AuditChain()
