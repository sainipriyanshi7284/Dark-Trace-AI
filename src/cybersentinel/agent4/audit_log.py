"""Lightweight local JSONL audit logger for CyberSentinel Agent 4.

Records every policy enforcement decision for compliance, SOC auditing, and forensics.
Does not store secrets or unnecessary raw packet payloads.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from cybersentinel.agent4.contract import PolicyDecision
from cybersentinel.agent4.exceptions import (
    AuditLogError,
    AuditLogReadError,
    AuditLogWriteError,
)

logger = logging.getLogger(__name__)

DEFAULT_AUDIT_LOG_PATH = "audit_logs/policy_decisions.jsonl"

AUDIT_RECORD_FIELDS = [
    "flow_id",
    "timestamp",
    "policy_profile",
    "risk_level",
    "confidence_level",
    "fusion_score",
    "action",
    "matched_rule",
    "decision_reason",
    "requires_human_review",
    "simulated",
]


class PolicyAuditLogger:
    """Lightweight local JSONL audit logger for CyberSentinel policy decisions."""

    def __init__(self, log_path: Optional[Union[str, Path]] = None) -> None:
        """Initialize the audit logger with a configurable log file path.

        Args:
            log_path: Path to the audit log file. If omitted, defaults to
                      'audit_logs/policy_decisions.jsonl'.
        """
        self.log_path = Path(log_path or DEFAULT_AUDIT_LOG_PATH).resolve()
        self._ensure_file_exists()

    def _ensure_file_exists(self) -> None:
        """Create the parent directory and audit file if they do not exist."""
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            if not self.log_path.exists():
                self.log_path.touch(exist_ok=True)
        except Exception as exc:
            logger.warning("Failed to initialize audit log path %s: %s", self.log_path, exc)

    def append_record(
        self,
        decision: Union[PolicyDecision, Dict[str, Any]],
        fusion_score: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Append a validated policy decision record to the JSONL audit log.

        Args:
            decision: PolicyDecision instance or compatible dictionary.
            fusion_score: Optional explicit continuous fusion score.
            metadata: Optional dictionary with extra context (non-sensitive).

        Returns:
            Dict[str, Any]: The exact recorded audit dictionary.

        Raises:
            AuditLogWriteError: If writing to the audit log fails.
        """
        if isinstance(decision, PolicyDecision):
            d_dict = decision.to_dict()
            meta = decision.metadata
        elif isinstance(decision, dict):
            d_dict = decision
            meta = decision.get("metadata", {})
        else:
            raise AuditLogWriteError(
                f"Expected PolicyDecision or dict, got {type(decision).__name__}."
            )

        # Resolve fusion_score
        f_score = fusion_score
        if f_score is None:
            if "fusion_score" in d_dict and d_dict["fusion_score"] is not None:
                try:
                    f_score = float(d_dict["fusion_score"])
                except (ValueError, TypeError):
                    f_score = None
            elif isinstance(meta, dict) and meta.get("fusion_score") is not None:
                try:
                    f_score = float(meta["fusion_score"])
                except (ValueError, TypeError):
                    f_score = None

        record: Dict[str, Any] = {
            "flow_id": str(d_dict.get("flow_id", "UNKNOWN")),
            "timestamp": str(d_dict.get("timestamp", "")),
            "policy_profile": str(d_dict.get("policy_profile", "DEFAULT")),
            "risk_level": str(d_dict.get("risk_level", "UNKNOWN")),
            "confidence_level": str(d_dict.get("confidence_level", "LOW")),
            "fusion_score": f_score,
            "action": str(d_dict.get("action", "REVIEW")),
            "matched_rule": str(d_dict.get("matched_rule", "RULE_UNSPECIFIED")),
            "decision_reason": str(d_dict.get("decision_reason", "")),
            "requires_human_review": bool(d_dict.get("requires_human_review", True)),
            "simulated": bool(d_dict.get("simulated", True)),
        }

        # Write to JSONL file
        try:
            self._ensure_file_exists()
            line = json.dumps(record, ensure_ascii=False) + "\n"
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
        except Exception as exc:
            msg = f"Failed to write audit record to {self.log_path}: {exc}"
            logger.error(msg)
            raise AuditLogWriteError(msg) from exc

        return record

    def get_records_by_flow_id(self, flow_id: str) -> List[Dict[str, Any]]:
        """Retrieve all audit records associated with a given network flow ID.

        Gracefully ignores malformed lines.

        Args:
            flow_id: Identifier of the flow to query.

        Returns:
            List[Dict[str, Any]]: List of matching audit records.
        """
        all_records = self._read_all_valid_records()
        return [r for r in all_records if r.get("flow_id") == str(flow_id)]

    def get_recent_records(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve the most recent audit records up to limit.

        Args:
            limit: Maximum number of recent records to return.

        Returns:
            List[Dict[str, Any]]: Ordered list of recent audit records.
        """
        all_records = self._read_all_valid_records()
        if limit <= 0:
            return []
        return all_records[-limit:]

    def export_json(self, indent: int = 2) -> str:
        """Export all valid audit log records as a serialized JSON array string.

        Args:
            indent: Indentation level for formatting.

        Returns:
            str: Serialized JSON array of audit records.
        """
        records = self._read_all_valid_records()
        return json.dumps(records, indent=indent, ensure_ascii=False)

    def _read_all_valid_records(self) -> List[Dict[str, Any]]:
        """Read all valid records from JSONL file, gracefully skipping corrupted lines."""
        if not self.log_path.exists():
            return []

        records: List[Dict[str, Any]] = []
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line_idx, line in enumerate(f, start=1):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        obj = json.loads(stripped)
                        if isinstance(obj, dict):
                            records.append(obj)
                        else:
                            logger.warning(
                                "Skipping non-dict record at %s:%d", self.log_path, line_idx
                            )
                    except json.JSONDecodeError as exc:
                        logger.warning(
                            "Skipping malformed JSON line at %s:%d: %s",
                            self.log_path,
                            line_idx,
                            exc,
                        )
        except OSError as exc:
            msg = f"Failed to read audit log at {self.log_path}: {exc}"
            logger.error(msg)
            raise AuditLogReadError(msg) from exc

        return records

    def clear(self) -> None:
        """Truncate the audit log file (useful for test isolation)."""
        try:
            self._ensure_file_exists()
            with open(self.log_path, "w", encoding="utf-8") as f:
                f.truncate(0)
        except Exception as exc:
            raise AuditLogWriteError(f"Failed to clear audit log: {exc}") from exc

