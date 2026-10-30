"""Unit and integration tests for CyberSentinel Agent 4 Policy Audit Logger.

Tests:
  12. Append audit record: verify all 11 fields are written correctly.
  13. Read audit records by flow_id: verify retrieval.
  14. Read recent audit records: verify ordering and limit.
  15. Export audit log to JSON: verify valid JSON output.
  16. Create audit file if it does not exist.
  17. Handle corrupted audit log lines gracefully without crashing.
  18. Handle write errors or read-only paths without crashing.
  19. Integration: AdaptivePolicyEngine automatic logging.
  20. Audit logger clear / truncate functionality.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from cybersentinel.agent4.adaptive_policy import AdaptivePolicyEngine
from cybersentinel.agent4.audit_log import AUDIT_RECORD_FIELDS, PolicyAuditLogger
from cybersentinel.agent4.contract import PolicyAction, PolicyDecision, PolicyProfile
from cybersentinel.agent4.exceptions import AuditLogWriteError


@pytest.fixture
def temp_audit_file(tmp_path: Path) -> Path:
    """Fixture providing a temporary JSONL log file path."""
    return tmp_path / "audit" / "test_policy_decisions.jsonl"


@pytest.fixture
def audit_logger(temp_audit_file: Path) -> PolicyAuditLogger:
    """Fixture providing a PolicyAuditLogger instance targeting a temp file."""
    return PolicyAuditLogger(log_path=temp_audit_file)


# =============================================================================
# 12. Append Audit Record: All 11 Fields
# =============================================================================
def test_append_record_verifies_all_11_fields(audit_logger: PolicyAuditLogger, temp_audit_file: Path):
    """Scenario 12: Verify all 11 audit fields are written accurately."""
    decision = PolicyDecision(
        flow_id="FLOW-AUDIT-101",
        action=PolicyAction.BLOCK,
        policy_profile="STRICT",
        matched_rule="RULE_CRITICAL_RISK_BLOCK",
        decision_reason="STRICT policy: high confidence critical threat requires immediate block.",
        risk_level="CRITICAL",
        confidence_level="HIGH",
        requires_human_review=False,
        simulated=True,
        timestamp="2026-10-30T12:00:00Z",
    )

    recorded = audit_logger.append_record(decision, fusion_score=0.92)

    # Verify returned dictionary fields
    assert set(recorded.keys()) == set(AUDIT_RECORD_FIELDS)
    assert len(recorded) == 11
    assert recorded["flow_id"] == "FLOW-AUDIT-101"
    assert recorded["timestamp"] == "2026-10-30T12:00:00Z"
    assert recorded["policy_profile"] == "STRICT"
    assert recorded["risk_level"] == "CRITICAL"
    assert recorded["confidence_level"] == "HIGH"
    assert recorded["fusion_score"] == 0.92
    assert recorded["action"] == "BLOCK"
    assert recorded["matched_rule"] == "RULE_CRITICAL_RISK_BLOCK"
    assert recorded["decision_reason"] == "STRICT policy: high confidence critical threat requires immediate block."
    assert recorded["requires_human_review"] is False
    assert recorded["simulated"] is True

    # Verify physical file on disk
    assert temp_audit_file.exists()
    lines = temp_audit_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    disk_record = json.loads(lines[0])
    assert set(disk_record.keys()) == set(AUDIT_RECORD_FIELDS)
    assert disk_record == recorded


def test_append_record_from_dict_and_metadata_score(audit_logger: PolicyAuditLogger):
    """Verify appending a raw dict resolves fusion_score from metadata."""
    raw_dict = {
        "flow_id": "FLOW-DICT-202",
        "timestamp": "2026-10-30T12:05:00Z",
        "policy_profile": "BALANCED",
        "risk_level": "MEDIUM",
        "confidence_level": "HIGH",
        "action": "ALERT",
        "matched_rule": "RULE_MEDIUM_RISK_ALERT",
        "decision_reason": "BALANCED policy alert.",
        "requires_human_review": False,
        "simulated": True,
        "metadata": {"fusion_score": 0.42},
    }

    recorded = audit_logger.append_record(raw_dict)
    assert recorded["flow_id"] == "FLOW-DICT-202"
    assert recorded["fusion_score"] == 0.42
    assert recorded["action"] == "ALERT"


# =============================================================================
# 13. Read Audit Records by flow_id
# =============================================================================
def test_get_records_by_flow_id(audit_logger: PolicyAuditLogger):
    """Scenario 13: Verify retrieving records filtered by network flow_id."""
    audit_logger.append_record({"flow_id": "FLOW-A", "action": "ALLOW", "risk_level": "LOW", "confidence_level": "HIGH", "matched_rule": "R1", "decision_reason": "ok", "requires_human_review": False, "simulated": True, "policy_profile": "BALANCED", "timestamp": "t1"})
    audit_logger.append_record({"flow_id": "FLOW-B", "action": "ALERT", "risk_level": "MEDIUM", "confidence_level": "HIGH", "matched_rule": "R2", "decision_reason": "alert", "requires_human_review": False, "simulated": True, "policy_profile": "BALANCED", "timestamp": "t2"})
    audit_logger.append_record({"flow_id": "FLOW-A", "action": "REVIEW", "risk_level": "HIGH", "confidence_level": "HIGH", "matched_rule": "R3", "decision_reason": "review", "requires_human_review": True, "simulated": True, "policy_profile": "BALANCED", "timestamp": "t3"})

    records_a = audit_logger.get_records_by_flow_id("FLOW-A")
    assert len(records_a) == 2
    assert records_a[0]["action"] == "ALLOW"
    assert records_a[1]["action"] == "REVIEW"

    records_b = audit_logger.get_records_by_flow_id("FLOW-B")
    assert len(records_b) == 1
    assert records_b[0]["action"] == "ALERT"

    records_none = audit_logger.get_records_by_flow_id("FLOW-NONEXISTENT")
    assert records_none == []


# =============================================================================
# 14. Read Recent Audit Records: Ordering and Limit
# =============================================================================
def test_get_recent_records(audit_logger: PolicyAuditLogger):
    """Scenario 14: Verify recent record ordering and limit slicing."""
    for i in range(1, 6):
        audit_logger.append_record({
            "flow_id": f"FLOW-{i}",
            "action": "ALLOW",
            "risk_level": "LOW",
            "confidence_level": "HIGH",
            "matched_rule": f"R{i}",
            "decision_reason": f"reason {i}",
            "requires_human_review": False,
            "simulated": True,
            "policy_profile": "BALANCED",
            "timestamp": f"2026-10-30T10:0{i}:00Z",
        })

    # Retrieve limit=3 (should return last 3 records: FLOW-3, FLOW-4, FLOW-5)
    recent = audit_logger.get_recent_records(limit=3)
    assert len(recent) == 3
    assert [r["flow_id"] for r in recent] == ["FLOW-3", "FLOW-4", "FLOW-5"]

    # Retrieve all records with large limit
    all_rec = audit_logger.get_recent_records(limit=50)
    assert len(all_rec) == 5

    # Edge cases
    assert audit_logger.get_recent_records(limit=0) == []
    assert audit_logger.get_recent_records(limit=-5) == []


# =============================================================================
# 15. Export Audit Log to JSON
# =============================================================================
def test_export_json(audit_logger: PolicyAuditLogger):
    """Scenario 15: Verify export_json produces a valid JSON array string."""
    audit_logger.append_record({"flow_id": "EXPORT-1", "action": "ALLOW", "risk_level": "LOW", "confidence_level": "HIGH", "matched_rule": "R1", "decision_reason": "ok", "requires_human_review": False, "simulated": True, "policy_profile": "BALANCED", "timestamp": "t1"})
    audit_logger.append_record({"flow_id": "EXPORT-2", "action": "BLOCK", "risk_level": "CRITICAL", "confidence_level": "HIGH", "matched_rule": "R2", "decision_reason": "blocked", "requires_human_review": False, "simulated": True, "policy_profile": "BALANCED", "timestamp": "t2"})

    exported = audit_logger.export_json(indent=2)
    assert isinstance(exported, str)

    parsed = json.loads(exported)
    assert isinstance(parsed, list)
    assert len(parsed) == 2
    assert parsed[0]["flow_id"] == "EXPORT-1"
    assert parsed[1]["flow_id"] == "EXPORT-2"


# =============================================================================
# 16. Create Missing Audit File
# =============================================================================
def test_create_missing_audit_file(tmp_path: Path):
    """Scenario 16: Verify logger creates nested parent directories and log file if missing."""
    deep_path = tmp_path / "deeply" / "nested" / "logs" / "audit.jsonl"
    assert not deep_path.exists()

    logger_instance = PolicyAuditLogger(log_path=deep_path)
    assert deep_path.exists()
    assert deep_path.is_file()
    assert logger_instance.get_recent_records() == []


# =============================================================================
# 17. Handle Corrupted Audit Log Lines Gracefully
# =============================================================================
def test_handle_corrupted_audit_log_lines_gracefully(audit_logger: PolicyAuditLogger, temp_audit_file: Path):
    """Scenario 17: Logger skips corrupted, non-dict, or blank lines without crashing."""
    valid_record_1 = {
        "flow_id": "VALID-1",
        "timestamp": "t1",
        "policy_profile": "BALANCED",
        "risk_level": "LOW",
        "confidence_level": "HIGH",
        "fusion_score": 0.1,
        "action": "ALLOW",
        "matched_rule": "R1",
        "decision_reason": "ok",
        "requires_human_review": False,
        "simulated": True,
    }
    valid_record_2 = {
        "flow_id": "VALID-2",
        "timestamp": "t2",
        "policy_profile": "BALANCED",
        "risk_level": "HIGH",
        "confidence_level": "HIGH",
        "fusion_score": 0.65,
        "action": "REVIEW",
        "matched_rule": "R2",
        "decision_reason": "review",
        "requires_human_review": True,
        "simulated": True,
    }

    # Write a mix of valid records, corrupted JSON, blank lines, and non-dict JSON
    content = (
        json.dumps(valid_record_1) + "\n"
        + "\n"  # blank line
        + "{ corrupted json line -- not valid } \n"
        + "   \n"  # whitespace line
        + json.dumps([1, 2, 3]) + "\n"  # valid JSON, but a list instead of dict
        + json.dumps(valid_record_2) + "\n"
    )
    temp_audit_file.write_text(content, encoding="utf-8")

    # The logger should cleanly read only the 2 valid dict records
    records = audit_logger.get_recent_records()
    assert len(records) == 2
    assert records[0]["flow_id"] == "VALID-1"
    assert records[1]["flow_id"] == "VALID-2"

    # Querying by flow ID should also work cleanly
    rec_valid = audit_logger.get_records_by_flow_id("VALID-2")
    assert len(rec_valid) == 1
    assert rec_valid[0]["action"] == "REVIEW"


# =============================================================================
# 18. Handle Write Errors Gracefully
# =============================================================================
def test_handle_write_errors_raises_audit_log_write_error(tmp_path: Path):
    """Scenario 18: Verify AuditLogWriteError is raised when writing to an invalid target."""
    dir_target = tmp_path / "directory_as_target"
    dir_target.mkdir(parents=True, exist_ok=True)

    # Point log_path to an existing directory so opening it as a file fails
    logger_instance = PolicyAuditLogger(log_path=dir_target)

    decision = {
        "flow_id": "ERR-1",
        "action": "ALLOW",
        "risk_level": "LOW",
        "confidence_level": "HIGH",
        "matched_rule": "R1",
        "decision_reason": "ok",
        "requires_human_review": False,
        "simulated": True,
    }

    with pytest.raises(AuditLogWriteError) as exc_info:
        logger_instance.append_record(decision)

    assert "Failed to write audit record" in str(exc_info.value) or "Permission" in str(exc_info.value)


# =============================================================================
# 19. Integration: AdaptivePolicyEngine Automatic Logging
# =============================================================================
def test_integration_adaptive_policy_with_audit_logger(temp_audit_file: Path):
    """Verify AdaptivePolicyEngine automatically logs decisions when audit_logger is provided."""
    audit_logger = PolicyAuditLogger(log_path=temp_audit_file)
    engine = AdaptivePolicyEngine(default_profile=PolicyProfile.BALANCED, audit_logger=audit_logger)

    flow_1 = {"flow_id": "INT-LOG-1", "final_class": "BENIGN", "assessment": "BENIGN", "risk_level": "LOW", "confidence_level": "HIGH", "fusion_score": 0.05}
    flow_2 = {"flow_id": "INT-LOG-2", "final_class": "PORT SCAN", "assessment": "SUSPICIOUS", "risk_level": "MEDIUM", "confidence_level": "HIGH", "fusion_score": 0.35}
    flow_3 = {"flow_id": "INT-LOG-3", "final_class": "DDOS", "assessment": "MALICIOUS", "risk_level": "CRITICAL", "confidence_level": "HIGH", "fusion_score": 0.95}

    # Evaluate across different profiles
    engine.evaluate(flow_1, profile="CONSERVATIVE")
    engine.evaluate(flow_2, profile="STRICT")
    engine.evaluate(flow_3, profile="BALANCED")

    # Read back records from audit logger
    records = audit_logger.get_recent_records()
    assert len(records) == 3

    assert records[0]["flow_id"] == "INT-LOG-1"
    assert records[0]["policy_profile"] == "CONSERVATIVE"
    assert records[0]["action"] == "ALLOW"
    assert records[0]["fusion_score"] == 0.05

    assert records[1]["flow_id"] == "INT-LOG-2"
    assert records[1]["policy_profile"] == "STRICT"
    assert records[1]["action"] == "REVIEW"  # Suspicious medium escalated under STRICT
    assert records[1]["requires_human_review"] is True

    assert records[2]["flow_id"] == "INT-LOG-3"
    assert records[2]["policy_profile"] == "BALANCED"
    assert records[2]["action"] == "BLOCK"
    assert records[2]["simulated"] is True


# =============================================================================
# 20. Clear / Truncate Functionality
# =============================================================================
def test_clear_audit_log(audit_logger: PolicyAuditLogger):
    """Verify clearing the audit log empties records."""
    audit_logger.append_record({"flow_id": "CLR-1", "action": "ALLOW", "risk_level": "LOW", "confidence_level": "HIGH", "matched_rule": "R1", "decision_reason": "ok", "requires_human_review": False, "simulated": True})
    assert len(audit_logger.get_recent_records()) == 1

    audit_logger.clear()
    assert len(audit_logger.get_recent_records()) == 0

