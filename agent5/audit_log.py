"""Audit logging engine for Agent 5 Adaptive Defense.

Maintains an immutable, chronological audit trail recording:
  - Policy creation
  - Policy activation
  - Policy application (hits on later flows)
  - Policy expiry
  - Replay decisions (ALLOW / BLOCK)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PolicyAuditEvent:
    """Represents a single auditable policy lifecycle event."""
    timestamp: str
    event_type: str  # "POLICY_CREATED", "POLICY_ACTIVATED", "POLICY_APPLIED", "POLICY_EXPIRED", "REPLAY_DECISION"
    policy_id: Optional[str] = None
    record_id: Optional[str] = None
    seq: Optional[int] = None
    scope_type: Optional[str] = None
    scope_value: Optional[str] = None
    action: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert audit event to dictionary."""
        return asdict(self)


class DefenseAuditLogger:
    """Manages audit trail for Agent 5 Adaptive Defense operations."""

    def __init__(self) -> None:
        """Initialize in-memory audit log list."""
        self.events: List[PolicyAuditEvent] = []

    def log_event(
        self,
        event_type: str,
        policy_id: Optional[str] = None,
        record_id: Optional[str] = None,
        seq: Optional[int] = None,
        scope_type: Optional[str] = None,
        scope_value: Optional[str] = None,
        action: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> PolicyAuditEvent:
        """Record a structured audit event."""
        now_iso = datetime.now(timezone.utc).isoformat()
        evt = PolicyAuditEvent(
            timestamp=now_iso,
            event_type=event_type,
            policy_id=policy_id,
            record_id=record_id,
            seq=seq,
            scope_type=scope_type,
            scope_value=scope_value,
            action=action,
            details=details or {},
        )
        self.events.append(evt)
        logger.debug("Defense Audit Event: %s (policy=%s, record=%s)", event_type, policy_id, record_id)
        return evt

    def get_events(self, event_type: Optional[str] = None) -> List[PolicyAuditEvent]:
        """Retrieve recorded events, optionally filtered by event type."""
        if event_type is None:
            return list(self.events)
        return [e for e in self.events if e.event_type == event_type]

    def clear(self) -> None:
        """Clear all audit events."""
        self.events.clear()
