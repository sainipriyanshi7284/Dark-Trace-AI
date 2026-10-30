"""Threat intelligence trigger policy, private indicator filtering, and caching layer."""

from collections import OrderedDict
import time
from typing import Any, Dict, Optional, Tuple

from dark_trace.common.ip_utils import is_routable_public_indicator, is_valid_ip
from dark_trace.common.schemas import NetworkFlow


class ThreatIntelTriggerPolicy:
    """Evaluates whether a network flow qualifies for TinyFish external investigation.

    Safety & Quota Guardrails:
    1. Strictly rejects RFC 1918 / RFC 4193 / internal / private IPs.
    2. Enforces anomaly severity threshold (default >= 0.75) to preserve free-tier quota.
    3. Maintains an in-memory LRU cache with TTL to prevent redundant external queries.
    """

    def __init__(
        self,
        severity_threshold: float = 0.75,
        cache_ttl_seconds: int = 3600,
        cache_max_entries: int = 500,
    ):
        """Initialize the trigger policy.

        Args:
            severity_threshold: Minimum normalized anomaly score [0.0, 1.0] to trigger lookup.
            cache_ttl_seconds: Time-to-live for cached indicator investigations (seconds).
            cache_max_entries: Maximum number of indicators to hold in memory.
        """
        self.severity_threshold = max(0.0, min(1.0, float(severity_threshold)))
        self.cache_ttl = max(60, int(cache_ttl_seconds))
        self.cache_max_entries = max(10, int(cache_max_entries))
        # LRU cache mapping: indicator -> (timestamp, ThreatIntelligenceResult)
        self._cache: OrderedDict[str, Tuple[float, Any]] = OrderedDict()

    def get_cached_result(self, indicator: str) -> Optional[Any]:
        """Retrieve cached threat intelligence result if fresh."""
        clean = indicator.strip()
        if clean in self._cache:
            cached_time, result = self._cache[clean]
            if (time.time() - cached_time) < self.cache_ttl:
                # Move to end of OrderedDict for LRU tracking
                self._cache.move_to_end(clean)
                return result
            else:
                # Expired
                del self._cache[clean]
        return None

    def store_cached_result(self, indicator: str, result: Any) -> None:
        """Store an investigation result in the LRU cache."""
        clean = indicator.strip()
        if not clean:
            return

        if clean in self._cache:
            self._cache.move_to_end(clean)
        self._cache[clean] = (time.time(), result)

        # Evict oldest entry if exceeding capacity
        if len(self._cache) > self.cache_max_entries:
            self._cache.popitem(last=False)

    def evaluate_flow(
        self,
        flow: NetworkFlow,
        normalized_anomaly_score: float,
    ) -> Tuple[bool, str, Optional[str], str]:
        """Evaluate if the flow should trigger an external TinyFish investigation.

        Args:
            flow: The network flow being analyzed.
            normalized_anomaly_score: Bounded anomaly severity [0.0, 1.0].

        Returns:
            Tuple containing:
                - should_investigate (bool)
                - trigger_status (str: "TRIGGERED" | "CACHE_HIT" | "SKIPPED_PRIVATE_IP" | "SKIPPED_BELOW_THRESHOLD" | "NO_ELIGIBLE_INDICATOR")
                - candidate_indicator (Optional[str])
                - indicator_type (str: "PUBLIC_IP" | "NONE")
        """
        # Select external public indicator candidates (prioritize destination IP for outbound, source IP for inbound)
        candidate_ip: Optional[str] = None
        if is_valid_ip(flow.dst_ip) and is_routable_public_indicator(flow.dst_ip):
            candidate_ip = flow.dst_ip
        elif is_valid_ip(flow.src_ip) and is_routable_public_indicator(flow.src_ip):
            candidate_ip = flow.src_ip

        if not candidate_ip:
            # Check if IPs are private
            if is_valid_ip(flow.dst_ip) or is_valid_ip(flow.src_ip):
                return False, "SKIPPED_PRIVATE_IP", None, "NONE"
            return False, "NO_ELIGIBLE_INDICATOR", None, "NONE"

        # Check Cache
        cached = self.get_cached_result(candidate_ip)
        if cached is not None:
            return True, "CACHE_HIT", candidate_ip, "PUBLIC_IP"

        # Check Trigger conditions: manual force override OR severity threshold
        if flow.force_threat_intel or normalized_anomaly_score >= self.severity_threshold:
            return True, "TRIGGERED", candidate_ip, "PUBLIC_IP"

        return False, "SKIPPED_BELOW_THRESHOLD", candidate_ip, "PUBLIC_IP"
