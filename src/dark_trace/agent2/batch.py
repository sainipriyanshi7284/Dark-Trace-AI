"""Batch Anomaly Processing Module for Agent 2.

Provides resilient, high-throughput flow batch execution using the production
Agent 2 unsupervised Isolation Forest detector.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence
import time

from dark_trace.agent2.agent import Agent2
from dark_trace.agent2.schemas import Agent2Evidence


@dataclass
class BatchProcessingResult:
    """Aggregated outcome of batch anomaly inference."""

    total_flows: int = 0
    anomalous_flows: int = 0
    normal_flows: int = 0
    error_flows: int = 0
    results: List[Agent2Evidence] = field(default_factory=list)
    processing_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert batch processing summary to dictionary."""
        return {
            "total_flows": self.total_flows,
            "anomalous_flows": self.anomalous_flows,
            "normal_flows": self.normal_flows,
            "error_flows": self.error_flows,
            "processing_time_ms": self.processing_time_ms,
            "results": [r.to_dict() if hasattr(r, "to_dict") else r for r in self.results],
        }


class BatchAnomalyProcessor:
    """Processes sequential or streaming batches of network flows."""

    def __init__(self, agent: Optional[Agent2] = None):
        """Initialize batch processor with an Agent2 instance."""
        self.agent = agent or Agent2()

    def process_batch(self, flows: Sequence[Any]) -> BatchProcessingResult:
        """Execute anomaly analysis across a sequence of network flows.

        Args:
            flows: Sequence of network flows (NetworkFlowInput, NetworkFlow, or dicts).

        Returns:
            BatchProcessingResult: Aggregated summary and individual evidence items.
        """
        start = time.perf_counter()
        results: List[Agent2Evidence] = []
        anomalies = 0
        normal = 0
        errors = 0

        for f in flows:
            ev = self.agent.analyze_flow(f)
            results.append(ev)
            anom_dict = ev.anomaly_evidence if isinstance(ev.anomaly_evidence, dict) else {}
            is_anom = anom_dict.get("is_anomaly")
            if is_anom is True:
                anomalies += 1
            elif is_anom is False:
                normal += 1
            else:
                errors += 1

        elapsed = (time.perf_counter() - start) * 1000.0

        return BatchProcessingResult(
            total_flows=len(flows),
            anomalous_flows=anomalies,
            normal_flows=normal,
            error_flows=errors,
            results=results,
            processing_time_ms=round(elapsed, 2),
        )
