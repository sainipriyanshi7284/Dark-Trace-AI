"""Threat intelligence investigator coordinating TinyFish Search & Fetch APIs."""

from datetime import datetime, timezone
import os
from typing import Any, Dict, List, Optional

from dark_trace.agent2.threat_intel.client import (
    TinyFishAuthError,
    TinyFishClient,
    TinyFishError,
    TinyFishRateLimitError,
)
from dark_trace.agent2.threat_intel.triggers import ThreatIntelTriggerPolicy
from dark_trace.common.schemas import NetworkFlow, ThreatIntelligenceResult


class ThreatIntelInvestigator:
    """Investigates selected network indicators using TinyFish Free-Tier Search & Fetch.

    Ensures ML anomaly detection proceeds uninterrupted regardless of external API status.
    """

    def __init__(
        self,
        client: Optional[TinyFishClient] = None,
        policy: Optional[ThreatIntelTriggerPolicy] = None,
    ):
        """Initialize investigator.

        Args:
            client: TinyFishClient instance. If omitted, initialized with env configuration.
            policy: ThreatIntelTriggerPolicy instance. If omitted, uses standard defaults.
        """
        self.client = client or TinyFishClient()
        self.policy = policy or ThreatIntelTriggerPolicy()

    def investigate_flow(
        self,
        flow: NetworkFlow,
        normalized_anomaly_score: float,
    ) -> ThreatIntelligenceResult:
        """Evaluate flow and optionally query TinyFish external threat intelligence.

        Args:
            flow: NetworkFlow record.
            normalized_anomaly_score: Calculated anomaly severity index [0.0, 1.0].

        Returns:
            ThreatIntelligenceResult: Fully populated threat intelligence evidence block.
        """
        should_run, status, indicator, ind_type = self.policy.evaluate_flow(
            flow=flow,
            normalized_anomaly_score=normalized_anomaly_score,
        )

        if not should_run:
            return ThreatIntelligenceResult(
                provider="tinyfish",
                investigation_status=status,
                indicator=indicator,
                indicator_type=ind_type,
            )

        if status == "CACHE_HIT" and indicator:
            cached = self.policy.get_cached_result(indicator)
            if cached is not None:
                return cached

        # Check API key readiness
        if not self.client.is_configured:
            return ThreatIntelligenceResult(
                provider="tinyfish",
                investigation_status="UNAVAILABLE",
                indicator=indicator,
                indicator_type=ind_type,
                error="TINYFISH_API_KEY environment variable is not configured",
            )

        # Execute investigation via Free-Tier Search API
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            query = f"{indicator} malicious scanner attack CVE"
            search_items = self.client.search(query=query, limit=3)

            findings: List[str] = []
            sources: List[Dict[str, str]] = []

            for item in search_items:
                title = item.get("title", "Threat Intelligence Source")
                url = item.get("url", "")
                snippet = item.get("snippet", "").strip()

                if url:
                    sources.append({"title": title, "url": url})
                if snippet:
                    findings.append(f"[{title}] {snippet[:250]}")
                elif title:
                    findings.append(f"Reported in: {title}")

            if not findings:
                findings.append(f"No active external abuse or CVE reports matched indicator '{indicator}'.")

            result = ThreatIntelligenceResult(
                provider="tinyfish",
                investigation_status="COMPLETED",
                indicator=indicator,
                indicator_type=ind_type,
                findings=findings,
                sources=sources,
                investigated_at=now_iso,
                error=None,
            )

            # Store in cache
            if indicator:
                self.policy.store_cached_result(indicator, result)

            return result

        except TinyFishRateLimitError as err:
            return ThreatIntelligenceResult(
                provider="tinyfish",
                investigation_status="RATE_LIMITED",
                indicator=indicator,
                indicator_type=ind_type,
                error=str(err),
                investigated_at=now_iso,
            )
        except TinyFishAuthError as err:
            return ThreatIntelligenceResult(
                provider="tinyfish",
                investigation_status="UNAVAILABLE",
                indicator=indicator,
                indicator_type=ind_type,
                error=str(err),
                investigated_at=now_iso,
            )
        except Exception as err:
            return ThreatIntelligenceResult(
                provider="tinyfish",
                investigation_status="FAILED",
                indicator=indicator,
                indicator_type=ind_type,
                error=f"Investigation failed: {err}",
                investigated_at=now_iso,
            )
