"""Unit tests for TinyFish Threat Intelligence Client, trigger policies, and resilience."""

import json
from unittest.mock import MagicMock
import unittest
import urllib.error
import urllib.request

from dark_trace.agent2.threat_intel.client import (
    TinyFishAuthError,
    TinyFishClient,
    TinyFishError,
    TinyFishRateLimitError,
)
from dark_trace.agent2.threat_intel.investigator import ThreatIntelInvestigator
from dark_trace.agent2.threat_intel.triggers import ThreatIntelTriggerPolicy
from dark_trace.common.schemas import NetworkFlow, ThreatIntelligenceResult


class TestTinyFish(unittest.TestCase):
    """Test suite covering free-tier search/fetch, private IP guards, caching, and offline resilience."""

    def test_search_api_success(self):
        """Test successful Search API response parsing."""
        mock_response = {
            "results": [
                {
                    "title": "Threat Advisory: Mirai Scanner Variant",
                    "url": "https://threat-intel-example.org/advisories/mirai-2026",
                    "snippet": "IP 198.51.100.23 observed conducting automated Telnet and SSH brute force.",
                }
            ]
        }
        mock_http = MagicMock(return_value=mock_response)

        client = TinyFishClient(api_key="test_key_123", http_requester=mock_http)
        results = client.search(query="198.51.100.23 scanner")

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["title"], "Threat Advisory: Mirai Scanner Variant")
        self.assertIn("198.51.100.23", results[0]["snippet"])

    def test_fetch_api_success(self):
        """Test successful Fetch API response parsing."""
        mock_response = {
            "results": [
                {
                    "url": "https://threat-intel-example.org/cve/2026",
                    "title": "CVE Advisory",
                    "content": "# Critical Advisory\nRemote code execution detected in the wild.",
                }
            ]
        }
        mock_http = MagicMock(return_value=mock_response)

        client = TinyFishClient(api_key="test_key_123", http_requester=mock_http)
        pages = client.fetch(urls=["https://threat-intel-example.org/cve/2026"])

        self.assertEqual(len(pages), 1)
        self.assertEqual(pages[0]["title"], "CVE Advisory")
        self.assertIn("Remote code execution", pages[0]["content"])

    def test_auth_error_handling(self):
        """Test that HTTP 401/403 raises TinyFishAuthError."""
        def mock_auth_fail(req, timeout):
            raise urllib.error.HTTPError(
                url=req.get_full_url(),
                code=401,
                msg="Unauthorized",
                hdrs={},
                fp=None,
            )

        client = TinyFishClient(api_key="invalid_key", http_requester=mock_auth_fail)
        with self.assertRaises(TinyFishAuthError):
            client.search(query="malicious IP")

    def test_rate_limit_error_handling(self):
        """Test that HTTP 429 raises TinyFishRateLimitError."""
        def mock_rate_limit(req, timeout):
            raise urllib.error.HTTPError(
                url=req.get_full_url(),
                code=429,
                msg="Too Many Requests",
                hdrs={},
                fp=None,
            )

        client = TinyFishClient(api_key="test_key", http_requester=mock_rate_limit)
        with self.assertRaises(TinyFishRateLimitError):
            client.search(query="malicious IP")

    def test_private_ip_strictly_rejected(self):
        """Test that internal RFC 1918 private IPs are never queried externally."""
        mock_http = MagicMock()
        client = TinyFishClient(api_key="test_key", http_requester=mock_http)
        investigator = ThreatIntelInvestigator(client=client)

        private_flow = NetworkFlow(
            flow_id="f_internal",
            timestamp="2026-10-30T17:00:00Z",
            src_ip="10.0.0.15",
            dst_ip="192.168.1.50",  # Private destination IP
            src_port=50000,
            dst_port=80,
            protocol="TCP",
            features={"duration_ms": 100.0},
        )

        result = investigator.investigate_flow(private_flow, normalized_anomaly_score=0.95)
        self.assertEqual(result.investigation_status, "SKIPPED_PRIVATE_IP")
        self.assertEqual(len(result.findings), 0)
        # Verify no external HTTP requests were sent
        mock_http.assert_not_called()

    def test_severity_threshold_gate(self):
        """Test that flows below severity threshold are skipped to preserve quota."""
        mock_http = MagicMock()
        client = TinyFishClient(api_key="test_key", http_requester=mock_http)
        investigator = ThreatIntelInvestigator(client=client)

        public_flow = NetworkFlow(
            flow_id="f_public",
            timestamp="2026-10-30T17:00:00Z",
            src_ip="10.0.0.15",
            dst_ip="93.184.216.34",  # Public destination IP
            src_port=50000,
            dst_port=80,
            protocol="TCP",
            features={"duration_ms": 100.0},
        )

        # Score 0.40 is below threshold 0.75
        result = investigator.investigate_flow(public_flow, normalized_anomaly_score=0.40)
        self.assertEqual(result.investigation_status, "SKIPPED_BELOW_THRESHOLD")
        mock_http.assert_not_called()

        # Force threat intel override triggers investigation even if score is low
        public_flow.force_threat_intel = True
        mock_http.return_value = {"results": [{"title": "Forced Investigation", "url": "https://example.com"}]}
        result_forced = investigator.investigate_flow(public_flow, normalized_anomaly_score=0.40)
        self.assertEqual(result_forced.investigation_status, "COMPLETED")
        self.assertEqual(mock_http.call_count, 1)

    def test_caching_layer_prevents_redundant_queries(self):
        """Test that querying the same indicator within TTL hits cache."""
        mock_http = MagicMock()
        mock_http.return_value = {
            "results": [{"title": "Scanner Report", "url": "https://example.com", "snippet": "Known scanner"}]
        }
        client = TinyFishClient(api_key="test_key", http_requester=mock_http)
        policy = ThreatIntelTriggerPolicy(severity_threshold=0.75, cache_ttl_seconds=3600)
        investigator = ThreatIntelInvestigator(client=client, policy=policy)

        flow = NetworkFlow(
            flow_id="f1",
            timestamp="2026-10-30T17:00:00Z",
            src_ip="10.0.0.1",
            dst_ip="93.184.216.34",
            src_port=50000,
            dst_port=443,
            protocol="TCP",
            features={"duration_ms": 100.0},
        )

        # First call -> HTTP request made
        res1 = investigator.investigate_flow(flow, normalized_anomaly_score=0.90)
        self.assertEqual(res1.investigation_status, "COMPLETED")
        self.assertEqual(mock_http.call_count, 1)

        # Second call with same destination IP -> hits cache, no second HTTP request
        flow2 = NetworkFlow(
            flow_id="f2",
            timestamp="2026-10-30T17:01:00Z",
            src_ip="10.0.0.2",
            dst_ip="93.184.216.34",
            src_port=50001,
            dst_port=443,
            protocol="TCP",
            features={"duration_ms": 100.0},
        )
        res2 = investigator.investigate_flow(flow2, normalized_anomaly_score=0.85)
        self.assertEqual(res2.investigation_status, "COMPLETED")
        self.assertEqual(mock_http.call_count, 1)  # Still 1 call!

    def test_missing_api_key_graceful_degradation(self):
        """Test that unconfigured API key marks status UNAVAILABLE without error."""
        client = TinyFishClient(api_key="")  # Unconfigured
        investigator = ThreatIntelInvestigator(client=client)

        flow = NetworkFlow(
            flow_id="f_no_key",
            timestamp="2026-10-30T17:00:00Z",
            src_ip="10.0.0.1",
            dst_ip="93.184.216.34",
            src_port=50000,
            dst_port=443,
            protocol="TCP",
            features={"duration_ms": 100.0},
        )
        result = investigator.investigate_flow(flow, normalized_anomaly_score=0.95)
        self.assertEqual(result.investigation_status, "UNAVAILABLE")
        self.assertIn("not configured", result.error)


if __name__ == "__main__":
    unittest.main()
