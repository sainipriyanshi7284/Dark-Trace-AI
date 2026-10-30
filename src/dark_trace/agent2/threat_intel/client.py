"""TinyFish Threat Intelligence API client restricted to Free-Tier Search & Fetch.

MANDATORY FREE-TIER GOVERNANCE:
- Permitted: Search API and Fetch API only.
- Strictly Forbidden: Agent API, Browser API, and any paid metered endpoints.
- Free Tier Limits:
  - Search: 30 requests/minute, 500 requests/hour.
  - Fetch: 150 URLs/minute, 1,000 URLs/day.
"""

from collections import deque
import json
import os
import time
from typing import Any, Callable, Dict, List, Optional
import urllib.error
import urllib.request


class TinyFishError(Exception):
    """Base exception for TinyFish API client errors."""


class TinyFishAuthError(TinyFishError):
    """Raised when authentication fails (HTTP 401 / 403)."""


class TinyFishRateLimitError(TinyFishError):
    """Raised when the free-tier rate limit is exceeded (HTTP 429)."""


class TinyFishClient:
    """Client for TinyFish's Search and Fetch APIs compliant with Free-Tier rules."""

    # Default endpoints
    DEFAULT_BASE_URL = "https://api.tinyfish.ai/v1"

    # Free tier rate limits: max 30 search requests per 60 seconds
    MAX_SEARCH_PER_MINUTE = 30
    WINDOW_SECONDS = 60.0

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 5.0,
        max_retries: int = 1,
        http_requester: Optional[Callable[[urllib.request.Request, float], Dict[str, Any]]] = None,
    ):
        """Initialize the TinyFish client.

        Args:
            api_key: TinyFish API key. If omitted, reads from TINYFISH_API_KEY env var.
            base_url: Base URL for TinyFish REST endpoints.
            timeout: Request timeout in seconds.
            max_retries: Number of retry attempts on transient network timeouts.
            http_requester: Optional custom HTTP request handler (used for test mocking).
        """
        self._api_key = api_key or os.environ.get("TINYFISH_API_KEY", "").strip()
        self.base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self.timeout = max(1.0, float(timeout))
        self.max_retries = max(0, int(max_retries))
        self._http_requester = http_requester or self._default_http_request
        self._request_history: deque = deque()

    @property
    def is_configured(self) -> bool:
        """Return True if an API key is available."""
        return bool(self._api_key)

    def _check_local_rate_limit(self) -> None:
        """Enforce the 30 requests/minute free-tier ceiling locally."""
        now = time.time()
        while self._request_history and (now - self._request_history[0]) > self.WINDOW_SECONDS:
            self._request_history.popleft()

        if len(self._request_history) >= self.MAX_SEARCH_PER_MINUTE:
            oldest = self._request_history[0]
            wait_time = round(self.WINDOW_SECONDS - (now - oldest), 1)
            raise TinyFishRateLimitError(
                f"TinyFish free-tier rate limit reached (30 req/min). "
                f"Please wait {wait_time}s before sending additional requests."
            )

        self._request_history.append(now)

    def _default_http_request(
        self, request: urllib.request.Request, timeout: float
    ) -> Dict[str, Any]:
        """Perform standard HTTP POST/GET request using urllib.request."""
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status_code = response.getcode()
                body = response.read().decode("utf-8")
                try:
                    return json.loads(body)
                except json.JSONDecodeError:
                    return {"raw_content": body, "status": status_code}
        except urllib.error.HTTPError as err:
            if err.code in (401, 403):
                raise TinyFishAuthError(f"TinyFish authentication error ({err.code}): Invalid or inactive API key.")
            elif err.code == 429:
                raise TinyFishRateLimitError("TinyFish rate limit exceeded (HTTP 429).")
            else:
                body_snippet = err.read().decode("utf-8", errors="replace")[:200]
                raise TinyFishError(f"TinyFish HTTP error ({err.code}): {body_snippet}")
        except (urllib.error.URLError, TimeoutError) as err:
            raise TinyFishError(f"TinyFish network connection error: {err}")

    def _send_request(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute request with retries and authentication headers."""
        if not self._api_key:
            raise TinyFishAuthError(
                "TINYFISH_API_KEY is not configured. Set the TINYFISH_API_KEY environment variable."
            )

        self._check_local_rate_limit()

        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url=url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
                "User-Agent": "DarkTrace-AI/1.0 (Cybersecurity-Anomaly-Agent)",
            },
            method="POST",
        )

        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                return self._http_requester(req, self.timeout)
            except (TinyFishAuthError, TinyFishRateLimitError):
                # Do not retry auth or rate-limit rejections
                raise
            except urllib.error.HTTPError as err:
                if err.code in (401, 403):
                    raise TinyFishAuthError(f"TinyFish authentication error ({err.code}): Invalid API key.")
                elif err.code == 429:
                    raise TinyFishRateLimitError("TinyFish rate limit exceeded (HTTP 429).")
                else:
                    raise TinyFishError(f"TinyFish HTTP error ({err.code})")
            except Exception as err:
                last_error = err
                if attempt < self.max_retries:
                    time.sleep(0.5 * (attempt + 1))

        raise TinyFishError(f"TinyFish request failed after {self.max_retries + 1} attempts: {last_error}")

    def search(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Query live threat intelligence reports via TinyFish Search API (Free Tier).

        Args:
            query: Threat query string (e.g. '198.51.100.23 malware scanning CVE').
            limit: Maximum search results to retrieve (1 to 10).

        Returns:
            List[Dict[str, Any]]: Search results with title, url, snippet/content.
        """
        clean_query = str(query).strip()
        if not clean_query:
            return []

        payload = {
            "query": clean_query,
            "limit": max(1, min(10, int(limit))),
        }

        response = self._send_request("search", payload)
        # Parse standardized results list
        results = response.get("results", [])
        formatted = []
        for item in results:
            if isinstance(item, dict):
                formatted.append(
                    {
                        "title": str(item.get("title", "Threat Report")),
                        "url": str(item.get("url", "")),
                        "snippet": str(item.get("snippet", item.get("content", ""))),
                    }
                )
        return formatted

    def fetch(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Retrieve clean structured content from threat URLs via TinyFish Fetch API (Free Tier).

        Args:
            urls: Target URLs of security advisories or blocklists to inspect.

        Returns:
            List[Dict[str, Any]]: Clean markdown/text content per URL.
        """
        valid_urls = [str(u).strip() for u in urls if str(u).strip().startswith(("http://", "https://"))]
        if not valid_urls:
            return []

        payload = {"urls": valid_urls[:5]}  # Free-tier limit per request
        response = self._send_request("fetch", payload)

        pages = response.get("results", response.get("pages", []))
        formatted = []
        for item in pages:
            if isinstance(item, dict):
                formatted.append(
                    {
                        "url": str(item.get("url", "")),
                        "content": str(item.get("content", item.get("text", ""))),
                        "title": str(item.get("title", "")),
                    }
                )
        return formatted
