"""Base HTTP client for the ransomware.live API.

Provides rate limiting, retries, error handling, and shared HTTP session
management. Both free_api and pro_api modules build on this client.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from mcp_server.config import settings

logger = logging.getLogger("ransomware_intel.api")


class RateLimiter:
    """Simple token-bucket rate limiter for API calls."""

    def __init__(self, calls_per_second: float = 2.0) -> None:
        self._min_interval = 1.0 / calls_per_second
        self._last_call: float = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a request is allowed under the rate limit."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            if elapsed < self._min_interval:
                await asyncio.sleep(self._min_interval - elapsed)
            self._last_call = time.monotonic()


class APIClient:
    """Async HTTP client for ransomware.live with rate limiting and retries.

    Usage::

        async with APIClient() as client:
            data = await client.get("/groups")
    """

    def __init__(
        self,
        base_url: str | None = None,
        pro_key: str | None = None,
        timeout: float | None = None,
        max_retries: int | None = None,
    ) -> None:
        # Use explicit key if provided (even empty), otherwise fall back to config
        self.pro_key = pro_key if pro_key is not None else settings.ransomware_live_pro_key
        # Auto-select base URL: PRO API if key is available, otherwise free v2
        if base_url:
            self.base_url = base_url.rstrip("/")
        elif self.pro_key and self.pro_key not in ("your_pro_api_key_here",):
            self.base_url = settings.ransomware_live_pro_api_base.rstrip("/")
        else:
            self.base_url = settings.ransomware_live_api_base.rstrip("/")
        self.timeout = timeout or settings.api_timeout_seconds
        self.max_retries = max_retries if max_retries is not None else settings.api_max_retries
        self._rate_limiter = RateLimiter(settings.api_rate_limit_per_second)
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> APIClient:
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            headers=self._build_headers(),
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _build_headers(self) -> dict[str, str]:
        """Build request headers, including PRO API key if available."""
        headers = {
            "Accept": "application/json",
            "User-Agent": "ransomware-intel-agent/0.1.0",
        }
        # Only send the key if it's a real value, not a placeholder
        if self.pro_key and self.pro_key not in ("your_pro_api_key_here",):
            headers["X-API-KEY"] = self.pro_key
        return headers

    async def _ensure_client(self) -> httpx.AsyncClient:
        """Lazily create the HTTP client if not in a context manager."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
                headers=self._build_headers(),
                follow_redirects=True,
            )
        return self._client

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Make a GET request with rate limiting and retries.

        Args:
            path: API endpoint path (e.g. "/groups").
            params: Optional query parameters.

        Returns:
            Parsed JSON response body.

        Raises:
            APIError: If the request fails after all retries.
        """
        client = await self._ensure_client()
        last_error: Exception | None = None

        for attempt in range(self.max_retries + 1):
            await self._rate_limiter.acquire()
            try:
                response = await client.get(path, params=params)
                response.raise_for_status()
                content_type = response.headers.get("content-type", "")
                if "application/json" not in content_type:
                    logger.warning(
                        "Non-JSON response for %s (content-type: %s, url: %s)",
                        path, content_type, response.url,
                    )
                    raise APIError(
                        f"Expected JSON but got {content_type} for {path} "
                        f"(final url: {response.url})",
                    )
                return response.json()
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                # Don't retry client errors (except 429 rate limit)
                if status != 429 and 400 <= status < 500:
                    logger.warning("API client error %d for %s: %s", status, path, exc)
                    raise APIError(
                        f"API returned {status} for {path}", status_code=status
                    ) from exc
                last_error = exc
                logger.warning(
                    "API error %d for %s (attempt %d/%d)",
                    status, path, attempt + 1, self.max_retries + 1,
                )
            except (httpx.RequestError, httpx.TimeoutException) as exc:
                last_error = exc
                logger.warning(
                    "Request error for %s (attempt %d/%d): %s",
                    path, attempt + 1, self.max_retries + 1, exc,
                )

            # Exponential backoff before retry
            if attempt < self.max_retries:
                wait = 2 ** attempt
                logger.info("Retrying in %ds...", wait)
                await asyncio.sleep(wait)

        raise APIError(
            f"All {self.max_retries + 1} attempts failed for {path}"
        ) from last_error

    async def get_or_none(self, path: str, params: dict[str, Any] | None = None) -> Any | None:
        """Like get() but returns None on 404 instead of raising."""
        try:
            return await self.get(path, params=params)
        except APIError as exc:
            if exc.status_code == 404:
                return None
            raise

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None


class APIError(Exception):
    """Raised when an API request fails."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
