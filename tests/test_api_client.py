"""Tests for the ransomware.live API client layer."""

from __future__ import annotations

import pytest

from mcp_server.api.client import APIClient, APIError, RateLimiter


class TestRateLimiter:
    """Tests for the rate limiter."""

    @pytest.mark.asyncio
    async def test_rate_limiter_allows_first_call(self):
        limiter = RateLimiter(calls_per_second=10.0)
        # First call should not block
        await limiter.acquire()

    @pytest.mark.asyncio
    async def test_rate_limiter_spacing(self):
        import time
        limiter = RateLimiter(calls_per_second=100.0)
        start = time.monotonic()
        await limiter.acquire()
        await limiter.acquire()
        elapsed = time.monotonic() - start
        # Should have some small delay, but not too much at 100/s
        assert elapsed < 1.0


class TestAPIClient:
    """Tests for the base API client."""

    def test_client_initializes_with_defaults(self):
        client = APIClient()
        assert client.base_url
        assert client.max_retries >= 0
        assert client.timeout > 0

    def test_client_accepts_custom_config(self):
        client = APIClient(
            base_url="https://test.example.com",
            pro_key="test-key",
            timeout=60.0,
            max_retries=5,
        )
        assert client.base_url == "https://test.example.com"
        assert client.pro_key == "test-key"
        assert client.timeout == 60.0
        assert client.max_retries == 5

    def test_build_headers_without_key(self):
        client = APIClient(pro_key="")
        headers = client._build_headers()
        assert "api-key" not in headers
        assert headers["Accept"] == "application/json"

    def test_build_headers_with_key(self):
        client = APIClient(pro_key="my-pro-key")
        headers = client._build_headers()
        assert headers["api-key"] == "my-pro-key"


class TestAPIError:
    """Tests for the APIError exception."""

    def test_api_error_with_status(self):
        err = APIError("Not Found", status_code=404)
        assert err.status_code == 404
        assert "Not Found" in str(err)

    def test_api_error_without_status(self):
        err = APIError("Something went wrong")
        assert err.status_code is None
