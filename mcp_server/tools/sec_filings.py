"""get_8k_filings tool — pulls SEC cybersecurity incident disclosures.

Queries the ransomware.live PRO API for 8-K filings with optional
ticker/CIK filtering.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp_server.api.client import APIClient
from mcp_server.api.pro_api import ProAPI
from mcp_server.models import SECFiling

logger = logging.getLogger("ransomware_intel.tools.sec_filings")


async def get_8k_filings(
    ticker: str | None = None,
    cik: str | None = None,
) -> dict[str, Any]:
    """Get SEC cybersecurity 8-K incident disclosures.

    Queries the PRO API for SEC filings related to cybersecurity
    incidents. Supports filtering by stock ticker or CIK number.

    Args:
        ticker: Stock ticker symbol (e.g. "MSFT", "AAPL").
        cik: SEC Central Index Key number.

    Returns:
        Dict with:
            - filings: list of SECFiling objects
            - total_count: number of results
            - available: whether PRO API data was accessible
    """
    async with APIClient() as client:
        pro = ProAPI(client)
        filings = await pro.get_8k_filings(ticker=ticker, cik=cik)

    if not filings:
        filter_desc = ""
        if ticker:
            filter_desc = f" for ticker {ticker}"
        elif cik:
            filter_desc = f" for CIK {cik}"

        logger.info("No 8-K filings found%s", filter_desc)
        return {
            "filings": [],
            "total_count": 0,
            "available": False,
        }

    return {
        "filings": filings,
        "total_count": len(filings),
        "available": True,
    }
