#!/usr/bin/env python3
"""Quick validation script — tests every capability with visual pass/fail.

Run this after setting up your .env to verify everything works:

    python tests/quick_test.py

Pass your API key directly if you prefer not to use .env:

    RANSOMWARE_LIVE_PRO_KEY=your_key python tests/quick_test.py
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

# Ensure project is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console
from rich.table import Table

console = Console()

# Load .env if present
from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")


async def check(name: str, coro) -> tuple[str, bool, str]:
    """Run a check and return (name, passed, detail)."""
    try:
        result = await coro
        return (name, True, str(result)[:120])
    except Exception as exc:
        return (name, False, str(exc)[:120])


async def run_checks() -> list[tuple[str, bool, str]]:
    """Run all validation checks."""
    from mcp_server.config import settings

    results: list[tuple[str, bool, str]] = []

    # ---- Config checks ----
    results.append((
        "PRO API key configured",
        settings.has_pro_api,
        "Key is set" if settings.has_pro_api else "Set RANSOMWARE_LIVE_PRO_KEY in .env",
    ))

    ollama_available = False
    try:
        import ollama as ollama_client
        ollama_client.list()
        ollama_available = True
    except Exception:
        pass
    results.append((
        "Ollama available",
        ollama_available,
        "Running" if ollama_available else "Not running (keyword fallback will be used)",
    ))

    embed_available = False
    if ollama_available:
        try:
            import ollama as ollama_client
            models = ollama_client.list()
            model_names = [m.get("name", m.get("model", "")) for m in models.get("models", [])]
            embed_available = any("nomic-embed" in n for n in model_names)
        except Exception:
            pass
    results.append((
        "nomic-embed-text model",
        embed_available,
        "Pulled" if embed_available else "Run: ollama pull nomic-embed-text",
    ))

    # ---- Free API checks ----
    console.print("\n[bold]Testing Free API endpoints...[/bold]")

    from mcp_server.api.client import APIClient
    from mcp_server.api.free_api import FreeAPI

    try:
        async with APIClient() as client:
            free = FreeAPI(client)

            # Groups
            groups = await free.get_groups()
            results.append(("Free API: /groups", len(groups) > 0, f"{len(groups)} groups"))

            # Group profile
            profile = await free.get_group("lockbit3")
            results.append((
                "Free API: /group/lockbit3",
                profile is not None,
                profile.name if profile else "Not found",
            ))

            # Recent victims
            victims = await free.get_recent_victims()
            results.append(("Free API: /recentvictims", len(victims) > 0, f"{len(victims)} victims"))

            # Victim search
            search = await free.search_victims("bank")
            results.append(("Free API: /searchvictims", isinstance(search, list), f"{len(search)} results"))

            # YARA rules
            yara = await free.get_group_yara("lockbit3")
            results.append(("Free API: /yara/lockbit3", isinstance(yara, list), f"{len(yara)} rules"))

    except Exception as exc:
        results.append(("Free API connectivity", False, str(exc)[:120]))

    # ---- PRO API checks ----
    if settings.has_pro_api:
        console.print("[bold]Testing PRO API endpoints...[/bold]")

        from mcp_server.api.pro_api import ProAPI

        try:
            async with APIClient() as client:
                pro = ProAPI(client)

                # TTPs
                ttps = await pro.get_group_ttps("lockbit3")
                results.append(("PRO API: /ttps/lockbit3", len(ttps) > 0, f"{len(ttps)} TTPs"))

                # IOCs
                iocs = await pro.get_group_iocs("lockbit3")
                results.append(("PRO API: /iocs/lockbit3", isinstance(iocs, list), f"{len(iocs)} IOCs"))

                # Negotiations
                negotiations = await pro.get_negotiations("lockbit3")
                results.append((
                    "PRO API: /negotiations/lockbit3",
                    isinstance(negotiations, list),
                    f"{len(negotiations)} transcripts",
                ))

                # Ransom note text
                note = await pro.get_ransom_note_text("lockbit3")
                results.append((
                    "PRO API: /ransomnotestext/lockbit3",
                    len(note) > 0,
                    f"{len(note)} chars" if note else "Empty",
                ))

                # 8-K filings
                filings = await pro.get_8k_filings()
                results.append(("PRO API: /8k", isinstance(filings, list), f"{len(filings)} filings"))

        except Exception as exc:
            results.append(("PRO API connectivity", False, str(exc)[:120]))
    else:
        console.print("[dim]Skipping PRO API tests (no key)[/dim]")

    # ---- Tool checks ----
    console.print("[bold]Testing tools...[/bold]")

    # Keyword matching (always works)
    from mcp_server.embeddings.embed import keyword_match
    kw_result = keyword_match("LockBit 3.0 has encrypted your files")
    results.append((
        "Tool: keyword matching",
        len(kw_result) > 0 and kw_result[0][0] == "lockbit",
        f"Top match: {kw_result[0][0]} ({kw_result[0][1]:.0%})" if kw_result else "No matches",
    ))

    # TTP correlation (always works)
    from mcp_server.tools.ttp_correlation import map_observations_to_mitre
    mitre = map_observations_to_mitre([
        "RDP lateral movement", "vssadmin shadow copy deletion", "schtasks persistence",
    ])
    results.append((
        "Tool: MITRE mapping",
        len(mitre) >= 3,
        f"Mapped to {len(mitre)} techniques: {', '.join(mitre[:5])}",
    ))

    # Confidence scoring (always works)
    from mcp_server.models import RansomNoteMatch
    from mcp_server.scoring.confidence import calculate_confidence
    score = calculate_confidence(
        group_name="lockbit",
        note_matches=[RansomNoteMatch(group_name="lockbit", similarity_score=0.85)],
        file_extension=".lockbit",
    )
    results.append((
        "Tool: confidence scoring",
        score.total_score > 0,
        f"{score.confidence_pct}% ({score.confidence_label})",
    ))

    # Embedding match (requires Ollama)
    if embed_available:
        from mcp_server.tools.ransom_note import match_ransom_note
        try:
            matches = await match_ransom_note("LockBit 3.0 encrypted your files. Visit our TOR site.")
            results.append((
                "Tool: embedding match",
                len(matches) > 0,
                f"Top: {matches[0].group_name} ({matches[0].similarity_score:.0%})" if matches else "No matches",
            ))
        except Exception as exc:
            results.append(("Tool: embedding match", False, str(exc)[:80]))

    # Full pipeline (if PRO key available)
    if settings.has_pro_api:
        console.print("[bold]Testing full pipeline...[/bold]")
        try:
            from mcp_server.tools.ttp_correlation import correlate_ttps
            ttp_result = await correlate_ttps(
                observed_ttps=["RDP lateral movement", "vssadmin", "schtasks", "rclone"],
                candidate_groups=["lockbit3", "alphv", "blackbasta"],
            )
            top = ttp_result.get("top_match", "none")
            count = len(ttp_result.get("group_scores", []))
            results.append((
                "Tool: TTP correlation (live)",
                count > 0,
                f"Top match: {top}, {count} groups scored",
            ))
        except Exception as exc:
            results.append(("Tool: TTP correlation (live)", False, str(exc)[:80]))

    return results


def display_results(results: list[tuple[str, bool, str]]) -> int:
    """Display results table and return exit code."""
    table = Table(title="Ransomware Intelligence Agent — Validation Results")
    table.add_column("Check", style="bold", min_width=35)
    table.add_column("Status", justify="center", min_width=6)
    table.add_column("Detail", max_width=80)

    passed = 0
    failed = 0
    for name, ok, detail in results:
        status = "[green]PASS[/green]" if ok else "[red]FAIL[/red]"
        if ok:
            passed += 1
        else:
            failed += 1
        table.add_row(name, status, detail)

    console.print()
    console.print(table)
    console.print()
    console.print(
        f"[bold]{passed} passed[/bold], "
        f"[bold red]{failed} failed[/bold red]" if failed else f"[bold green]{passed} passed, 0 failed[/bold green]"
    )

    if failed:
        console.print("\n[yellow]Some checks failed. See the Detail column above for what to fix.[/yellow]")
    else:
        console.print("\n[green]All checks passed — you're ready to go![/green]")

    return 1 if failed else 0


def main() -> None:
    results = asyncio.run(run_checks())
    exit_code = display_results(results)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
