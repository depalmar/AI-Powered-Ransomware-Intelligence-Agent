#!/usr/bin/env python3
"""Demo walkthrough script for the SANS podcast demonstration.

Loads the simulated incident scenario and runs the full attribution
pipeline, showing each step of the analysis.

Usage:
    python demo/run_demo.py
    python demo/run_demo.py --format json
    python demo/run_demo.py --step-by-step
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from mcp_server.models import (
    HashArtifact,
    IOCType,
    IncidentArtifacts,
    LateralMovement,
    LateralMovementMethod,
    NetworkIOC,
    PersistenceMechanism,
    PersistenceType,
    RansomNoteArtifact,
    VictimInfo,
)

console = Console()

SCENARIO_PATH = Path(__file__).parent / "scenario.json"


def load_scenario() -> dict:
    """Load the simulated incident scenario."""
    with open(SCENARIO_PATH) as f:
        return json.load(f)


def parse_scenario(data: dict) -> IncidentArtifacts:
    """Parse the scenario JSON into an IncidentArtifacts model."""
    artifacts_data = data["artifacts"]

    # Parse hashes
    hashes = []
    for name, hash_val in artifacts_data["hashes"].items():
        clean = hash_val.replace("sha256:", "")
        hashes.append(HashArtifact(
            hash_type=IOCType.SHA256,
            value=clean,
            filename=name,
        ))

    # Parse network IOCs
    network_iocs = [
        NetworkIOC(
            ioc_type=IOCType.IP,
            value=ioc["value"],
            port=ioc.get("port"),
            note=ioc.get("note", ""),
        )
        for ioc in artifacts_data["network_iocs"]
    ]

    # Parse persistence
    persistence = [
        PersistenceMechanism(
            persistence_type=PersistenceType(p["type"]),
            name=p.get("name", ""),
            command=p.get("command", ""),
            path=p.get("path", ""),
            value=p.get("value", ""),
        )
        for p in artifacts_data["persistence"]
    ]

    # Parse lateral movement
    lateral_movement = [
        LateralMovement(
            method=LateralMovementMethod(lm["method"]),
            source=lm["source"],
            destination=lm["destination"],
            timestamp=datetime.fromisoformat(lm["timestamp"]) if lm.get("timestamp") else None,
        )
        for lm in artifacts_data["lateral_movement"]
    ]

    return IncidentArtifacts(
        incident_id=data["incident_id"],
        timestamp=datetime.fromisoformat(data["timestamp"]),
        victim=VictimInfo(
            company=data["victim"]["company"],
            sector=data["victim"]["sector"],
            size=data["victim"]["size"],
            geography=data["victim"]["geography"],
        ),
        ransom_note=RansomNoteArtifact(
            filename=artifacts_data["ransom_note"]["filename"],
            content=artifacts_data["ransom_note"]["content"],
        ),
        hashes=hashes,
        file_extension=artifacts_data["file_extension"],
        network_iocs=network_iocs,
        persistence=persistence,
        lateral_movement=lateral_movement,
        lolbas=artifacts_data["lolbas"],
    )


async def run_full_demo(output_format: str = "markdown") -> None:
    """Run the full attribution pipeline demo."""
    from mcp_server.tools.ir_brief import generate_ir_brief

    console.print(Panel(
        "[bold red]Ransomware Intelligence Agent — Live Demo[/bold red]\n"
        "[dim]SANS Podcast: Stay Ahead of Ransomware with Ryan Chapman[/dim]",
        title="Demo",
        border_style="red",
    ))
    console.print()

    # Load scenario
    console.print("[bold]Loading simulated incident...[/bold]")
    scenario = load_scenario()
    artifacts = parse_scenario(scenario)

    # Display incident overview
    _display_incident_overview(artifacts)
    console.print()

    # Run the pipeline
    console.print("[bold yellow]Running attribution pipeline...[/bold yellow]")
    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Generating intelligence brief...", total=None)
        result = await generate_ir_brief(artifacts, output_format)
        progress.update(task, completed=True)

    console.print()

    # Display the result
    if output_format == "json":
        console.print_json(json.dumps(
            result["brief_data"].model_dump(mode="json"),
            indent=2,
            default=str,
        ))
    else:
        brief_text = result["brief"]
        console.print(Markdown(brief_text))

    # Display confidence breakdown
    console.print()
    _display_confidence_breakdown(result["attribution"])


async def run_step_by_step() -> None:
    """Run each step individually with pauses for explanation."""
    from mcp_server.tools.ir_brief import generate_ir_brief
    from mcp_server.tools.ransom_note import match_ransom_note
    from mcp_server.tools.ttp_correlation import correlate_ttps

    console.print(Panel(
        "[bold red]Step-by-Step Demo[/bold red]",
        border_style="red",
    ))

    scenario = load_scenario()
    artifacts = parse_scenario(scenario)
    _display_incident_overview(artifacts)

    # Step 1: Ransom Note Matching
    console.print("\n[bold cyan]Step 1: Ransom Note Analysis[/bold cyan]")
    console.print("Comparing ransom note against known group notes...")
    matches = await match_ransom_note(artifacts.ransom_note.content)
    if matches:
        table = Table(title="Ransom Note Matches")
        table.add_column("Group", style="bold")
        table.add_column("Similarity", justify="right")
        table.add_column("Method")
        for m in matches:
            table.add_row(
                m.group_name,
                f"{m.similarity_score:.1%}",
                m.match_method,
            )
        console.print(table)
    else:
        console.print("[yellow]No matches found (Ollama may not be running)[/yellow]")
    console.print()

    # Step 2: TTP Correlation
    console.print("[bold cyan]Step 2: TTP Correlation[/bold cyan]")
    console.print("Mapping observed TTPs to MITRE ATT&CK...")
    observed_ttps = list(artifacts.lolbas)
    for lm in artifacts.lateral_movement:
        observed_ttps.append(f"{lm.method.value} lateral movement")
    ttp_result = await correlate_ttps(observed_ttps)

    if ttp_result["mitre_ids"]:
        console.print(f"Mapped to MITRE techniques: {', '.join(ttp_result['mitre_ids'])}")
    if ttp_result["group_scores"]:
        table = Table(title="TTP-Based Group Correlation")
        table.add_column("Group", style="bold")
        table.add_column("Score", justify="right")
        table.add_column("Overlap")
        for gs in ttp_result["group_scores"][:5]:
            table.add_row(
                gs["group"],
                f"{gs['score']:.1%}",
                f"{gs['overlap_count']}/{gs['total_observed']}",
            )
        console.print(table)
    console.print()

    # Step 3: Full Brief
    console.print("[bold cyan]Step 3: Full Intelligence Brief[/bold cyan]")
    console.print("Running complete attribution pipeline...")
    result = await generate_ir_brief(artifacts)
    console.print(Markdown(result["brief"]))


def _display_incident_overview(artifacts: IncidentArtifacts) -> None:
    """Display a summary of the incident artifacts."""
    table = Table(title=f"Incident: {artifacts.incident_id}")
    table.add_column("Artifact", style="bold")
    table.add_column("Value")

    table.add_row("Victim", artifacts.victim.company)
    table.add_row("Sector", artifacts.victim.sector)
    table.add_row("Geography", artifacts.victim.geography)
    table.add_row("Timestamp", str(artifacts.timestamp))
    table.add_row("Ransom Note", artifacts.ransom_note.filename if artifacts.ransom_note else "N/A")
    table.add_row("File Extension", artifacts.file_extension)
    table.add_row("Hashes", str(len(artifacts.hashes)))
    table.add_row("Network IOCs", str(len(artifacts.network_iocs)))
    table.add_row("Persistence Mechanisms", str(len(artifacts.persistence)))
    table.add_row("Lateral Movement Events", str(len(artifacts.lateral_movement)))
    table.add_row("LOLBAS Observed", str(len(artifacts.lolbas)))

    console.print(table)


def _display_confidence_breakdown(attribution) -> None:
    """Display the confidence score breakdown."""
    table = Table(title="Confidence Score Breakdown")
    table.add_column("Signal", style="bold")
    table.add_column("Weight", justify="right")
    table.add_column("Raw Score", justify="right")
    table.add_column("Weighted", justify="right")
    table.add_column("Detail")

    for signal in attribution.confidence.signals:
        table.add_row(
            signal.signal_name.replace("_", " ").title(),
            f"{signal.weight:.0%}",
            f"{signal.raw_score:.1%}",
            f"{signal.weighted_score:.3f}",
            signal.detail,
        )

    table.add_row(
        "[bold]TOTAL[/bold]",
        "[bold]100%[/bold]",
        "",
        f"[bold]{attribution.confidence.total_score:.3f}[/bold]",
        f"[bold]{attribution.confidence.confidence_label}[/bold]",
    )

    console.print(table)


def main() -> None:
    """Entry point for the demo script."""
    parser = argparse.ArgumentParser(description="Ransomware Intelligence Agent Demo")
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    parser.add_argument(
        "--step-by-step",
        action="store_true",
        help="Run each step individually with explanations",
    )
    args = parser.parse_args()

    if args.step_by_step:
        asyncio.run(run_step_by_step())
    else:
        asyncio.run(run_full_demo(args.format))


if __name__ == "__main__":
    main()
