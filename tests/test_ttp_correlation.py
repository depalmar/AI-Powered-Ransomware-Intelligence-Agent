"""Tests for TTP correlation logic."""

from __future__ import annotations

import pytest

from mcp_server.tools.ttp_correlation import (
    OBSERVATION_TO_MITRE,
    map_observations_to_mitre,
)


class TestObservationToMitre:
    """Tests for mapping forensic observations to MITRE technique IDs."""

    def test_rdp_maps_correctly(self):
        result = map_observations_to_mitre(["RDP lateral movement"])
        assert "T1021.001" in result

    def test_psexec_maps_correctly(self):
        result = map_observations_to_mitre(["PsExec execution"])
        assert "T1021.002" in result

    def test_vssadmin_maps_correctly(self):
        result = map_observations_to_mitre(["vssadmin shadow copy deletion"])
        assert "T1490" in result

    def test_schtasks_maps_correctly(self):
        result = map_observations_to_mitre(["schtasks persistence"])
        assert "T1053.005" in result

    def test_rclone_maps_correctly(self):
        result = map_observations_to_mitre(["rclone data exfiltration"])
        assert "T1567.002" in result

    def test_powershell_maps_correctly(self):
        result = map_observations_to_mitre(["powershell encoded command"])
        assert "T1059.001" in result

    def test_direct_technique_id_passthrough(self):
        result = map_observations_to_mitre(["T1486"])
        assert "T1486" in result

    def test_subtechnique_passthrough(self):
        result = map_observations_to_mitre(["T1021.001"])
        assert "T1021.001" in result

    def test_multiple_observations(self):
        result = map_observations_to_mitre([
            "RDP lateral movement",
            "vssadmin shadow copy deletion",
            "schtasks persistence",
        ])
        assert "T1021.001" in result
        assert "T1490" in result
        assert "T1053.005" in result

    def test_empty_list(self):
        result = map_observations_to_mitre([])
        assert result == []

    def test_unrecognized_observation(self):
        result = map_observations_to_mitre(["completely unknown technique xyz"])
        # Should return empty or only match partial keywords
        assert isinstance(result, list)

    def test_results_are_sorted(self):
        result = map_observations_to_mitre([
            "vssadmin", "rdp", "powershell", "schtasks",
        ])
        assert result == sorted(result)

    def test_results_are_unique(self):
        result = map_observations_to_mitre([
            "vssadmin shadow copy deletion",
            "vssadmin delete shadows",
            "bcdedit recovery disabled",
        ])
        # T1490 should appear only once despite multiple observations mapping to it
        assert len(result) == len(set(result))

    def test_case_insensitive(self):
        result = map_observations_to_mitre(["RDP", "rdp", "Rdp"])
        assert "T1021.001" in result


class TestObservationMapping:
    """Tests for the observation lookup table."""

    def test_lookup_table_has_entries(self):
        assert len(OBSERVATION_TO_MITRE) > 0

    def test_all_values_are_valid_technique_ids(self):
        import re
        for key, techniques in OBSERVATION_TO_MITRE.items():
            for tid in techniques:
                assert re.match(r"T\d{4}(\.\d{3})?", tid), (
                    f"Invalid technique ID '{tid}' for key '{key}'"
                )
