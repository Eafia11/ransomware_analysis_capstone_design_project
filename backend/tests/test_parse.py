from pathlib import Path

from app.services.attack_chain_builder import (
    build_abstracted_attack_chains,
    build_attack_chain_candidates,
    filter_core_sysmon_events,
)
from app.services.normalizer import filter_events
from app.services.winlogbeat_parser import parse_winlogbeat_file


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_FILE = PROJECT_ROOT / "collector" / "sample_inputs" / "winlogbeat_sample-20260415.jsonl"


def test_parse_winlogbeat_sample_file():
    parsed = parse_winlogbeat_file(SAMPLE_FILE)

    assert len(parsed) == 697
    assert parsed[0]["timestamp"] <= parsed[-1]["timestamp"]


def test_build_attack_chain_candidates_from_sample():
    parsed = parse_winlogbeat_file(SAMPLE_FILE)
    sysmon_events = filter_events(
        parsed,
        channel="Microsoft-Windows-Sysmon/Operational",
    )
    sysmon_core = filter_core_sysmon_events(sysmon_events)
    attack_chains = build_attack_chain_candidates(sysmon_core)
    abstracted_chains = build_abstracted_attack_chains(attack_chains)

    assert len(sysmon_events) == 697
    assert len(sysmon_core) == 648
    assert len(attack_chains) == 124
    assert len(abstracted_chains) == len(attack_chains)
    assert "abstracted_actions" in abstracted_chains[0]
