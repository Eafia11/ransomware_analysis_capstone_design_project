from app.services.attack_chain_builder import (
    build_attack_chain_candidates,
    filter_core_sysmon_events,
)
from app.services.ioc_extractor import extract_iocs_from_analysis
from app.services.mitre_mapper import map_chain_to_mitre
from app.services.normalizer import filter_events, normalize_winlogbeat_event


def test_normalize_top_level_sysmon_file_create_fields_feed_ioc_and_mitre():
    raw_events = [
        {
            "EventID": 1,
            "TimeCreated": r"\/Date(1780056290428)\/",
            "RecordId": 1,
            "Provider": "Microsoft-Windows-Sysmon",
            "MachineName": "DESKTOP-H6FBQ5J",
            "ProcessGuid": "{PROCESS-GUID}",
            "ProcessId": "4321",
            "Image": r"C:\Users\Public\encryptor.exe",
            "CommandLine": "encryptor.exe",
            "User": r"DESKTOP-H6FBQ5J\windows",
        },
        {
            "EventID": 11,
            "TimeCreated": r"\/Date(1780056291428)\/",
            "RecordId": 2,
            "Provider": "Microsoft-Windows-Sysmon",
            "MachineName": "DESKTOP-H6FBQ5J",
            "ProcessGuid": "{PROCESS-GUID}",
            "ProcessId": "4321",
            "Image": r"C:\Users\Public\encryptor.exe",
            "TargetFilename": r"C:\Users\victim\Documents\budget.xlsx.locked",
        },
    ]

    parsed_events = [normalize_winlogbeat_event(event) for event in raw_events]
    sysmon_events = filter_events(parsed_events, channel="Microsoft-Windows-Sysmon/Operational")
    attack_chains = build_attack_chain_candidates(filter_core_sysmon_events(sysmon_events))
    iocs = extract_iocs_from_analysis(parsed_events, attack_chains)
    mitre = map_chain_to_mitre(attack_chains[0])

    assert parsed_events[1]["event_id"] == "11"
    assert parsed_events[1]["target_filename"] == r"C:\Users\victim\Documents\budget.xlsx.locked"
    assert r"C:\Users\victim\Documents\budget.xlsx.locked" in iocs["file_paths"]
    assert ".locked" in iocs["encrypted_extensions"]
    assert any(item["technique_id"] == "T1486" for item in mitre)


def test_normalize_sysmon_file_create_accepts_event_data_key_variants():
    raw_event = {
        "event_id": 11,
        "provider_name": "Microsoft-Windows-Sysmon",
        "event_data": {
            "ProcessGuid": "{PROCESS-GUID}",
            "Image": r"C:\Users\Public\payload.exe",
            "target_filename": r"C:\Users\victim\Desktop\HOW_TO_DECRYPT.txt",
        },
    }

    event = normalize_winlogbeat_event(raw_event)

    assert event["channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert event["event_type_name"] == "FileCreate"
    assert event["target_filename"] == r"C:\Users\victim\Desktop\HOW_TO_DECRYPT.txt"
