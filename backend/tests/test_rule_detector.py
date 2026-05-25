from app.services.rule_detector import (
    classify_chain,
    detect_malicious_chains,
    filter_suspicious_results,
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
