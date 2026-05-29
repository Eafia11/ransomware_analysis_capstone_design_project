from app.services.report_service import calculate_risk_level


def test_many_generic_iocs_without_suspicious_chain_stays_low():
    iocs = {
        "ips": [f"8.8.8.{idx}" for idx in range(20)],
        "domains": [f"example{idx}.com" for idx in range(20)],
        "urls": [f"http://example.com/{idx}" for idx in range(20)],
        "hashes": ["a" * 64],
        "file_paths": [rf"C:\Windows\System32\file{idx}.dll" for idx in range(200)],
        "registry_keys": [],
        "ransom_notes": [],
        "encrypted_extensions": [],
        "suspicious_file_names": [],
        "bitcoin_addresses": [],
        "email_addresses": [],
    }

    assert calculate_risk_level([], iocs) == "low"


def test_ransomware_iocs_without_suspicious_chain_raise_to_medium_not_high():
    iocs = {
        "ransom_notes": ["HOW_TO_DECRYPT.txt"],
        "encrypted_extensions": [".locked"],
        "suspicious_file_names": [],
        "bitcoin_addresses": [],
    }

    assert calculate_risk_level([], iocs) == "medium"


def test_high_rule_score_with_ransomware_ioc_is_high():
    suspicious_results = [{"score": 9, "label": "suspicious"}]
    iocs = {
        "ransom_notes": ["HOW_TO_DECRYPT.txt"],
        "encrypted_extensions": [],
        "suspicious_file_names": [],
        "bitcoin_addresses": [],
    }

    assert calculate_risk_level(suspicious_results, iocs) == "high"
