from __future__ import annotations
import re
from typing import Any

IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|top|xyz|info|biz|onion)\b'
)

HASH_PATTERN = re.compile(
    r'\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b'
)

REGISTRY_PATTERN = re.compile(
    r'(HKEY_[A-Z_]+|HKLM|HKCU|HKU|HKCR)\\[^\s\'"]+',
    re.IGNORECASE
)

BITCOIN_PATTERN = re.compile(
    r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
)

ENCRYPTED_EXT_PATTERN = re.compile(
    r'\b\w+\.(locked|enc|crypt|ransom|crypted|pay|aes|encrypted)\b',
    re.IGNORECASE
)

RANSOM_NOTE_PATTERN = re.compile(
    r'\b(readme\.txt|how_to_decrypt|recover_files|!!!readme|decrypt_instruction|your_files_are_encrypted)\b',
    re.IGNORECASE
)


def extract_iocs(actions: list[dict[str, Any]]) -> dict[str, list[str]]:
    ips = set()
    domains = set()
    hashes = set()
    registry_keys = set()
    bitcoin_addresses = set()
    encrypted_files = set()
    ransom_notes = set()

    for action in actions:
        texts = [
            action.get("image") or "",
            action.get("command_line") or "",
            action.get("destination_ip") or "",
            action.get("destination_hostname") or "",
            action.get("target_filename") or "",
            action.get("registry_key") or "",
            action.get("parent_image") or "",
            action.get("network_dest") or "",
        ]
        combined = " ".join(texts)

        for ip in IP_PATTERN.findall(combined):
            if not ip.startswith(("127.", "192.168.", "10.", "172.")):
                ips.add(ip)

        for domain in DOMAIN_PATTERN.findall(combined):
            domains.add(domain)

        for hash_val in HASH_PATTERN.findall(combined):
            hashes.add(hash_val)

        for reg in REGISTRY_PATTERN.findall(combined):
            registry_keys.add(reg if isinstance(reg, str) else reg[0])

        for btc in BITCOIN_PATTERN.findall(combined):
            bitcoin_addresses.add(btc)

        for ext in ENCRYPTED_EXT_PATTERN.findall(combined):
            encrypted_files.add(ext)

        for note in RANSOM_NOTE_PATTERN.findall(combined):
            ransom_notes.add(note)

    return {
        "ips": list(ips),
        "domains": list(domains),
        "hashes": list(hashes),
        "registry_keys": list(registry_keys),
        "bitcoin_addresses": list(bitcoin_addresses),
        "encrypted_files": list(encrypted_files),
        "ransom_notes": list(ransom_notes),
    }


def extract_iocs_from_chain(chain: dict[str, Any]) -> dict[str, Any]:
    actions = chain.get("actions", [])
    iocs = extract_iocs(actions)

    return {
        "process_guid": chain.get("process_guid"),
        "image": chain.get("image"),
        "iocs": iocs,
        "ioc_count": sum(len(v) for v in iocs.values()),
    }