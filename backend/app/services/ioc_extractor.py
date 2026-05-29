from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse


IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
URL_PATTERN = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|top|xyz|info|biz|co|kr|dev|site|online)\b",
    re.IGNORECASE,
)
HASH_PATTERN = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
BITCOIN_PATTERN = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
WINDOWS_PATH_PATTERN = re.compile(
    r"\b[A-Za-z]:\\(?:[^\s\\/:*?\"<>|\r\n]+\\)*[^\s\\/:*?\"<>|\r\n]*"
)
REGISTRY_PATTERN = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|"
    r"HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[^\s\"']+",
    re.IGNORECASE,
)
RANSOM_NOTE_PATTERN = re.compile(
    r"\b(?:README_RESTORE|HOW_TO_DECRYPT|RECOVER_FILES|DECRYPT_INSTRUCTION|"
    r"YOUR_FILES_ARE_ENCRYPTED|RESTORE_FILES|READ_ME|README_FOR_DECRYPT)"
    r"(?:\.[A-Za-z0-9]+)?\b",
    re.IGNORECASE,
)
ENCRYPTED_EXTENSION_PATTERN = re.compile(
    r"\.[A-Za-z0-9_-]*?(locked|encrypted|crypted|crypt|enc|ransom|pay|aes)\b",
    re.IGNORECASE,
)
SUSPICIOUS_FILE_NAME_PATTERN = re.compile(
    r"\b(?:ransom|decrypt|encryptor|locker|dropper|payload|mimikatz|"
    r"procdump|shadowcopy|vssadmin|bitsadmin|certutil)\.[A-Za-z0-9]{1,8}\b",
    re.IGNORECASE,
)

TEXT_FIELDS = [
    "message",
    "image",
    "command_line",
    "parent_image",
    "parent_command_line",
    "target_filename",
    "target_object",
    "details",
    "destination_ip",
    "destination_hostname",
    "hashes",
    "script_block_text",
]


def extract_iocs_from_events(events: list[dict[str, Any]]) -> dict[str, list[str]]:
    accumulator = _empty_ioc_sets()

    for event in events:
        _extract_from_texts(_collect_texts(event), accumulator)

    return _finalize_iocs(accumulator)


def extract_iocs_from_chains(chains: list[dict[str, Any]]) -> dict[str, list[str]]:
    accumulator = _empty_ioc_sets()

    for chain in chains:
        _extract_from_texts(_collect_texts(chain), accumulator)
        for action in chain.get("actions", []):
            _extract_from_texts(_collect_texts(action), accumulator)

    return _finalize_iocs(accumulator)


def extract_iocs_from_analysis(
    parsed_events: list[dict[str, Any]],
    attack_chains: list[dict[str, Any]],
) -> dict[str, list[str]]:
    accumulator = _empty_ioc_sets()

    for iocs in [
        extract_iocs_from_events(parsed_events),
        extract_iocs_from_chains(attack_chains),
    ]:
        for key, values in iocs.items():
            accumulator[key].update(values)

    return _finalize_iocs(accumulator)


def summarize_iocs(iocs: dict[str, list[str]]) -> dict[str, int]:
    return {key: len(values) for key, values in iocs.items()}


def _empty_ioc_sets() -> dict[str, set[str]]:
    return {
        "ips": set(),
        "domains": set(),
        "urls": set(),
        "hashes": set(),
        "file_paths": set(),
        "registry_keys": set(),
        "ransom_notes": set(),
        "encrypted_extensions": set(),
        "suspicious_file_names": set(),
        "bitcoin_addresses": set(),
        "email_addresses": set(),
    }


def _collect_texts(item: dict[str, Any]) -> list[str]:
    texts = []

    for field in TEXT_FIELDS:
        value = item.get(field)
        if value is not None:
            texts.append(str(value))

    raw_event_data = item.get("raw_event_data")
    if isinstance(raw_event_data, dict):
        texts.extend(str(value) for value in raw_event_data.values() if value is not None)

    return texts


def _extract_from_texts(texts: list[str], accumulator: dict[str, set[str]]) -> None:
    combined = " ".join(texts)

    for url in URL_PATTERN.findall(combined):
        cleaned_url = _clean_token(url)
        accumulator["urls"].add(cleaned_url)
        parsed_url = urlparse(cleaned_url)
        if parsed_url.hostname:
            accumulator["domains"].add(parsed_url.hostname.lower())

    for ip in IP_PATTERN.findall(combined):
        if not _is_noise_ip(ip):
            accumulator["ips"].add(ip)

    for domain in DOMAIN_PATTERN.findall(combined):
        accumulator["domains"].add(domain.lower())

    for hash_value in HASH_PATTERN.findall(combined):
        accumulator["hashes"].add(hash_value.lower())

    for email in EMAIL_PATTERN.findall(combined):
        accumulator["email_addresses"].add(email.lower())

    for bitcoin_address in BITCOIN_PATTERN.findall(combined):
        accumulator["bitcoin_addresses"].add(bitcoin_address)

    for file_path in WINDOWS_PATH_PATTERN.findall(combined):
        cleaned_path = _clean_token(file_path)
        accumulator["file_paths"].add(cleaned_path)
        _extract_ransomware_file_artifacts(cleaned_path, accumulator)

    for registry_key in REGISTRY_PATTERN.findall(combined):
        accumulator["registry_keys"].add(_clean_token(registry_key))

    _extract_ransomware_file_artifacts(combined, accumulator)


def _extract_ransomware_file_artifacts(
    text: str,
    accumulator: dict[str, set[str]],
) -> None:
    for note in RANSOM_NOTE_PATTERN.findall(text):
        accumulator["ransom_notes"].add(_clean_token(note))

    for extension in ENCRYPTED_EXTENSION_PATTERN.findall(text):
        accumulator["encrypted_extensions"].add(f".{extension.lower()}")

    for filename in SUSPICIOUS_FILE_NAME_PATTERN.findall(text):
        accumulator["suspicious_file_names"].add(_clean_token(filename).lower())


def _finalize_iocs(accumulator: dict[str, set[str]]) -> dict[str, list[str]]:
    return {key: sorted(values) for key, values in accumulator.items()}


def _clean_token(value: str) -> str:
    return value.strip().strip(".,;:)]}'\"")


def _is_noise_ip(ip: str) -> bool:
    return (
        ip.startswith("127.")
        or ip.startswith("0.")
        or ip == "255.255.255.255"
        or ip.startswith("169.254.")
    )
