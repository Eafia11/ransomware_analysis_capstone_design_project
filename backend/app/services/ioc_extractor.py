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
WINDOWS_PATH_PATTERN = re.compile(
    r"\b[A-Za-z]:\\(?:[^\s\\/:*?\"<>|\r\n]+\\)*[^\s\\/:*?\"<>|\r\n]*"
)
REGISTRY_PATTERN = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|"
    r"HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[^\s\"']+",
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

    for file_path in WINDOWS_PATH_PATTERN.findall(combined):
        accumulator["file_paths"].add(_clean_token(file_path))

    for registry_key in REGISTRY_PATTERN.findall(combined):
        accumulator["registry_keys"].add(_clean_token(registry_key))


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
