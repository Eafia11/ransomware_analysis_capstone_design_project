from __future__ import annotations
import re
from typing import Any


# IoC 추출 정규식 패턴 (Task21)
IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|top|xyz|info|biz)\b'
)

HASH_PATTERN = re.compile(
    r'\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b'
)


def extract_iocs(actions: list[dict[str, Any]]) -> dict[str, list[str]]:
    """이벤트 액션에서 IP, 도메인, 해시값 추출"""
    ips = set()
    domains = set()
    hashes = set()

    for action in actions:
        # 검사할 텍스트 수집
        texts = [
            action.get("image") or "",
            action.get("command_line") or "",
            action.get("destination_ip") or "",
            action.get("destination_hostname") or "",
            action.get("target_filename") or "",
        ]
        combined = " ".join(texts)

        # IP 추출
        for ip in IP_PATTERN.findall(combined):
            # 내부 IP 제외
            if not ip.startswith(("127.", "192.168.", "10.", "172.")):
                ips.add(ip)

        # 도메인 추출
        for domain in DOMAIN_PATTERN.findall(combined):
            domains.add(domain)

        # 해시 추출
        for hash_val in HASH_PATTERN.findall(combined):
            hashes.add(hash_val)

    return {
        "ips": list(ips),
        "domains": list(domains),
        "hashes": list(hashes),
    }


def extract_iocs_from_chain(chain: dict[str, Any]) -> dict[str, Any]:
    """체인에서 IoC 추출 후 결과 반환"""
    actions = chain.get("actions", [])
    iocs = extract_iocs(actions)

    return {
        "process_guid": chain.get("process_guid"),
        "image": chain.get("image"),
        "iocs": iocs,
        "ioc_count": sum(len(v) for v in iocs.values()),
    }