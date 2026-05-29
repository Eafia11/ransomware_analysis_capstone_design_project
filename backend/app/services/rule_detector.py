from __future__ import annotations

import ipaddress
from collections import Counter
from typing import Any

from app.services.feature_extractor import extract_chain_features


ENCRYPTED_EXTENSIONS = (".locked", ".encrypted", ".crypted", ".crypt", ".enc")
RANSOM_NOTE_KEYWORDS = (
    "how_to_decrypt",
    "readme_restore",
    "recover_files",
    "decrypt_instruction",
    "your_files_are_encrypted",
)
RECOVERY_INHIBIT_KEYWORDS = (
    "vssadmin",
    "delete shadows",
    "wmic shadowcopy delete",
    "wbadmin",
    "bcdedit",
    "recoveryenabled no",
)
RUN_KEY_KEYWORDS = (
    "\\currentversion\\run",
    "\\currentversion\\runonce",
    "\\policies\\explorer\\run",
)
POWERSHELL_DOWNLOAD_KEYWORDS = (
    "encodedcommand",
    "-enc ",
    "frombase64string",
    "downloadstring",
    "downloadfile",
    "invoke-webrequest",
    " iwr ",
    "invoke-expression",
    "iex ",
)
LOLBIN_KEYWORDS = (
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "wmic",
    "wscript",
    "cscript",
    "installutil",
    "msbuild",
)


def score_chain(features: dict[str, Any]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    if features["uses_suspicious_process"] == 1:
        score += 2
        reasons.append("의심 프로세스가 실행됨")

    if features["uses_suspicious_command"] == 1:
        score += 3
        reasons.append("의심 명령어 키워드가 발견됨")

    if features["file_create_count"] >= 3:
        score += 2
        reasons.append("파일 생성 이벤트가 다수 발생함")

    if features["registry_modify_count"] >= 2:
        score += 2
        reasons.append("레지스트리 변경 이벤트가 다수 발생함")

    if features["network_connect_count"] >= 1:
        score += 1
        reasons.append("네트워크 연결이 관찰됨")

    if features["has_multiple_behaviors"] == 1:
        score += 2
        reasons.append("여러 행위 유형이 함께 관찰됨")

    if features["event_count"] >= 5:
        score += 1
        reasons.append("이벤트 수가 많음")

    return score, reasons


def analyze_ransomware_indicators(actions: list[dict[str, Any]]) -> dict[str, Any]:
    flags = {
        "mass_file_activity": False,
        "encrypted_extension": False,
        "ransom_note": False,
        "recovery_inhibit": False,
        "run_key_persistence": False,
        "powershell_download_or_obfuscation": False,
        "lolbin_execution": False,
        "external_network_connection": False,
        "impact_combo": False,
        "delivery_persistence_combo": False,
    }
    evidence: dict[str, list[str]] = {key: [] for key in flags}

    file_events = [
        action
        for action in actions
        if str(action.get("event_id") or "") == "11" and action.get("target_filename")
    ]
    file_directories = Counter(_directory_name(action.get("target_filename") or "") for action in file_events)
    max_files_in_directory = max(file_directories.values(), default=0)

    if len(file_events) >= 10 or max_files_in_directory >= 5:
        flags["mass_file_activity"] = True
        evidence["mass_file_activity"].append(
            f"{len(file_events)} file creation events observed"
        )

    for action in actions:
        event_id = str(action.get("event_id") or "")
        text = _combined_action_text(action)
        target_filename = str(action.get("target_filename") or "")
        target_object = str(action.get("target_object") or "")

        if target_filename.lower().endswith(ENCRYPTED_EXTENSIONS):
            flags["encrypted_extension"] = True
            _add_evidence(evidence, "encrypted_extension", target_filename)

        if any(keyword in target_filename.lower() for keyword in RANSOM_NOTE_KEYWORDS):
            flags["ransom_note"] = True
            _add_evidence(evidence, "ransom_note", target_filename)

        if any(keyword in text for keyword in RECOVERY_INHIBIT_KEYWORDS):
            flags["recovery_inhibit"] = True
            _add_evidence(evidence, "recovery_inhibit", _evidence_text(action))

        if event_id in {"12", "13", "14"} and any(
            keyword in target_object.lower() for keyword in RUN_KEY_KEYWORDS
        ):
            flags["run_key_persistence"] = True
            _add_evidence(evidence, "run_key_persistence", target_object)

        if "powershell" in text and any(keyword in text for keyword in POWERSHELL_DOWNLOAD_KEYWORDS):
            flags["powershell_download_or_obfuscation"] = True
            _add_evidence(
                evidence,
                "powershell_download_or_obfuscation",
                _evidence_text(action),
            )

        if any(keyword in text for keyword in LOLBIN_KEYWORDS):
            flags["lolbin_execution"] = True
            _add_evidence(evidence, "lolbin_execution", _evidence_text(action))

        if event_id == "3" and _is_external_destination(action.get("destination_ip")):
            flags["external_network_connection"] = True
            _add_evidence(
                evidence,
                "external_network_connection",
                str(action.get("destination_ip")),
            )

    if (
        flags["recovery_inhibit"]
        and (flags["mass_file_activity"] or flags["encrypted_extension"])
        and flags["ransom_note"]
    ):
        flags["impact_combo"] = True
        evidence["impact_combo"].append(
            "recovery inhibition, encrypted file activity, and ransom note indicators co-occurred"
        )

    if (
        flags["powershell_download_or_obfuscation"]
        and flags["external_network_connection"]
        and flags["run_key_persistence"]
    ):
        flags["delivery_persistence_combo"] = True
        evidence["delivery_persistence_combo"].append(
            "PowerShell delivery, external network activity, and Run key persistence co-occurred"
        )

    return {"flags": flags, "evidence": evidence}


def score_ransomware_indicators(indicators: dict[str, Any]) -> tuple[int, list[str]]:
    flags = indicators["flags"]
    score = 0
    reasons: list[str] = []

    scoring_rules = [
        ("mass_file_activity", 3, "대량 파일 생성 행위가 관찰됨"),
        ("encrypted_extension", 3, "암호화된 파일로 보이는 확장자가 관찰됨"),
        ("ransom_note", 4, "랜섬노트로 보이는 파일명이 관찰됨"),
        ("recovery_inhibit", 4, "시스템 복구 방해 명령이 관찰됨"),
        ("run_key_persistence", 3, "Run 키 지속성 레지스트리 변경이 관찰됨"),
        (
            "powershell_download_or_obfuscation",
            3,
            "PowerShell 다운로드 또는 난독화 행위가 관찰됨",
        ),
        ("lolbin_execution", 2, "LOLBins 실행이 관찰됨"),
        ("external_network_connection", 2, "외부 네트워크 연결이 관찰됨"),
        (
            "impact_combo",
            5,
            "랜섬웨어 영향 행위 조합이 높은 신뢰도로 관찰됨",
        ),
        (
            "delivery_persistence_combo",
            4,
            "전달 및 지속성 행위 조합이 관찰됨",
        ),
    ]

    for flag, points, reason in scoring_rules:
        if flags[flag]:
            score += points
            reasons.append(reason)

    return score, reasons


def classify_chain(score: int) -> str:
    if score >= 5:
        return "suspicious"
    return "benign"


def detect_malicious_chains(attack_chains: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results = []

    for chain in attack_chains:
        features = extract_chain_features(chain)
        score, reasons = score_chain(features)
        indicators = analyze_ransomware_indicators(chain.get("actions", []))
        indicator_score, indicator_reasons = score_ransomware_indicators(indicators)
        score += indicator_score
        reasons.extend(indicator_reasons)

        if not _has_suspicious_anchor(features, indicators):
            score = min(score, 4)

        label = classify_chain(score)
        parent_process = chain.get("parent_process") or {}

        results.append({
            "process_guid": chain.get("process_guid"),
            "image": chain.get("image"),
            "command_line": chain.get("command_line"),
            "parent_image": parent_process.get("image"),
            "user": chain.get("user"),
            "start_time": chain.get("start_time"),
            "event_count": chain.get("event_count"),
            "features": features,
            "indicators": indicators,
            "score": score,
            "label": label,
            "reasons": reasons,
            "actions": chain.get("actions", []),
        })

    results.sort(key=lambda x: (-x["score"], x.get("start_time") or ""))
    return results


def filter_suspicious_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [result for result in results if result.get("label") == "suspicious"]


def _has_suspicious_anchor(
    features: dict[str, Any],
    indicators: dict[str, Any],
) -> bool:
    if features["uses_suspicious_process"] == 1 or features["uses_suspicious_command"] == 1:
        return True

    flags = indicators["flags"]
    anchor_flags = {
        "encrypted_extension",
        "ransom_note",
        "recovery_inhibit",
        "run_key_persistence",
        "powershell_download_or_obfuscation",
        "lolbin_execution",
        "impact_combo",
        "delivery_persistence_combo",
    }

    return any(flags[flag] for flag in anchor_flags)


def _combined_action_text(action: dict[str, Any]) -> str:
    fields = [
        "image",
        "command_line",
        "parent_image",
        "parent_command_line",
        "target_filename",
        "target_object",
        "details",
        "destination_ip",
        "destination_hostname",
    ]
    return " ".join(str(action.get(field) or "") for field in fields).lower()


def _evidence_text(action: dict[str, Any]) -> str:
    return (
        str(action.get("command_line") or "")
        or str(action.get("target_filename") or "")
        or str(action.get("target_object") or "")
        or str(action.get("image") or "")
    )


def _add_evidence(evidence: dict[str, list[str]], key: str, value: str) -> None:
    cleaned = value.strip()
    if cleaned and cleaned not in evidence[key] and len(evidence[key]) < 5:
        evidence[key].append(cleaned)


def _directory_name(path: str) -> str:
    normalized = path.replace("/", "\\")
    if "\\" not in normalized:
        return ""
    return normalized.rsplit("\\", 1)[0].lower()


def _is_external_destination(ip: Any) -> bool:
    if not ip:
        return False

    try:
        address = ipaddress.ip_address(str(ip))
    except ValueError:
        return False

    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
    )
