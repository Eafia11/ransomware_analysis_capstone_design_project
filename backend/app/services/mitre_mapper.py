from __future__ import annotations

from typing import Any


CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


MITRE_RULES = [
    {
        "technique_id": "T1059.001",
        "technique": "PowerShell",
        "tactic": "Execution",
        "keywords": [
            "powershell",
            "pwsh",
            "encodedcommand",
            "-enc ",
            "frombase64string",
            "downloadstring",
            "invoke-expression",
            "iex ",
            " iwr ",
            "invoke-webrequest",
        ],
    },
    {
        "technique_id": "T1059.003",
        "technique": "Windows Command Shell",
        "tactic": "Execution",
        "keywords": ["cmd.exe", "cmd /c", "cmd /k", "/c "],
    },
    {
        "technique_id": "T1105",
        "technique": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "keywords": [
            "downloadfile",
            "downloadstring",
            "invoke-webrequest",
            " iwr ",
            "curl ",
            "wget ",
            "certutil",
            "bitsadmin",
            "start-bitstransfer",
        ],
    },
    {
        "technique_id": "T1003",
        "technique": "OS Credential Dumping",
        "tactic": "Credential Access",
        "keywords": ["mimikatz", "sekurlsa", "lsass", "procdump", "comsvcs.dll"],
    },
    {
        "technique_id": "T1087",
        "technique": "Account Discovery",
        "tactic": "Discovery",
        "keywords": ["net user", "net group", "net localgroup", "whoami /all"],
    },
    {
        "technique_id": "T1053.005",
        "technique": "Scheduled Task",
        "tactic": "Execution",
        "keywords": ["schtasks", "at.exe", "new-scheduledtask", "register-scheduledtask"],
    },
    {
        "technique_id": "T1543.003",
        "technique": "Windows Service",
        "tactic": "Persistence",
        "keywords": ["sc create", "sc.exe create", "new-service", "create service"],
    },
    {
        "technique_id": "T1218",
        "technique": "System Binary Proxy Execution",
        "tactic": "Defense Evasion",
        "keywords": ["mshta", "rundll32", "regsvr32", "installutil", "msbuild", "wscript", "cscript"],
    },
    {
        "technique_id": "T1490",
        "technique": "Inhibit System Recovery",
        "tactic": "Impact",
        "keywords": [
            "vssadmin",
            "delete shadows",
            "shadowcopy",
            "wbadmin",
            "bcdedit",
            "recoveryenabled no",
            "wmic shadowcopy delete",
        ],
    },
    {
        "technique_id": "T1486",
        "technique": "Data Encrypted for Impact",
        "tactic": "Impact",
        "keywords": [
            ".locked",
            ".encrypted",
            ".crypted",
            ".crypt",
            ".enc",
            "how_to_decrypt",
            "recover_files",
            "your_files_are_encrypted",
        ],
    },
    {
        "technique_id": "T1112",
        "technique": "Modify Registry",
        "tactic": "Defense Evasion",
        "event_ids": {"12", "13", "14"},
        "keywords": ["reg add", "reg delete", "regedit"],
    },
]


def map_action_to_mitre(action: dict[str, Any]) -> list[dict[str, Any]]:
    event_id = str(action.get("event_id") or "")
    evidence_source = _action_evidence_text(action)
    combined = " ".join([
        str(action.get("image") or ""),
        str(action.get("command_line") or ""),
        str(action.get("parent_image") or ""),
        str(action.get("parent_command_line") or ""),
        str(action.get("target_filename") or ""),
        str(action.get("target_object") or ""),
        str(action.get("details") or ""),
        str(action.get("destination_ip") or ""),
        str(action.get("destination_hostname") or ""),
    ]).lower()
    matches = []

    for rule in MITRE_RULES:
        event_ids = rule.get("event_ids")
        matched_keywords = [
            keyword
            for keyword in rule.get("keywords", [])
            if keyword in combined
        ]
        event_match = event_ids is not None and event_id in event_ids

        if matched_keywords or event_match:
            evidence = []
            if evidence_source:
                evidence.append(evidence_source)
            if event_match:
                evidence.append(f"Sysmon event ID {event_id}")

            matches.append({
                "technique_id": rule["technique_id"],
                "technique": rule["technique"],
                "tactic": rule["tactic"],
                "evidence": _unique_limited(evidence),
                "confidence": _confidence_for_match(matched_keywords, event_match),
            })

    return matches


def map_chain_to_mitre(chain: dict[str, Any]) -> list[dict[str, Any]]:
    mapped: dict[tuple[str, str], dict[str, Any]] = {}

    for action in chain.get("actions", []):
        for match in map_action_to_mitre(action):
            key = (match["technique_id"], match["tactic"])
            if key not in mapped:
                mapped[key] = match
                continue

            existing = mapped[key]
            existing["evidence"] = _unique_limited([
                *existing.get("evidence", []),
                *match.get("evidence", []),
            ])
            existing["confidence"] = _higher_confidence(
                existing.get("confidence", "low"),
                match.get("confidence", "low"),
            )

    return list(mapped.values())


def enrich_results_with_mitre(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            **result,
            "mitre_attack": map_chain_to_mitre(result),
        }
        for result in results
    ]


def _action_evidence_text(action: dict[str, Any]) -> str:
    for field in [
        "command_line",
        "target_filename",
        "target_object",
        "details",
        "image",
        "destination_ip",
        "destination_hostname",
    ]:
        value = str(action.get(field) or "").strip()
        if value:
            return value
    return ""


def _confidence_for_match(matched_keywords: list[str], event_match: bool) -> str:
    if event_match and matched_keywords:
        return "high"
    if event_match or len(matched_keywords) >= 2:
        return "medium"
    return "low"


def _higher_confidence(left: str, right: str) -> str:
    return left if CONFIDENCE_ORDER[left] >= CONFIDENCE_ORDER[right] else right


def _unique_limited(values: list[str], limit: int = 5) -> list[str]:
    unique = []
    for value in values:
        cleaned = value.strip()
        if cleaned and cleaned not in unique:
            unique.append(cleaned)
        if len(unique) >= limit:
            break
    return unique
