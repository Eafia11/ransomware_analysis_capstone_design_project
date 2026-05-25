from __future__ import annotations

from typing import Any


MITRE_RULES = [
    {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution",
        "keywords": ["powershell", "encodedcommand", "invoke-expression", "iex "],
    },
    {
        "technique_id": "T1059.003",
        "technique_name": "Windows Command Shell",
        "tactic": "Execution",
        "keywords": ["cmd.exe", "cmd /c", "cmd /k"],
    },
    {
        "technique_id": "T1003",
        "technique_name": "Credential Dumping",
        "tactic": "Credential Access",
        "keywords": ["mimikatz", "lsass", "procdump"],
    },
    {
        "technique_id": "T1490",
        "technique_name": "Inhibit System Recovery",
        "tactic": "Impact",
        "keywords": ["vssadmin", "shadowcopy", "delete shadows", "wbadmin", "bcdedit"],
    },
    {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "keywords": ["downloadstring", "downloadfile", "bitsadmin", "certutil"],
    },
    {
        "technique_id": "T1112",
        "technique_name": "Modify Registry",
        "tactic": "Defense Evasion",
        "keywords": ["reg add", "reg delete", "regedit", "regsvr32"],
    },
    {
        "technique_id": "T1136",
        "technique_name": "Create Account",
        "tactic": "Persistence",
        "keywords": ["net user", "net localgroup"],
    },
    {
        "technique_id": "T1218",
        "technique_name": "Signed Binary Proxy Execution",
        "tactic": "Defense Evasion",
        "keywords": ["mshta", "rundll32", "wscript", "cscript"],
    },
]


def map_to_attack(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map process actions to MITRE ATT&CK techniques."""
    matched_techniques = []
    seen = set()

    for action in actions:
        image = (action.get("image") or "").lower()
        command_line = (action.get("command_line") or "").lower()
        combined = f"{image} {command_line}"

        for rule in MITRE_RULES:
            if rule["technique_id"] in seen:
                continue
            if any(keyword in combined for keyword in rule["keywords"]):
                matched_techniques.append({
                    "technique_id": rule["technique_id"],
                    "technique_name": rule["technique_name"],
                    "tactic": rule["tactic"],
                })
                seen.add(rule["technique_id"])

    return matched_techniques


def analyze_chain_attack(chain: dict[str, Any]) -> dict[str, Any]:
    """Return ATT&CK mapping details for one process chain."""
    actions = chain.get("actions", [])
    techniques = map_to_attack(actions)

    return {
        "process_guid": chain.get("process_guid"),
        "image": chain.get("image"),
        "matched_techniques": techniques,
        "technique_count": len(techniques),
    }
